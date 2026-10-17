// Chain building + signature verification against the embedded Mozilla root store,
// hostname matching, expiry status and grading.
import { readTLV, children, decodeOID, b64encode, b64decode, bytesEqual, toHex } from './asn1.js';
import { CURVES, isSelfIssued } from './x509.js';
import { ROOTS, ROOT_STORE_VERSION } from './roots.js';
import { parseIPv4, parseIPv6 } from './netguard.js';

const subtle = globalThis.crypto.subtle;
const DAY = 86400000;

// ---------- root store index (built lazily, once per isolate) ----------
let rootIndex = null;
function roots() {
  if (!rootIndex) {
    rootIndex = new Map();
    for (const [name, subj, spki, notAfter, sha256] of ROOTS) {
      const list = rootIndex.get(subj) || [];
      list.push({ name, spki, notAfter, sha256 });
      rootIndex.set(subj, list);
    }
  }
  return rootIndex;
}
export { ROOT_STORE_VERSION };

function spkiCurve(spkiDer) {
  try {
    const seq = readTLV(spkiDer, 0);
    const [alg] = children(spkiDer, seq);
    const [oidT, paramT] = children(spkiDer, alg);
    const oid = decodeOID(oidT.value());
    if (oid === '1.2.840.10045.2.1' && paramT && paramT.tag === 0x06) {
      const c = CURVES[decodeOID(paramT.value())];
      return { kind: 'EC', curve: c ? c.name : null, size: c ? Math.ceil(c.bits / 8) : null };
    }
    if (oid === '1.2.840.113549.1.1.1' || oid === '1.2.840.113549.1.1.10') return { kind: 'RSA' };
    if (oid === '1.3.101.112') return { kind: 'Ed25519' };
    return { kind: 'unknown', oid };
  } catch { return { kind: 'unknown' }; }
}

function ecdsaDerToRaw(der, size) {
  const seq = readTLV(der, 0);
  const [r, s] = children(der, seq);
  const fix = (v) => {
    let b = v.value();
    while (b.length > size && b[0] === 0) b = b.subarray(1);
    if (b.length > size) throw new Error('bad ecdsa int');
    const out = new Uint8Array(size); out.set(b, size - b.length); return out;
  };
  const out = new Uint8Array(size * 2);
  out.set(fix(r), 0); out.set(fix(s), size);
  return out;
}

/** Verify `cert`'s signature with issuer SPKI DER. Returns true/false, or null when the algorithm is unsupported. */
export async function verifySignature(cert, issuerSpkiDer) {
  const sa = cert.signatureAlgorithm;
  const key = spkiCurve(issuerSpkiDer);
  try {
    if (sa.family === 'RSA' && key.kind === 'RSA' && sa.hash && sa.hash !== 'MD5') {
      const k = await subtle.importKey('spki', issuerSpkiDer, { name: 'RSASSA-PKCS1-v1_5', hash: sa.hash }, false, ['verify']);
      return await subtle.verify('RSASSA-PKCS1-v1_5', k, cert.signature, cert.tbs);
    }
    if (sa.family === 'RSA-PSS' && key.kind === 'RSA' && /^SHA-/.test(sa.hash || '')) {
      const k = await subtle.importKey('spki', issuerSpkiDer, { name: 'RSA-PSS', hash: sa.hash }, false, ['verify']);
      return await subtle.verify({ name: 'RSA-PSS', saltLength: sa.saltLength }, k, cert.signature, cert.tbs);
    }
    if (sa.family === 'ECDSA' && key.kind === 'EC' && key.curve && sa.hash) {
      const k = await subtle.importKey('spki', issuerSpkiDer, { name: 'ECDSA', namedCurve: key.curve }, false, ['verify']);
      return await subtle.verify({ name: 'ECDSA', hash: sa.hash }, k, ecdsaDerToRaw(cert.signature, key.size), cert.tbs);
    }
    if (sa.family === 'Ed25519' && key.kind === 'Ed25519') {
      const k = await subtle.importKey('spki', issuerSpkiDer, { name: 'Ed25519' }, false, ['verify']);
      return await subtle.verify({ name: 'Ed25519' }, k, cert.signature, cert.tbs);
    }
  } catch { return null; }
  // Signature family incompatible with the issuer's key type → cannot be a valid signature.
  const compatible = (sa.family === 'RSA' || sa.family === 'RSA-PSS') ? key.kind === 'RSA' : sa.family === 'ECDSA' ? key.kind === 'EC' : sa.family === 'Ed25519' ? key.kind === 'Ed25519' : true;
  if (!compatible && key.kind !== 'unknown') return false;
  return null;
}

function rootFor(cert) {
  // Is this cert itself a store root (same subject + same key)?
  const list = roots().get(b64encode(cert.subjectDer));
  if (!list) return null;
  const spki = b64encode(cert.spkiDer);
  return list.find((r) => r.spki === spki) || null;
}

/**
 * Build the path leaf → … → trust anchor using the presented certificates, verifying each signature.
 * certs: parsed certificates in the order the server sent them.
 */
export async function analyzeChain(certs, now = new Date()) {
  const out = {
    presented: certs.length, path: [0], complete: false, trusted: false, trustAnchor: null, anchorInChain: false,
    selfSigned: false, orderOk: true, unusedCerts: [], issues: [], signaturesVerified: 0, signaturesUnverifiable: 0,
    trustStore: ROOT_STORE_VERSION,
  };
  if (!certs.length) return out;
  const used = new Set([0]);
  let cur = certs[0];
  for (let depth = 0; depth < 10; depth++) {
    const self = rootFor(cur);
    if (self) {
      out.trusted = true; out.complete = true; out.trustAnchor = self.name; out.anchorInChain = true;
      if (depth === 0) out.issues.push({ severity: 'critical', code: 'leaf_is_root', message: 'The server certificate is itself a root CA certificate.' });
      break;
    }
    const cands = roots().get(b64encode(cur.issuerDer)) || [];
    let anchored = null;
    for (const r of cands) {
      const ok = await verifySignature(cur, b64decode(r.spki));
      if (ok === true) { anchored = r; out.signaturesVerified++; break; }
      if (ok === null) out.signaturesUnverifiable++;
    }
    if (anchored) {
      out.trusted = true; out.complete = true; out.trustAnchor = anchored.name;
      if (new Date(anchored.notAfter + 'T23:59:59Z') < now) out.issues.push({ severity: 'critical', code: 'root_expired', message: `Trust anchor ${anchored.name} has expired.` });
      break;
    }
    if (isSelfIssued(cur)) {
      const ok = await verifySignature(cur, cur.spkiDer);
      if (ok !== false) {
        out.complete = true; // path ends in a self-signed cert that is not in the trust store
        if (depth === 0) {
          out.selfSigned = true;
          out.issues.push({ severity: 'critical', code: 'self_signed', message: 'The certificate is self-signed and not trusted by browsers.' });
        } else {
          out.issues.push({ severity: 'critical', code: 'untrusted_root', message: `The chain ends at "${cur.subjectCN || cur.subjectString}", a root that is not in the Mozilla trust store.` });
        }
        break;
      }
    }
    // Look for the issuer among presented certs.
    let found = -1;
    for (let i = 0; i < certs.length; i++) {
      if (used.has(i) || !bytesEqual(certs[i].subjectDer, cur.issuerDer)) continue;
      const ok = await verifySignature(cur, certs[i].spkiDer);
      if (ok === true) { found = i; out.signaturesVerified++; break; }
      if (ok === null) { out.signaturesUnverifiable++; if (found < 0) found = i; }
    }
    if (found < 0) {
      out.issues.push({
        severity: 'critical', code: 'incomplete_chain',
        message: `Missing intermediate: no certificate for issuer "${cur.issuerCN || cur.issuerString}" was sent and it is not a trusted root. Many clients will fail.`,
      });
      break;
    }
    used.add(found); out.path.push(found); cur = certs[found];
  }
  // RFC 5280 §6.1.4: every issuing certificate must be a CA (basicConstraints cA=TRUE), must have keyCertSign
  // when keyUsage is present, and must respect pathLenConstraint. A store root that the server happens to
  // send (anchorInChain) is a trust anchor and is not subject to these checks.
  out.constraintViolations = 0;
  const lastAnchorIdx = out.anchorInChain ? out.path.length - 1 : -1;
  for (let k = 1; k < out.path.length; k++) {
    if (k === lastAnchorIdx) continue;
    const c = certs[out.path[k]];
    const name = c.subjectCN || c.subjectString;
    if (c.isCA !== true) {
      out.issues.push({ severity: 'critical', code: 'issuer_not_ca', message: `"${name}" issued a certificate in this chain but is not a CA certificate (basicConstraints cA is not TRUE). Browsers reject this chain.` });
      out.constraintViolations++;
    } else if (c.keyUsage && !c.keyUsage.keyCertSign) {
      out.issues.push({ severity: 'critical', code: 'issuer_not_ca', message: `"${name}" is a CA but its keyUsage does not allow certificate signing (keyCertSign). Browsers reject this chain.` });
      out.constraintViolations++;
    }
    if (c.isCA === true && Number.isInteger(c.pathLen)) {
      let below = 0;
      for (let j = 1; j < k; j++) if (!isSelfIssued(certs[out.path[j]])) below++;
      if (below > c.pathLen) {
        out.issues.push({ severity: 'critical', code: 'path_len_exceeded', message: `"${name}" has pathLenConstraint ${c.pathLen} but ${below} intermediate CA(s) follow it. Browsers reject this chain.` });
        out.constraintViolations++;
      }
    }
  }
  if (out.constraintViolations) { out.trusted = false; out.constraintsOk = false; } else out.constraintsOk = true;

  for (let i = 0; i < out.path.length; i++) if (out.path[i] !== i) out.orderOk = false;
  if (!out.orderOk) out.issues.push({ severity: 'warning', code: 'chain_order', message: 'Certificates were sent out of order (most clients tolerate this).' });
  for (let i = 0; i < certs.length; i++) if (!used.has(i)) out.unusedCerts.push(i);
  if (out.unusedCerts.length) out.issues.push({ severity: 'info', code: 'extra_certs', message: `${out.unusedCerts.length} extra certificate(s) sent that are not needed for the trusted path (e.g. a cross-sign or the root itself).` });
  // Validity + weak signatures across the path
  for (let k = 1; k < out.path.length; k++) {
    const c = certs[out.path[k]];
    if (c.notAfter < now) out.issues.push({ severity: 'critical', code: 'intermediate_expired', message: `Intermediate "${c.subjectCN || c.subjectString}" expired on ${c.notAfter.toISOString().slice(0, 10)}.` });
    if (c.notBefore > now) out.issues.push({ severity: 'critical', code: 'intermediate_not_yet_valid', message: `Intermediate "${c.subjectCN}" is not yet valid.` });
  }
  for (const k of out.path) {
    const c = certs[k];
    if (c.signatureAlgorithm.weak && !(k === out.path[out.path.length - 1] && isSelfIssued(c))) {
      out.issues.push({ severity: 'critical', code: 'weak_signature', message: `"${c.subjectCN || c.subjectString}" is signed with ${c.signatureAlgorithm.name} (insecure).` });
    }
  }
  return out;
}

// ---------- hostname matching (RFC 6125 / CA/B Forum rules as browsers apply them) ----------
function wildcardMatch(pattern, host) {
  if (pattern === host) return true;
  if (!pattern.startsWith('*.')) return false;
  const suffix = pattern.slice(1); // ".example.com"
  if (suffix.split('.').length < 3) return false; // no "*.com"
  if (!host.endsWith(suffix)) return false;
  const left = host.slice(0, -suffix.length);
  return left.length > 0 && !left.includes('.');
}

export function matchHostname(cert, host, isIp) {
  if (isIp) {
    const want = host.includes(':') ? parseIPv6(host) : parseIPv4(host);
    for (const ip of cert.san.ips) {
      const have = ip.includes(':') ? parseIPv6(ip) : parseIPv4(ip);
      if (want && have && bytesEqual(want, have)) return { matches: true, matchedName: ip, method: 'SAN iPAddress' };
    }
    return { matches: false, matchedName: null, method: 'SAN iPAddress', note: 'No iPAddress SAN matches the requested IP.' };
  }
  for (const n of cert.san.dns) {
    if (wildcardMatch(n, host)) return { matches: true, matchedName: n, method: 'SAN dNSName' };
  }
  if (!cert.san.dns.length && cert.subjectCN && wildcardMatch(cert.subjectCN.toLowerCase(), host)) {
    return { matches: false, matchedName: cert.subjectCN, method: 'CN (legacy)', note: 'Matched only the Common Name; modern browsers require a SAN entry.' };
  }
  return { matches: false, matchedName: null, method: 'SAN dNSName', note: `Certificate names: ${cert.san.dns.slice(0, 10).join(', ') || cert.subjectCN || '(no names)'}` };
}

export function expiryInfo(cert, now = new Date()) {
  const msLeft = cert.notAfter - now;
  const daysRemaining = Math.floor(msLeft / DAY);
  let status;
  if (now < cert.notBefore) status = 'not_yet_valid';
  else if (msLeft < 0) status = 'expired';
  else if (daysRemaining < 7) status = 'critical';
  else if (daysRemaining < 30) status = 'warning';
  else status = 'ok';
  return { notBefore: cert.notBefore.toISOString(), notAfter: cert.notAfter.toISOString(), daysRemaining, status, lifetimeDays: Math.round((cert.notAfter - cert.notBefore) / DAY) };
}

export function describeKey(pk) {
  if (pk.type === 'RSA' || pk.type === 'RSA-PSS') return { type: pk.type, bits: pk.bits, exponent: pk.exponent, label: `RSA ${pk.bits}` };
  if (pk.type === 'EC') return { type: 'EC', curve: pk.curve, bits: pk.bits, label: `ECDSA ${pk.curve}` };
  return { type: pk.type, bits: pk.bits, label: pk.type };
}

export function keyIsWeak(pk) {
  if (pk.type === 'RSA' || pk.type === 'RSA-PSS') return !pk.bits || pk.bits < 2048;
  if (pk.type === 'EC') return !pk.bits || pk.bits < 256;
  if (pk.type === 'DSA') return true;
  return false;
}

/**
 * Grade: F = browsers will reject (expired, not yet valid, name mismatch, untrusted, broken chain, weak sig).
 *        C = works but risky (expires < 7d, weak key, TLS < 1.2).
 *        B = expires < 30d, or no TLS 1.3.   A = everything good.
 * live=false (CT fallback) grades are capped/labelled as estimates by the caller.
 */
export function grade({ expiry, hostname, chain, key, tlsVersion, live }) {
  const reasons = [];
  let g = 'A';
  const worst = (x) => { const order = ['A', 'B', 'C', 'F']; if (order.indexOf(x) > order.indexOf(g)) g = x; };
  if (expiry.status === 'expired') { worst('F'); reasons.push('certificate has expired'); }
  if (expiry.status === 'not_yet_valid') { worst('F'); reasons.push('certificate is not yet valid'); }
  if (hostname && !hostname.matches) { worst('F'); reasons.push('certificate does not match the hostname'); }
  if (chain) {
    if (chain.trusted === false && !chain.constraintViolations) { worst('F'); reasons.push(chain.selfSigned ? 'self-signed certificate' : chain.complete ? 'chain ends at an untrusted root' : 'incomplete chain / unknown issuer'); }
    for (const i of chain.issues) {
      if (['intermediate_expired', 'weak_signature', 'root_expired', 'leaf_is_root', 'issuer_not_ca', 'path_len_exceeded'].includes(i.code)) { worst('F'); reasons.push(i.message); }
    }
  }
  if (expiry.status === 'critical') { worst('C'); reasons.push(`expires in ${expiry.daysRemaining} day(s)`); }
  if (key && keyIsWeak(key)) { worst('C'); reasons.push(`weak key (${key.label})`); }
  if (tlsVersion && tlsVersion < 0x0303) { worst('C'); reasons.push('server negotiated a TLS version older than 1.2'); }
  if (expiry.status === 'warning') { worst('B'); reasons.push(`expires in ${expiry.daysRemaining} days`); }
  if (live && tlsVersion === 0x0303) { worst('B'); reasons.push('TLS 1.3 not supported (negotiated TLS 1.2)'); }
  // Revocation (OCSP/CRL) is never checked, so every summary carries that qualifier.
  let summary;
  if (g === 'A') summary = chain ? `Certificate is unexpired, chains to a trusted root and matches the hostname; expires in ${expiry.daysRemaining} days (revocation not checked).` : `Certificate is unexpired and covers the hostname; expires in ${expiry.daysRemaining} days (trust chain not observed; revocation not checked).`;
  else summary = `Grade ${g}: ${reasons.join('; ')} (revocation not checked).`;
  return { grade: g, reasons, summary };
}

export function sha256Hex(bytes) {
  return subtle.digest('SHA-256', bytes).then((d) => toHex(new Uint8Array(d), ':').toUpperCase());
}
