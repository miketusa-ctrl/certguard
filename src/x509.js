// X.509 certificate parser (DER) built on asn1.js. Extracts what CertGuard reports.
import { readTLV, children, expectTag, decodeOID, decodeString, decodeTime, toHex, intBitLength, Asn1Error } from './asn1.js';

export const NAME_OIDS = {
  '2.5.4.3': 'CN', '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'ST', '2.5.4.10': 'O', '2.5.4.11': 'OU',
  '2.5.4.5': 'serialNumber', '2.5.4.9': 'street', '2.5.4.17': 'postalCode', '2.5.4.15': 'businessCategory',
  '2.5.4.97': 'organizationIdentifier', '1.2.840.113549.1.9.1': 'emailAddress',
  '1.3.6.1.4.1.311.60.2.1.3': 'jurisdictionC', '1.3.6.1.4.1.311.60.2.1.2': 'jurisdictionST',
  '1.3.6.1.4.1.311.60.2.1.1': 'jurisdictionL', '0.9.2342.19200300.100.1.25': 'DC',
};

export const SIG_ALGS = {
  '1.2.840.113549.1.1.4': { name: 'md5WithRSAEncryption', family: 'RSA', hash: 'MD5', weak: true },
  '1.2.840.113549.1.1.5': { name: 'sha1WithRSAEncryption', family: 'RSA', hash: 'SHA-1', weak: true },
  '1.2.840.113549.1.1.11': { name: 'sha256WithRSAEncryption', family: 'RSA', hash: 'SHA-256' },
  '1.2.840.113549.1.1.12': { name: 'sha384WithRSAEncryption', family: 'RSA', hash: 'SHA-384' },
  '1.2.840.113549.1.1.13': { name: 'sha512WithRSAEncryption', family: 'RSA', hash: 'SHA-512' },
  '1.2.840.113549.1.1.10': { name: 'RSASSA-PSS', family: 'RSA-PSS', hash: null },
  '1.2.840.10045.4.1': { name: 'ecdsa-with-SHA1', family: 'ECDSA', hash: 'SHA-1', weak: true },
  '1.2.840.10045.4.3.2': { name: 'ecdsa-with-SHA256', family: 'ECDSA', hash: 'SHA-256' },
  '1.2.840.10045.4.3.3': { name: 'ecdsa-with-SHA384', family: 'ECDSA', hash: 'SHA-384' },
  '1.2.840.10045.4.3.4': { name: 'ecdsa-with-SHA512', family: 'ECDSA', hash: 'SHA-512' },
  '1.3.101.112': { name: 'Ed25519', family: 'Ed25519', hash: null },
  '1.3.101.113': { name: 'Ed448', family: 'Ed448', hash: null },
};

const HASH_OIDS = {
  '1.3.14.3.2.26': 'SHA-1', '2.16.840.1.101.3.4.2.1': 'SHA-256', '2.16.840.1.101.3.4.2.2': 'SHA-384', '2.16.840.1.101.3.4.2.3': 'SHA-512',
};

export const CURVES = {
  '1.2.840.10045.3.1.7': { name: 'P-256', bits: 256 },
  '1.3.132.0.34': { name: 'P-384', bits: 384 },
  '1.3.132.0.35': { name: 'P-521', bits: 521 },
};

const POLICY_TYPES = {
  '2.23.140.1.2.1': 'DV', '2.23.140.1.2.2': 'OV', '2.23.140.1.2.3': 'IV', '2.23.140.1.1': 'EV',
};

function parseName(buf, tlv) {
  expectTag(tlv, 0x30, 'Name');
  const attrs = [];
  for (const set of children(buf, tlv)) {
    for (const atv of children(buf, set)) {
      const [oidT, valT] = children(buf, atv);
      const oid = decodeOID(expectTag(oidT, 0x06, 'attr OID').value());
      attrs.push({ oid, key: NAME_OIDS[oid] || oid, value: decodeString(valT) });
    }
  }
  return attrs;
}

export function nameToString(attrs) {
  return attrs.map((a) => `${a.key}=${a.value}`).join(', ');
}
function nameGet(attrs, key) {
  const a = attrs.filter((x) => x.key === key);
  return a.length ? a[a.length - 1].value : null;
}

function parseAlgId(buf, tlv) {
  const kids = children(buf, expectTag(tlv, 0x30, 'AlgorithmIdentifier'));
  const oid = decodeOID(expectTag(kids[0], 0x06, 'alg OID').value());
  return { oid, params: kids[1] || null };
}

function parsePssParams(buf, paramsTlv) {
  // RSASSA-PSS-params ::= SEQUENCE { hashAlgorithm [0], maskGenAlgorithm [1], saltLength [2], trailerField [3] }
  let hash = 'SHA-1';
  let saltLength = 20;
  if (paramsTlv && paramsTlv.tag === 0x30) {
    for (const c of children(buf, paramsTlv)) {
      if (c.tag === 0xa0) {
        const alg = parseAlgId(buf, readTLV(buf, c.start, c.end));
        hash = HASH_OIDS[alg.oid] || alg.oid;
      } else if (c.tag === 0xa2) {
        const i = readTLV(buf, c.start, c.end);
        let n = 0;
        for (const b of i.value()) n = n * 256 + b;
        saltLength = n;
      }
    }
  }
  return { hash, saltLength };
}

function parseSpki(buf, tlv) {
  const [algT, bitsT] = children(buf, expectTag(tlv, 0x30, 'SPKI'));
  const alg = parseAlgId(buf, algT);
  expectTag(bitsT, 0x03, 'SPKI bitstring');
  const keyBytes = buf.subarray(bitsT.start + 1, bitsT.end); // skip unused-bits byte
  const out = { algOid: alg.oid, type: 'unknown', bits: null, curve: null };
  if (alg.oid === '1.2.840.113549.1.1.1' || alg.oid === '1.2.840.113549.1.1.10') {
    out.type = alg.oid.endsWith('.10') ? 'RSA-PSS' : 'RSA';
    try {
      const seq = readTLV(keyBytes, 0);
      const [mod, exp] = children(keyBytes, seq);
      out.bits = intBitLength(mod.value());
      let e = 0;
      for (const b of exp.value()) e = e * 256 + b;
      out.exponent = e;
    } catch { /* leave bits null */ }
  } else if (alg.oid === '1.2.840.10045.2.1') {
    out.type = 'EC';
    if (alg.params && alg.params.tag === 0x06) {
      const c = CURVES[decodeOID(alg.params.value())];
      if (c) { out.curve = c.name; out.bits = c.bits; } else out.curve = decodeOID(alg.params.value());
    }
  } else if (alg.oid === '1.3.101.112') { out.type = 'Ed25519'; out.bits = 256; }
  else if (alg.oid === '1.3.101.113') { out.type = 'Ed448'; out.bits = 456; }
  else if (alg.oid === '1.2.840.10040.4.1') { out.type = 'DSA'; }
  return out;
}

function parseGeneralNames(buf, seqTlv) {
  const dns = [];
  const ips = [];
  const other = [];
  for (const gn of children(buf, seqTlv)) {
    if (gn.tag === 0x82) dns.push(decodeString({ tag: 0x16, value: gn.value }).toLowerCase());
    else if (gn.tag === 0x87) {
      const v = gn.value();
      if (v.length === 4) ips.push(Array.from(v).join('.'));
      else if (v.length === 16) {
        const parts = [];
        for (let i = 0; i < 16; i += 2) parts.push(((v[i] << 8) | v[i + 1]).toString(16));
        ips.push(parts.join(':'));
      }
    } else if (gn.tag === 0x86) other.push('URI:' + decodeString({ tag: 0x16, value: gn.value }));
    else if (gn.tag === 0x81) other.push('email:' + decodeString({ tag: 0x16, value: gn.value }));
  }
  return { dns, ips, other };
}

function parseAia(extVal) {
  const ocsp = [];
  const caIssuers = [];
  const seq = readTLV(extVal, 0);
  for (const ad of children(extVal, seq)) {
    const [m, loc] = children(extVal, ad);
    const oid = decodeOID(m.value());
    if (loc.tag === 0x86) {
      const url = decodeString({ tag: 0x16, value: loc.value });
      if (oid === '1.3.6.1.5.5.7.48.1') ocsp.push(url);
      else if (oid === '1.3.6.1.5.5.7.48.2') caIssuers.push(url);
    }
  }
  return { ocsp, caIssuers };
}

/** Parse DER certificate bytes. Throws on structural errors. */
export function parseCertificate(der) {
  if (!(der instanceof Uint8Array)) der = new Uint8Array(der);
  const certT = expectTag(readTLV(der, 0), 0x30, 'Certificate');
  if (certT.end !== der.length) throw new Asn1Error('trailing data after certificate');
  const [tbsT, sigAlgT, sigT] = children(der, certT);
  expectTag(tbsT, 0x30, 'TBSCertificate');
  expectTag(sigT, 0x03, 'signatureValue');
  const sigAlg = parseAlgId(der, sigAlgT);
  const tbs = children(der, tbsT);
  let i = 0;
  let version = 1;
  if (tbs[i].tag === 0xa0) {
    const v = readTLV(der, tbs[i].start, tbs[i].end);
    version = v.value()[0] + 1;
    i++;
  }
  const serialT = expectTag(tbs[i++], 0x02, 'serial');
  i++; // inner signature AlgorithmIdentifier
  const issuerT = tbs[i++];
  const validityT = tbs[i++];
  const subjectT = tbs[i++];
  const spkiT = tbs[i++];
  const issuer = parseName(der, issuerT);
  const subject = parseName(der, subjectT);
  const [nbT, naT] = children(der, expectTag(validityT, 0x30, 'Validity'));
  const spki = parseSpki(der, spkiT);

  const ext = { san: { dns: [], ips: [], other: [] }, isCA: null, pathLen: null, ocsp: [], caIssuers: [], ski: null, aki: null, policies: [], sctCount: 0, keyUsage: null, ekus: [], mustStaple: false };
  let hasSanExt = false;
  for (; i < tbs.length; i++) {
    if (tbs[i].tag !== 0xa3) continue;
    const extsSeq = readTLV(der, tbs[i].start, tbs[i].end);
    for (const e of children(der, extsSeq)) {
      const parts = children(der, e);
      const oid = decodeOID(parts[0].value());
      const valT = parts[parts.length - 1];
      const val = valT.value();
      try {
        switch (oid) {
          case '2.5.29.17': hasSanExt = true; ext.san = parseGeneralNames(val, readTLV(val, 0)); break;
          case '2.5.29.19': {
            const seq = readTLV(val, 0);
            const k = children(val, seq);
            ext.isCA = false;
            for (const c of k) {
              if (c.tag === 0x01) ext.isCA = c.value()[0] !== 0;
              if (c.tag === 0x02) ext.pathLen = c.value()[0];
            }
            break;
          }
          case '1.3.6.1.5.5.7.1.1': Object.assign(ext, parseAia(val)); break;
          case '2.5.29.14': ext.ski = toHex(readTLV(val, 0).value()); break;
          case '2.5.29.35': {
            for (const c of children(val, readTLV(val, 0))) if (c.tag === 0x80) ext.aki = toHex(c.value());
            break;
          }
          case '2.5.29.32': {
            for (const pi of children(val, readTLV(val, 0))) {
              const p = decodeOID(children(val, pi)[0].value());
              ext.policies.push(p);
            }
            break;
          }
          case '1.3.6.1.4.1.11129.2.4.2': {
            // SignedCertificateTimestampList inside OCTET STRING: uint16 total, then uint16-prefixed SCTs
            const inner = readTLV(val, 0).value();
            let p = 2;
            while (p + 2 <= inner.length) {
              const l = (inner[p] << 8) | inner[p + 1];
              p += 2 + l;
              ext.sctCount++;
              if (ext.sctCount > 50) break;
            }
            break;
          }
          case '2.5.29.37': {
            for (const k of children(val, readTLV(val, 0))) ext.ekus.push(decodeOID(k.value()));
            break;
          }
          case '1.3.6.1.5.5.7.1.24': ext.mustStaple = true; break;
          case '2.5.29.15': {
            // KeyUsage BIT STRING: first byte = unused bits; bit 0 (MSB) digitalSignature … bit 5 keyCertSign, bit 6 cRLSign
            const bs = readTLV(val, 0).value();
            const b0 = bs.length > 1 ? bs[1] : 0;
            ext.keyUsage = {
              digitalSignature: !!(b0 & 0x80), keyEncipherment: !!(b0 & 0x20),
              keyCertSign: !!(b0 & 0x04), cRLSign: !!(b0 & 0x02),
            };
            break;
          }
          default: break;
        }
      } catch { /* ignore malformed individual extension */ }
    }
  }

  let sigInfo = SIG_ALGS[sigAlg.oid] ? { ...SIG_ALGS[sigAlg.oid] } : { name: sigAlg.oid, family: 'unknown', hash: null };
  if (sigAlg.oid === '1.2.840.113549.1.1.10') {
    const pss = parsePssParams(der, sigAlg.params);
    sigInfo = { ...sigInfo, hash: pss.hash, saltLength: pss.saltLength, name: `RSASSA-PSS (${pss.hash})` };
  }
  let validationType = null;
  for (const p of ext.policies) if (POLICY_TYPES[p]) validationType = POLICY_TYPES[p];

  const serialBytes = serialT.value();
  return {
    der,
    version,
    serialNumber: toHex(serialBytes[0] === 0 && serialBytes.length > 1 ? serialBytes.subarray(1) : serialBytes, ':').toUpperCase(),
    tbs: tbsT.raw(),
    signatureAlgorithm: sigInfo,
    signature: der.subarray(sigT.start + 1, sigT.end),
    issuer, issuerDer: issuerT.raw(),
    subject, subjectDer: subjectT.raw(),
    issuerString: nameToString(issuer),
    subjectString: nameToString(subject),
    subjectCN: nameGet(subject, 'CN'),
    subjectO: nameGet(subject, 'O'),
    issuerCN: nameGet(issuer, 'CN'),
    issuerO: nameGet(issuer, 'O'),
    notBefore: decodeTime(nbT),
    notAfter: decodeTime(naT),
    spkiDer: spkiT.raw(),
    publicKey: spki,
    hasSanExt,
    ...ext,
    validationType,
  };
}

export function isSelfIssued(cert) {
  const a = cert.issuerDer; const b = cert.subjectDer;
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
