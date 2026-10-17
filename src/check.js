// Orchestrates one certificate check. Transport and fetch are injected so this runs in the
// Worker (cloudflare:sockets) and in Node tests (node:net) unchanged.
import { handshakeProbe, TlsProbeError, TLS_VERSIONS } from './tls.js';
import { parseCertificate } from './x509.js';
import { analyzeChain, matchHostname, expiryInfo, grade, describeKey, sha256Hex, keyIsWeak } from './analysis.js';
import { resolvePublic, isCloudflareIp, TargetError } from './netguard.js';
import { ctLookup, CtUnavailable } from './ct.js';

export const VERSION = '0.3.0';

function withTimeout(promise, ms, code, message) {
  let t;
  return Promise.race([
    promise,
    new Promise((_, rej) => { t = setTimeout(() => rej(new TlsProbeError(code, message)), ms); }),
  ]).finally(() => clearTimeout(t));
}

async function liveProbe(transportFactory, ip, port, opts, timeoutMs) {
  const started = Date.now();
  const transport = await withTimeout(transportFactory(ip, port), Math.min(4000, timeoutMs), 'connect_timeout', `TCP connect to ${ip}:${port} timed out`);
  try {
    const left = Math.max(500, timeoutMs - (Date.now() - started));
    return await withTimeout(handshakeProbe(transport, opts), left, 'handshake_timeout', 'TLS handshake timed out');
  } finally {
    try { transport.close(); } catch { /* ignore */ }
  }
}

async function certSummary(c, now) {
  return {
    subject: c.subjectString,
    subjectCN: c.subjectCN,
    issuer: c.issuerString,
    issuerCN: c.issuerCN,
    issuerOrg: c.issuerO,
    serialNumber: c.serialNumber,
    notBefore: c.notBefore.toISOString(),
    notAfter: c.notAfter.toISOString(),
    expired: c.notAfter < now,
    key: describeKey(c.publicKey),
    signatureAlgorithm: c.signatureAlgorithm.name,
    isCA: c.isCA,
    sha256Fingerprint: await sha256Hex(c.der),
  };
}

/**
 * target: { host, port, ip, isIp } from parseTarget()
 * deps: { transportFactory(ip, port) → Promise<transport>, fetchImpl, now, timeoutMs }
 */
export async function runCheck(target, deps) {
  const { transportFactory, fetchImpl = fetch, timeoutMs = 7000 } = deps;
  const now = deps.now || new Date();
  const t0 = Date.now();
  const { host, port, isIp } = target;

  // 1. Resolve + SSRF screen (every resolved address must be public).
  let addrs;
  if (isIp) addrs = { all: [{ ip: host, bytes: target.ip, family: target.ip.length === 4 ? 4 : 6 }] };
  else addrs = await resolvePublic(host, { fetchImpl, timeoutMs: 3000 });
  const pick = addrs.all.find((a) => a.family === 4) || addrs.all[0];
  const cfProxied = isCloudflareIp(pick.bytes);

  // 2. Live handshake (pinned to the resolved, screened IP — no second DNS lookup → no rebinding).
  const sni = isIp ? null : host;
  const alpn = port === 443 || port === 8443 ? ['http/1.1'] : null;
  let probe = null;
  const attempts = [];
  if (!cfProxied) {
    // Router hook: reserve/count against the global live-check cap only when a real outbound connection is
    // about to be attempted. Throws (e.g. 429) to stop before any socket is opened.
    if (deps.beforeConnect) await deps.beforeConnect();
    for (const tls13 of [true, false]) {
      try {
        probe = await liveProbe(transportFactory, pick.ip, port, { sni, tls13, alpn }, timeoutMs);
        attempts.push({ offered: tls13 ? 'TLS 1.3+1.2' : 'TLS 1.2 only', result: 'ok' });
        break;
      } catch (e) {
        attempts.push({ offered: tls13 ? 'TLS 1.3+1.2' : 'TLS 1.2 only', result: e.code || 'error', message: String(e.message || e).slice(0, 200) });
        const retryable = ['tls_alert', 'connection_closed', 'decode_error', 'hello_retry', 'unsupported_suite', 'decrypt_failed', 'unexpected_message'];
        if (!retryable.includes(e.code)) break;
      }
      if (Date.now() - t0 > timeoutMs) break;
    }
  }

  if (probe && probe.certs && probe.certs.length) {
    return buildLiveResult({ host, port, isIp, pick, addrs, probe, attempts, now, t0 });
  }

  const last = attempts[attempts.length - 1];
  // Only the published Cloudflare IP list proves "Cloudflare network". A runtime refusal detected by
  // message regex on a non-listed IP is labelled socket_blocked, and is never negative-cached.
  const socketBlocked = !cfProxied && !!(last && PLATFORM_BLOCK_RE.test(last.message || ''));
  const platformBlocked = cfProxied || socketBlocked;

  // 3. Any failure that is NOT the platform's Cloudflare-network restriction is reported as a failed
  //    check: no grade, never a CT substitute, never cached.
  if (!platformBlocked) {
    throw checkFailed({ host, port, pick, addrs, attempts, now });
  }

  // 4. Target is on Cloudflare's network (or the platform refused the socket): live check impossible.
  //    CT fallback only if a Cert Spotter API key is configured; otherwise say so honestly, no grade.
  const lu = (o) => liveUnavailable({ host, port, pick, addrs, attempts, now, cfProxied, ...o });
  const where = cfProxied
    ? `${host} is served from Cloudflare's network, which Cloudflare Workers cannot open TCP sockets to`
    : `the Workers runtime refused the outbound connection to ${pick.ip}:${port} (a platform restriction — e.g. a Cloudflare address not in our IP list — or a transient runtime error; not cached, try again shortly)`;
  // socket_blocked is final whether or not a CT key is configured — only Cloudflare-list IPs may ever fall
  // through to CT. (No grade, never cached.)
  if (socketBlocked) {
    throw lu({ status: 422, reason: 'socket_blocked', message: `Live check unavailable for this ${isIp ? 'target' : 'host'}: ${where}. No grade is given.` });
  }
  if (isIp) {
    throw lu({ status: 422, reason: 'cloudflare_network_ip',
      message: `${host} is on Cloudflare's network, which Cloudflare Workers cannot open TCP sockets to, so a live check is unavailable for this target. CT lookup is not possible for raw IP addresses. No grade is given.` });
  }
  if (!cfProxied) throw new Error('internal: CT fallback reached for a non-Cloudflare-list target'); // defence in depth
  let ct;
  try {
    ct = await ctLookup(host, { apiKey: deps.ctApiKey, kv: deps.kv, ctx: deps.ctx, fetchImpl, timeoutMs: 6000, now, hourlyBudget: deps.ctHourlyBudget });
  } catch (e) {
    if (!(e instanceof CtUnavailable)) throw e;
    const noKey = e.reason === 'no_api_key';
    throw lu({ status: noKey ? 422 : 503, reason: noKey ? 'cloudflare_network' : e.reason, retryAfter: e.retryAfter,
      message: noKey
        ? `Live check unavailable for this host: ${where}. No grade is given. (A Certificate Transparency fallback exists but is not enabled on this deployment.)`
        : `Live check unavailable for this host: ${where}, and the Certificate Transparency fallback is temporarily unavailable: ${e.message} No grade is given.` });
  }
  if (!ct.found) {
    throw lu({ status: 422, reason: 'no_ct_data',
      message: `Live check unavailable for this host: ${where}, and no currently valid certificate for it was found in Certificate Transparency logs. No grade is given.` });
  }
  return buildCtResult({ host, port, pick, addrs, ct, attempts, platformBlocked, cfProxied, now, t0 });
}

const PLATFORM_BLOCK_RE = /proxy request failed|cannot connect to the specified address/i;

/**
 *  Error carrying a complete JSON body + HTTP status; the router returns it as-is. Only errors with
 *  negCacheable=true (422 for an IP on the published Cloudflare list) may be negative-cached.
 */
export class CheckResponseError extends Error {
  constructor(status, body, headers = {}, { negCacheable = false } = {}) { super(body.error.message); this.status = status; this.body = body; this.headers = headers; this.negCacheable = negCacheable; }
}

const REASON_TEXT = {
  connect_timeout: 'the TCP connection timed out (port closed/filtered or host down)',
  handshake_timeout: 'the TLS handshake timed out',
  tls_alert: 'the server rejected our TLS handshake',
  connection_closed: 'the server closed the connection during the handshake',
  not_tls: 'the server did not respond with TLS',
  too_large: "the server's handshake/certificate message exceeds CertGuard's size limit",
  hello_retry: 'the server requested an unsupported key-exchange group',
  unsupported_suite: 'the server chose a cipher suite CertGuard cannot decrypt',
  no_certificate: 'the server sent no certificate',
  parse_error: "the server's certificate could not be parsed",
};

function checkFailed({ host, port, pick, addrs, attempts, now, reason, detail }) {
  const last = attempts[attempts.length - 1] || {};
  const r = reason || last.result || 'error';
  const why = REASON_TEXT[r] || 'the TLS handshake failed';
  const message = `Check failed: couldn't complete a TLS handshake with ${host}:${port} — ${why}${detail || last.message ? ` (${detail || last.message})` : ''}. No grade is given because no certificate could be read.`;
  return new CheckResponseError(502, {
    ok: false, status: 'check_failed', grade: null, host, port, checkedAt: now.toISOString(),
    revocation_checked: false,
    error: { code: 'check_failed', reason: r, message },
    summary: message,
    source: { method: 'live_tls_handshake', live: true, ip: pick.ip, resolved: addrs.all.map((a) => a.ip).slice(0, 8), attempts },
    cache: { hit: false, cached: false },
  });
}

function liveUnavailable({ host, port, pick, addrs, attempts, now, status, reason, message, retryAfter, cfProxied = true }) {
  return new CheckResponseError(status, {
    ok: false, status: 'live_unavailable', grade: null, host, port, checkedAt: now.toISOString(),
    revocation_checked: false,
    error: { code: 'live_check_unavailable', reason, message },
    summary: message,
    source: { method: 'none', live: false, ip: pick.ip, cloudflareNetwork: !!cfProxied, socketBlocked: !cfProxied, resolved: addrs.all.map((a) => a.ip).slice(0, 8), attempts },
    cache: { hit: false, cached: false },
  }, retryAfter ? { 'retry-after': String(retryAfter) } : {}, { negCacheable: !!cfProxied && status === 422 });
}

async function buildLiveResult({ host, port, isIp, pick, addrs, probe, attempts, now, t0 }) {
  const certs = [];
  const parseErrors = [];
  for (let i = 0; i < probe.certs.length; i++) {
    try { certs.push(parseCertificate(probe.certs[i])); } catch (e) {
      parseErrors.push(`cert #${i}: ${e.message}`);
      if (i === 0) throw checkFailed({ host, port, pick, addrs, attempts, now, reason: 'parse_error', detail: e.message });
    }
  }
  const leaf = certs[0];
  const chain = await analyzeChain(certs, now);
  const hostname = matchHostname(leaf, host, isIp);
  const expiry = expiryInfo(leaf, now);
  const key = describeKey(leaf.publicKey);
  const tls13Offered = attempts[attempts.length - 1].offered.startsWith('TLS 1.3');
  const g = grade({ expiry, hostname, chain, key, tlsVersion: probe.version, live: tls13Offered });
  const issues = [];
  if (expiry.status !== 'ok') issues.push({ severity: expiry.status === 'warning' ? 'warning' : 'critical', code: 'expiry_' + expiry.status, message: expiry.status === 'expired' ? `Certificate expired ${-expiry.daysRemaining} day(s) ago.` : expiry.status === 'not_yet_valid' ? 'Certificate is not yet valid.' : `Certificate expires in ${expiry.daysRemaining} day(s).` });
  if (!hostname.matches) issues.push({ severity: 'critical', code: 'hostname_mismatch', message: `Certificate does not cover ${host}. ${hostname.note || ''}`.trim() });
  if (keyIsWeak(leaf.publicKey)) issues.push({ severity: 'warning', code: 'weak_key', message: `Weak key: ${key.label}.` });
  issues.push(...chain.issues);
  issues.push({ severity: 'info', code: 'revocation_not_checked', message: 'Revocation (OCSP/CRL) is not checked — a revoked certificate can still get a passing grade here.' });
  if (probe.version < 0x0303) issues.push({ severity: 'warning', code: 'old_tls', message: `Server negotiated ${probe.versionName}.` });
  else if (probe.version === 0x0303 && tls13Offered) issues.push({ severity: 'info', code: 'no_tls13', message: 'Server does not support TLS 1.3 (negotiated TLS 1.2).' });
  if (!tls13Offered) issues.push({ severity: 'info', code: 'tls13_probe_failed', message: `TLS 1.3 probe failed (${attempts[0].message}); details came from a TLS 1.2-only handshake.` });

  const chainCerts = [];
  for (let i = 0; i < certs.length; i++) {
    const s = await certSummary(certs[i], now);
    s.index = i;
    const pos = chain.path.indexOf(i);
    s.role = i === 0 ? 'leaf' : pos >= 0 ? (certs[i].isCA ? 'intermediate' : 'intermediate') : 'extra';
    if (pos >= 0 && pos === chain.path.length - 1 && chain.anchorInChain) s.role = 'root (sent by server)';
    chainCerts.push(s);
  }
  return {
    ok: true,
    status: 'checked',
    revocation_checked: false,
    host, port,
    checkedAt: now.toISOString(),
    source: {
      method: 'live_tls_handshake',
      live: true,
      description: `Live TLS handshake from Cloudflare Workers to ${pick.ip}:${port}${isIp ? '' : ` (SNI ${host})`}; certificate chain read directly from the server${probe.version === 0x0304 ? ' (TLS 1.3 handshake decrypted with an ephemeral key exchange)' : ''}.`,
      ip: pick.ip,
      resolved: addrs.all.map((a) => a.ip).slice(0, 8),
      attempts,
    },
    grade: g.grade,
    summary: g.summary,
    expiry,
    certificate: {
      ...(await certSummary(leaf, now)),
      sans: leaf.san.dns.slice(0, 100),
      sanCount: leaf.san.dns.length + leaf.san.ips.length,
      ipSans: leaf.san.ips.slice(0, 20),
      validationType: leaf.validationType,
      sctCount: leaf.sctCount,
      ocspUrls: leaf.ocsp, caIssuersUrls: leaf.caIssuers,
      mustStaple: leaf.mustStaple,
    },
    hostname: { requested: host, ...hostname },
    tls: {
      version: probe.versionName,
      versionNote: tls13Offered ? 'Highest version negotiated when offering TLS 1.3 and 1.2.' : 'Negotiated with a TLS 1.2-only ClientHello (TLS 1.3 attempt failed).',
      cipherSuite: probe.cipherName,
      keyExchangeGroup: probe.group,
      alpn: probe.alpn,
      ocspStapled: probe.ocspStapled,
      helloRetryRequest: probe.hrr,
    },
    chain: {
      presented: certs.length,
      complete: chain.complete,
      trusted: chain.trusted,
      trustAnchor: chain.trustAnchor,
      trustStore: chain.trustStore,
      orderOk: chain.orderOk,
      verifiedPath: chain.path,
      signaturesVerified: chain.signaturesVerified,
      certificates: chainCerts,
      parseErrors,
    },
    issues,
    measuredLive: ['certificate chain', 'expiry', 'hostname match', 'chain completeness/trust (signatures verified against Mozilla roots; basicConstraints, keyUsage keyCertSign and pathLen enforced)', 'TLS version', 'cipher suite', 'key exchange group', 'OCSP stapling'],
    notChecked: ['revocation (OCSP/CRL status)', 'legacy protocol support (SSLv3/TLS 1.0/1.1 acceptance)', 'full cipher-suite enumeration', 'name constraints / EKU path rules', 'CertificateVerify signature (server key possession)'],
    timingMs: Date.now() - t0,
  };
}

async function buildCtResult({ host, port, pick, addrs, ct, attempts, platformBlocked, cfProxied, now, t0 }) {
  const c = ct.cert;
  const fake = c || { notBefore: new Date(ct.newest.notBefore), notAfter: new Date(ct.newest.notAfter), san: { dns: ct.newest.dnsNames, ips: [] }, subjectCN: null };
  const expiry = expiryInfo(fake, now);
  const hostname = matchHostname(fake, host, false);
  const key = c ? describeKey(c.publicKey) : null;
  const g = grade({ expiry, hostname, chain: null, key, tlsVersion: null, live: false });
  const issues = [{ severity: 'info', code: 'not_live', message: cfProxied ? 'Target is served from Cloudflare\'s network; Cloudflare Workers cannot open raw TCP sockets to Cloudflare IPs, so this result comes from Certificate Transparency logs, not a live handshake.' : `Live handshake failed (${attempts.length ? attempts[attempts.length - 1].message : 'n/a'}); this result comes from Certificate Transparency logs.` }];
  if (expiry.status !== 'ok') issues.push({ severity: expiry.status === 'warning' ? 'warning' : 'critical', code: 'expiry_' + expiry.status, message: `Newest logged certificate expires in ${expiry.daysRemaining} day(s).` });
  issues.push({ severity: 'info', code: 'revocation_not_checked', message: 'Revocation (OCSP/CRL) is not checked — a revoked certificate can still get a passing grade here.' });
  if (ct.count > 1) issues.push({ severity: 'info', code: 'multiple_certs', message: `${ct.count} unexpired certificates are logged for this name; the server may present any of them (shown: the most recently issued).` });
  return {
    ok: true,
    status: 'checked',
    revocation_checked: false,
    host, port,
    checkedAt: now.toISOString(),
    source: {
      method: 'certificate_transparency',
      live: false,
      provider: 'SSLMate Cert Spotter API (public CT logs)',
      description: 'INFERRED: used only because this host is on Cloudflare\'s network, which Workers cannot open TCP sockets to. This is the most recently issued, currently valid certificate for this name found in public Certificate Transparency logs — not necessarily the certificate the server presents. Chain, TLS version and trust were NOT observed.',
      ctQuery: { mode: ct.mode, apiCalls: ct.calls, truncated: !!ct.truncated },
      reason: cfProxied ? 'cloudflare_network_target' : platformBlocked ? 'socket_blocked' : 'live_handshake_failed',
      ip: pick.ip,
      resolved: addrs.all.map((a) => a.ip).slice(0, 8),
      attempts,
    },
    grade: g.grade,
    gradeEstimated: true,
    summary: `Estimated from CT logs (not a live check): ${g.summary}`,
    expiry,
    certificate: c ? {
      ...(await certSummary(c, now)),
      sans: c.san.dns.slice(0, 100), sanCount: c.san.dns.length, validationType: c.validationType,
      ctLogEntry: ct.newest,
    } : { notBefore: ct.newest.notBefore, notAfter: ct.newest.notAfter, issuer: ct.newest.issuer, sans: ct.newest.dnsNames, ctLogEntry: ct.newest },
    hostname: { requested: host, ...hostname },
    tls: { version: null, note: 'Not observed (no live handshake).' },
    chain: { presented: null, complete: null, trusted: null, note: 'Not observed. Certificates in CT logs are issued by publicly-trusted CAs, but the chain the server sends is unknown.' },
    ct: { currentCertificates: ct.count, earliestNotAfter: ct.earliestNotAfter, candidates: ct.candidates },
    issues,
    measuredLive: [],
    inferred: ['certificate details', 'expiry', 'hostname coverage'],
    notChecked: ['revocation (OCSP/CRL status)', 'served chain', 'trust path', 'TLS version', 'cipher suite', 'legacy protocol support (TLS 1.0/1.1)'],
    timingMs: Date.now() - t0,
  };
}
