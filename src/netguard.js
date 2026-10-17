// Target validation & SSRF protection: hostname syntax, blocked names, private/reserved IP ranges,
// DNS-over-HTTPS resolution (Cloudflare 1.1.1.1 resolver) and port allowlist.

export const ALLOWED_PORTS = [443, 8443, 465, 993, 995];

export class TargetError extends Error {
  constructor(code, message, status = 400) { super(message); this.code = code; this.status = status; }
}

// ---------- IP parsing ----------
export function parseIPv4(s) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (!m) return null;
  const b = m.slice(1).map(Number);
  if (b.some((x) => x > 255)) return null;
  if (m.slice(1).some((x) => x.length > 1 && x[0] === '0')) return null; // no leading zeros (octal ambiguity)
  return Uint8Array.from(b);
}

export function parseIPv6(s) {
  if (s.startsWith('[') && s.endsWith(']')) s = s.slice(1, -1);
  if (s.includes('%')) return null; // zone ids not allowed
  if (!/^[0-9a-fA-F:.]+$/.test(s) || !s.includes(':')) return null;
  let tailV4 = null;
  const lastColon = s.lastIndexOf(':');
  if (s.slice(lastColon + 1).includes('.')) {
    tailV4 = parseIPv4(s.slice(lastColon + 1));
    if (!tailV4) return null;
    s = s.slice(0, lastColon + 1) + '0:0';
  }
  const dbl = s.split('::');
  if (dbl.length > 2) return null;
  const head = dbl[0] ? dbl[0].split(':') : [];
  const tail = dbl.length === 2 && dbl[1] ? dbl[1].split(':') : [];
  if (dbl.length === 1 && head.length !== 8) return null;
  if (dbl.length === 2 && head.length + tail.length > 7) return null;
  const groups = [...head, ...Array(8 - head.length - tail.length).fill('0'), ...tail];
  const out = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(groups[i])) return null;
    const v = parseInt(groups[i], 16);
    out[i * 2] = v >> 8; out[i * 2 + 1] = v & 0xff;
  }
  if (tailV4) out.set(tailV4, 12);
  return out;
}

export function ipToString(bytes) {
  if (bytes.length === 4) return Array.from(bytes).join('.');
  const g = [];
  for (let i = 0; i < 16; i += 2) g.push(((bytes[i] << 8) | bytes[i + 1]).toString(16));
  // compress longest zero run
  let best = -1, bestLen = 0;
  for (let i = 0; i < 8;) {
    if (g[i] !== '0') { i++; continue; }
    let j = i; while (j < 8 && g[j] === '0') j++;
    if (j - i > bestLen && j - i > 1) { best = i; bestLen = j - i; }
    i = j;
  }
  if (best < 0) return g.join(':');
  return g.slice(0, best).join(':') + '::' + g.slice(best + bestLen).join(':');
}

function inCidr(bytes, base, prefix) {
  if (bytes.length !== base.length) return false;
  let bits = prefix;
  for (let i = 0; i < bytes.length && bits > 0; i++) {
    const take = Math.min(8, bits);
    const mask = (0xff << (8 - take)) & 0xff;
    if ((bytes[i] & mask) !== (base[i] & mask)) return false;
    bits -= take;
  }
  return true;
}

function cidr(str) {
  const [ip, p] = str.split('/');
  const bytes = ip.includes(':') ? parseIPv6(ip) : parseIPv4(ip);
  return [bytes, Number(p), str];
}

// Private, loopback, link-local, CGNAT, documentation, benchmarking, multicast, reserved...
const BLOCKED_V4 = [
  '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24',
  '192.0.2.0/24', '192.31.196.0/24', '192.52.193.0/24', '192.88.99.0/24', '192.168.0.0/16', '192.175.48.0/24',
  '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4', '255.255.255.255/32',
].map(cidr);
const BLOCKED_V6 = [
  '::/128', '::1/128', '::ffff:0:0/96', '::/96', '64:ff9b::/96', '64:ff9b:1::/48', '100::/64', '2001::/23', '2001:db8::/32',
  '2002::/16', '3fff::/20', '5f00::/16', 'fc00::/7', 'fe80::/10', 'fec0::/10', 'ff00::/8',
].map(cidr);

// Cloudflare's published ranges (https://www.cloudflare.com/ips/). Workers cannot open TCP sockets to these.
export const CLOUDFLARE_RANGES = [
  '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '141.101.64.0/18', '108.162.192.0/18',
  '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
  '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22', '1.1.1.0/24', '1.0.0.0/24',
  '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32', '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
].map(cidr);

/** Returns the matching blocked range string, or null if the IP is publicly routable. */
export function blockedRange(bytes) {
  if (bytes.length === 4) {
    for (const [b, p, s] of BLOCKED_V4) if (inCidr(bytes, b, p)) return s;
    return null;
  }
  // IPv4-mapped / NAT64 / 6to4 are blocked outright above, but also report the embedded v4 reason.
  for (const [b, p, s] of BLOCKED_V6) if (inCidr(bytes, b, p)) return s;
  return null;
}

export function isCloudflareIp(bytes) {
  for (const [b, p] of CLOUDFLARE_RANGES) if (inCidr(bytes, b, p)) return true;
  return false;
}

// ---------- hostnames ----------
const BLOCKED_NAMES = new Set([
  'localhost', 'localhost.localdomain', 'ip6-localhost', 'ip6-loopback', 'broadcasthost',
  'metadata', 'metadata.google.internal', 'metadata.goog', 'instance-data', 'instance-data.ec2.internal',
  'metadata.azure.com', 'metadata.packet.net', 'metadata.platformequinix.com', 'metadata.oraclecloud.com',
  'kubernetes', 'kubernetes.default', 'kubernetes.default.svc',
]);
const BLOCKED_SUFFIXES = [
  'localhost', 'local', 'internal', 'localdomain', 'lan', 'home', 'home.arpa', 'intranet', 'corp', 'private',
  'test', 'example', 'invalid', 'onion', 'arpa', 'svc', 'cluster.local', 'alt',
];

const LABEL_RE = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;

/**
 * Parse and strictly validate user input. Accepts "host", "host:port", "[v6]:port", or a pasted URL
 * ("https://host:port/path"). Returns { host, port, ip: Uint8Array|null, isIp }.
 */
export function parseTarget(rawHost, rawPort) {
  if (typeof rawHost !== 'string') throw new TargetError('invalid_host', 'host is required');
  let input = rawHost.trim();
  if (!input) throw new TargetError('invalid_host', 'host is required');
  if (input.length > 300) throw new TargetError('invalid_host', 'host is too long');
  if (/[\s\\@]/.test(input) && !/^[a-z]+:\/\//i.test(input)) throw new TargetError('invalid_host', 'host contains invalid characters');
  let port = null;
  let url;
  try {
    url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(input) ? input : 'https://' + input);
  } catch {
    throw new TargetError('invalid_host', 'not a valid hostname');
  }
  if (!/^https?:$/.test(url.protocol)) throw new TargetError('invalid_host', 'only hostnames or https:// URLs are accepted');
  if (url.username || url.password) throw new TargetError('invalid_host', 'credentials in URL are not allowed');
  if (url.port) port = Number(url.port);
  else if (/^https?:\/\//i.test(input) && url.protocol === 'http:') port = 443; // http://x → check 443
  let host = url.hostname.toLowerCase();
  if (host.endsWith('.')) host = host.slice(0, -1);

  if (rawPort !== undefined && rawPort !== null && rawPort !== '') {
    const p = typeof rawPort === 'number' ? rawPort : (/^\d{1,5}$/.test(String(rawPort)) ? Number(rawPort) : NaN);
    if (!Number.isInteger(p)) throw new TargetError('invalid_port', 'port must be an integer');
    if (port !== null && port !== p) throw new TargetError('invalid_port', 'conflicting ports in host and port parameters');
    port = p;
  }
  if (port === null) port = 443;
  if (!ALLOWED_PORTS.includes(port)) {
    throw new TargetError('port_not_allowed', `port ${port} is not allowed; allowed ports: ${ALLOWED_PORTS.join(', ')}`);
  }

  // IP literals (URL parser normalizes decimal/hex/octal IPv4 forms like 2130706433 or 0x7f.1 to dotted quads)
  if (host.startsWith('[')) {
    const ip = parseIPv6(host);
    if (!ip) throw new TargetError('invalid_host', 'invalid IPv6 address');
    const r = blockedRange(ip);
    if (r) throw new TargetError('blocked_target', `target address is in a private/reserved range (${r})`, 403);
    return { host: ipToString(ip), port, ip, isIp: true };
  }
  const v4 = parseIPv4(host);
  if (v4) {
    const r = blockedRange(v4);
    if (r) throw new TargetError('blocked_target', `target address is in a private/reserved range (${r})`, 403);
    return { host, port, ip: v4, isIp: true };
  }

  if (host.length > 253) throw new TargetError('invalid_host', 'hostname is too long');
  const labels = host.split('.');
  // Internal / metadata names are rejected first (403) so they are reported as blocked, not merely invalid.
  if (BLOCKED_NAMES.has(host) || (labels.length > 1 && BLOCKED_NAMES.has(labels[0]) && /^(metadata|instance-data|kubernetes)$/.test(labels[0]))) {
    throw new TargetError('blocked_target', 'internal/metadata hostnames are not allowed', 403);
  }
  for (const suf of BLOCKED_SUFFIXES) {
    if (host === suf || host.endsWith('.' + suf)) throw new TargetError('blocked_target', `hostnames under .${suf} are not allowed`, 403);
  }
  if (labels.length < 2) throw new TargetError('invalid_host', 'hostname must be fully qualified (e.g. example.com)');
  for (const l of labels) if (!LABEL_RE.test(l)) throw new TargetError('invalid_host', `invalid hostname label "${l.slice(0, 63)}"`);
  if (/^\d+$/.test(labels[labels.length - 1])) throw new TargetError('invalid_host', 'invalid top-level domain');
  return { host, port, ip: null, isIp: false };
}

// ---------- DNS over HTTPS ----------
const DOH_ENDPOINTS = ['https://cloudflare-dns.com/dns-query', 'https://1.1.1.1/dns-query'];

async function dohQuery(fetchImpl, name, type, timeoutMs) {
  let lastErr;
  for (const ep of DOH_ENDPOINTS) {
    try {
      const res = await fetchImpl(`${ep}?name=${encodeURIComponent(name)}&type=${type}`, {
        headers: { accept: 'application/dns-json' },
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (!res.ok) throw new Error(`DoH HTTP ${res.status}`);
      return await res.json();
    } catch (e) { lastErr = e; }
  }
  throw new TargetError('dns_error', `DNS lookup failed (${lastErr && lastErr.message})`, 502);
}

/**
 * Resolve A and AAAA via DoH. Rejects if ANY resolved address is private/reserved.
 * Returns { v4: [str], v6: [str], all: [{ip, bytes, family}] }.
 */
export async function resolvePublic(host, { fetchImpl = fetch, timeoutMs = 3000 } = {}) {
  const [a, aaaa] = await Promise.all([dohQuery(fetchImpl, host, 'A', timeoutMs), dohQuery(fetchImpl, host, 'AAAA', timeoutMs)]);
  if (a.Status === 3 && aaaa.Status === 3) throw new TargetError('nxdomain', `${host} does not exist (NXDOMAIN)`, 422);
  if (a.Status !== 0 && aaaa.Status !== 0) throw new TargetError('dns_error', `DNS lookup failed (rcode ${a.Status})`, 502);
  const all = [];
  for (const [resp, type, family] of [[a, 1, 4], [aaaa, 28, 6]]) {
    for (const ans of resp.Answer || []) {
      if (ans.type !== type) continue;
      const bytes = family === 4 ? parseIPv4(ans.data) : parseIPv6(ans.data);
      if (!bytes) continue;
      const r = blockedRange(bytes);
      if (r) throw new TargetError('blocked_target', `${host} resolves to a private/reserved address (${ipToString(bytes)} in ${r})`, 403);
      all.push({ ip: ipToString(bytes), bytes, family });
      if (all.length > 32) break;
    }
  }
  if (!all.length) throw new TargetError('no_address', `${host} has no A/AAAA records`, 422);
  return { all, v4: all.filter((x) => x.family === 4).map((x) => x.ip), v6: all.filter((x) => x.family === 6).map((x) => x.ip) };
}

/**
 * Bucket a client IP for rate limiting / quotas: IPv4 as-is, IPv6 grouped by /64 (one subscriber
 * typically controls a whole /64, so per-address buckets would be trivially bypassed).
 */
export function ipBucket(ip) {
  if (typeof ip !== 'string' || !ip) return 'unknown';
  if (ip.includes(':')) {
    const b = parseIPv6(ip);
    if (!b) return 'v6:invalid';
    const g = [];
    for (let i = 0; i < 8; i += 2) g.push(((b[i] << 8) | b[i + 1]).toString(16));
    return g.join(':') + '::/64';
  }
  return parseIPv4(ip) ? ip : 'v4:invalid';
}

/** Coarser IPv6 aggregate: the /48 containing the address; null for IPv4 / unparseable. */
export function ipBucket48(ip) {
  if (typeof ip !== 'string' || !ip.includes(':')) return null;
  const b = parseIPv6(ip);
  if (!b) return null;
  const g = [];
  for (let i = 0; i < 6; i += 2) g.push(((b[i] << 8) | b[i + 1]).toString(16));
  return g.join(':') + '::/48';
}
