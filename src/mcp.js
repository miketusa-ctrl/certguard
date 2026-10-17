/**
 * CertGuard remote MCP server (since v0.2.0). Hand-rolled JSON-RPC 2.0 over Streamable HTTP; no SDK, no dependencies.
 * Adapted from DnsGuard src/lib/mcp.js.
 *
 * Dual-era and stateless:
 *  - Modern (MCP 2026-07-28): every request carries params._meta["io.modelcontextprotocol/protocolVersion"] plus the
 *    MCP-Protocol-Version / Mcp-Method / Mcp-Name headers. Methods: server/discover, tools/list, tools/call.
 *  - Legacy (2025-11-25, 2025-06-18, 2025-03-26, 2024-11-05): initialize handshake, notifications/initialized, ping,
 *    tools/list, tools/call. JSON-RPC batches (max 10 messages, at most one tools/call) are accepted for legacy clients.
 *  - No sessions: no Mcp-Session-Id is ever issued; one sent by a client is ignored. GET/DELETE → 405 (no SSE stream).
 *  - Responses are always application/json (no SSE).
 *
 * Auth + limits are NOT implemented here: the router passes in authenticate() and runCheck() from app.js, the exact
 * functions behind GET/POST /api/v1/check, so key handling, the result cache and every per-minute / daily / global
 * counter are identical. One tools/call = one check. initialize / tools/list / ping / server/discover never touch
 * check quota; they have a light per-isolate cap per IP bucket (DISCOVERY_PER_MIN; IPv6 → its /64).
 */
import { VERSION } from './check.js';
import { parseTarget, TargetError, ALLOWED_PORTS } from './netguard.js';

export const MODERN_VERSIONS = ['2026-07-28'];
export const LEGACY_VERSIONS = ['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];
export const SUPPORTED_VERSIONS = [...MODERN_VERSIONS, ...LEGACY_VERSIONS];
export const MAX_BODY_BYTES = 64 * 1024;
export const MAX_BATCH = 10;
export const MAX_CHECKS_PER_REQUEST = 1; // bounds CPU per invocation (cpu_ms = 100) and keeps 1 HTTP request ≈ 1 check
export const DISCOVERY_PER_MIN = 120; // per IP bucket per isolate, for non-check messages (initialize, tools/list, ping, …)
const META_VERSION = 'io.modelcontextprotocol/protocolVersion';
const META_CAPS = 'io.modelcontextprotocol/clientCapabilities';
const META_SERVER = 'io.modelcontextprotocol/serverInfo';
const ERROR_META = 'certguard/error';
export const PASS_HEADERS = ['retry-after', 'x-certguard-cache', 'x-certguard-plan']; // the headers /api/v1/check sends

// JSON-RPC / MCP error codes
export const E = {
  PARSE: -32700, INVALID_REQUEST: -32600, METHOD_NOT_FOUND: -32601, INVALID_PARAMS: -32602, INTERNAL: -32603,
  SERVER: -32000, // implementation-defined (auth, rate limit, body too large, forbidden origin)
  HEADER_MISMATCH: -32020, UNSUPPORTED_VERSION: -32022,
};

export const MCP_CORS = {
  // Keys are explicit headers (never ambient cookies), so a wildcard origin without credentials is safe and lets
  // browser-based MCP inspectors work. Same policy as /api/v1/check.
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'POST, OPTIONS', // GET/DELETE → 405 (no SSE stream, no sessions)
  'access-control-allow-headers': 'content-type, accept, authorization, x-api-key, mcp-protocol-version, mcp-method, mcp-name',
  'access-control-expose-headers': ['mcp-protocol-version', ...PASS_HEADERS].join(', '),
  'access-control-max-age': '86400',
};

export const SERVER_INFO = { name: 'certguard', title: 'CertGuard', version: VERSION };
export const instructions = (L = { anonPerMin: 10, anonDailyPerIp: 200, keyPerMin: 60, keyDailyQuota: 1000 }) => 'CertGuard checks a server\'s SSL/TLS certificate with a live TLS handshake: expiry, chain completeness and trust (Mozilla roots), hostname match, TLS version, cipher suite and key, and returns an A/B/C/F grade with findings. Call check_certificate with a hostname such as example.com (port 443 by default; 8443, 465, 993 and 995 are also allowed). Revocation (OCSP/CRL) is never checked. Hosts on Cloudflare\'s own network cannot be checked live: the tool then returns an isError result with code live_check_unavailable and no grade; a failed handshake returns check_failed with no grade. Results are cached for up to 10 minutes. Anonymous use is limited to about ' + L.anonPerMin + ' checks per minute and ' + L.anonDailyPerIp + ' per day per IP; send "Authorization: Bearer <key>" or "X-API-Key: <key>" with a free cg_ key (POST /api/v1/keys) for about ' + L.keyPerMin + ' per minute and ' + L.keyDailyQuota + ' per day.';

const PORTS = ALLOWED_PORTS;
const issueSchema = { type: 'object', properties: { severity: { type: 'string', enum: ['critical', 'warning', 'info'] }, code: { type: 'string' }, message: { type: 'string' } }, required: ['severity', 'code', 'message'] };

export const TOOLS = [{
  name: 'check_certificate',
  title: 'Check a server\'s SSL/TLS certificate (expiry, chain, hostname, TLS version)',
  description: 'Run a live TLS handshake against host:port and audit the certificate the server presents. Returns an A/B/C/F grade and summary, expiry (days remaining), hostname match, chain completeness and trust against Mozilla\'s root store, negotiated TLS version and cipher suite, key type/size, findings, and a link to the full report. Revocation (OCSP/CRL) is NOT checked. Hosts on Cloudflare\'s own network cannot be checked live (result: isError with code live_check_unavailable, no grade); a failed handshake returns check_failed with no grade. Read-only: it only opens a TLS connection to the public host. Same engine, cache and limits as the CertGuard JSON API (GET /api/v1/check).',
  inputSchema: {
    type: 'object',
    properties: {
      host: { type: 'string', minLength: 1, maxLength: 300, description: 'Hostname or public IP to check, e.g. example.com. An https:// URL is accepted and reduced to its host (and port). Private, internal and reserved addresses are rejected.' },
      port: { type: 'integer', enum: PORTS, default: 443, description: `TCP port (default 443). Allowed: ${PORTS.join(', ')}.` },
      include_raw: { type: 'boolean', default: false, description: 'Also return the full /api/v1/check JSON (all chain certificates, SANs, handshake attempts) in structuredContent.raw. Larger output.' },
    },
    required: ['host'],
    additionalProperties: false,
  },
  outputSchema: {
    type: 'object',
    properties: {
      host: { type: 'string' },
      port: { type: 'integer' },
      status: { type: 'string', enum: ['checked'] },
      grade: { type: 'string', enum: ['A', 'B', 'C', 'F'] },
      gradeEstimated: { type: 'boolean', description: 'true when the result was inferred from Certificate Transparency logs instead of a live handshake' },
      summary: { type: 'string' },
      revocation_checked: { type: 'boolean', description: 'Always false: OCSP/CRL status is not queried' },
      source: { type: 'object', properties: { method: { type: 'string', enum: ['live_tls_handshake', 'certificate_transparency'] }, live: { type: 'boolean' }, ip: { type: 'string' } } },
      expiry: { type: 'object', properties: { notBefore: { type: 'string' }, notAfter: { type: 'string' }, daysRemaining: { type: 'integer' }, status: { type: 'string', enum: ['ok', 'warning', 'critical', 'expired', 'not_yet_valid'] } } },
      hostname: { type: 'object', properties: { matches: { type: 'boolean' }, matchedName: { type: 'string' }, note: { type: 'string' } } },
      certificate: {
        type: 'object',
        properties: {
          subject: { type: 'string' }, issuer: { type: 'string' }, issuerOrg: { type: 'string' },
          sans: { type: 'array', items: { type: 'string' }, description: 'First 20 DNS names' }, sanCount: { type: 'integer' },
          key: { type: 'string' }, signatureAlgorithm: { type: 'string' }, validationType: { type: 'string' }, sha256Fingerprint: { type: 'string' },
        },
      },
      tls: { type: 'object', properties: { version: { type: 'string' }, cipherSuite: { type: 'string' }, keyExchangeGroup: { type: 'string' }, ocspStapled: { type: 'boolean' } } },
      chain: { type: 'object', properties: { presented: { type: 'integer' }, complete: { type: 'boolean' }, trusted: { type: 'boolean' }, trustAnchor: { type: 'string' } } },
      issues: { type: 'array', items: issueSchema },
      notChecked: { type: 'array', items: { type: 'string' } },
      checkedAt: { type: 'string' },
      cached: { type: 'boolean' },
      plan: { type: 'string', enum: ['anonymous', 'key'] },
      reportUrl: { type: 'string' },
      apiUrl: { type: 'string' },
      version: { type: 'string' },
      raw: { type: 'object', description: 'Full /api/v1/check response (only when include_raw is true)' },
    },
    required: ['host', 'port', 'status', 'grade', 'summary', 'revocation_checked', 'reportUrl'],
  },
  annotations: { title: 'Check SSL/TLS certificate', readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
}];
const TOOL_ARGS = Object.keys(TOOLS[0].inputSchema.properties); // inputSchema says additionalProperties: false; enforced in callTool

const clip = (s, n) => (typeof s === 'string' && s.length > n ? `${s.slice(0, n - 1)}…` : s);
const str = (v, n) => (typeof v === 'string' && v ? clip(v, n) : undefined);
const bool = (v) => (typeof v === 'boolean' ? v : undefined);
const int = (v) => (Number.isInteger(v) ? v : undefined);
/** Drop undefined/null members so structuredContent never carries a null where the outputSchema expects a type. */
const compact = (o) => Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined && v !== null));

export function reportLinks(origin, host, port) {
  const q = `host=${encodeURIComponent(host)}${port !== 443 ? `&port=${port}` : ''}`;
  return { reportUrl: `${origin}/?${q}`, apiUrl: `${origin}/api/v1/check?${q}` };
}

/** Concise, schema-conforming summary of a full /api/v1/check 200 body. Every string clipped, every array sliced. */
export function summarizeCheck(body, { origin, plan, cached, includeRaw }) {
  const c = body.certificate || {};
  const x = body.expiry || {};
  const h = body.hostname || {};
  const t = body.tls || {};
  const ch = body.chain || {};
  const src = body.source || {};
  const out = compact({
    host: clip(String(body.host), 300),
    port: body.port,
    status: 'checked',
    grade: body.grade,
    gradeEstimated: body.gradeEstimated === true ? true : undefined,
    summary: clip(String(body.summary || ''), 600),
    revocation_checked: false,
    source: compact({ method: str(src.method, 40), live: bool(src.live), ip: str(src.ip, 60) }),
    expiry: compact({ notBefore: str(x.notBefore, 40), notAfter: str(x.notAfter, 40), daysRemaining: int(x.daysRemaining), status: str(x.status, 20) }),
    hostname: compact({ matches: bool(h.matches), matchedName: str(h.matchedName, 300), note: str(h.note, 300) }),
    certificate: compact({
      subject: str(c.subject, 300), issuer: str(c.issuer, 300), issuerOrg: str(c.issuerOrg, 200),
      sans: Array.isArray(c.sans) ? c.sans.slice(0, 20).map((s) => clip(String(s), 255)) : undefined,
      sanCount: int(c.sanCount),
      key: c.key && typeof c.key === 'object' ? str(c.key.label, 60) : undefined,
      signatureAlgorithm: str(c.signatureAlgorithm, 80), validationType: str(c.validationType, 20), sha256Fingerprint: str(c.sha256Fingerprint, 64),
    }),
    tls: compact({ version: str(t.version, 20), cipherSuite: str(t.cipherSuite, 80), keyExchangeGroup: str(t.keyExchangeGroup, 40), ocspStapled: bool(t.ocspStapled) }),
    chain: compact({ presented: int(ch.presented), complete: bool(ch.complete), trusted: bool(ch.trusted), trustAnchor: str(ch.trustAnchor, 300) }),
    issues: (body.issues || []).slice(0, 10).map((i) => ({ severity: String(i.severity), code: clip(String(i.code), 60), message: clip(String(i.message), 300) })),
    notChecked: (body.notChecked || []).slice(0, 8).map((n) => clip(String(n), 200)),
    checkedAt: str(body.checkedAt, 40),
    cached: !!cached,
    plan: plan || 'anonymous',
    ...reportLinks(origin, body.host, body.port),
    version: VERSION,
  });
  if (includeRaw) out.raw = body;
  return out;
}

/** Human/LLM-readable text version of the summary (also the content[0] block). */
export function summaryText(s) {
  const lines = [`CertGuard check for ${s.host}:${s.port}: grade ${s.grade}${s.gradeEstimated ? ' (estimated from CT logs, not live)' : ''}. ${s.summary}`];
  if (s.expiry.notAfter) lines.push(`- Expires: ${s.expiry.notAfter} (${s.expiry.daysRemaining} days, ${s.expiry.status})`);
  if (s.hostname.matches !== undefined) lines.push(`- Hostname match: ${s.hostname.matches ? 'yes' : 'no'}${s.hostname.matchedName ? ` (${s.hostname.matchedName})` : ''}`);
  if (s.chain.trusted !== undefined) lines.push(`- Chain: ${s.chain.trusted ? 'trusted' : 'NOT trusted'}, ${s.chain.complete ? 'complete' : 'incomplete'}${s.chain.trustAnchor ? `, anchor ${s.chain.trustAnchor}` : ''}`);
  if (s.tls.version) lines.push(`- TLS: ${s.tls.version}${s.tls.cipherSuite ? `, ${s.tls.cipherSuite}` : ''}`);
  if (s.certificate.issuer) lines.push(`- Issuer: ${s.certificate.issuer}`);
  if (s.certificate.key) lines.push(`- Key: ${s.certificate.key}`);
  const notable = s.issues.filter((i) => i.severity !== 'info');
  if (notable.length) lines.push('', 'Issues:', ...notable.map((i) => `- [${i.severity}] ${i.message}`));
  lines.push('', 'Revocation (OCSP/CRL) was not checked.', `Full report: ${s.reportUrl}`);
  return lines.join('\n');
}

function toolError(message, data, extra = {}) {
  return { content: [{ type: 'text', text: message }], isError: true, ...(data ? { _meta: { [ERROR_META]: data } } : {}), ...extra };
}

/** Text for a non-200 /api/v1/check body (check_failed, live_unavailable, rate limits, blocked targets, …). */
function failureText(r, retry) {
  const b = r.body || {};
  const e = b.error || {};
  let msg = String(e.message || 'The check could not be completed.');
  const attempts = b.source && Array.isArray(b.source.attempts) ? b.source.attempts : [];
  if (attempts.length) msg += `\nAttempts: ${attempts.slice(0, 3).map((a) => `${clip(String(a.offered), 40)} → ${clip(String(a.result), 40)}`).join('; ')}`;
  if ((b.status === 'check_failed' || b.status === 'live_unavailable') && !/no grade/i.test(msg)) msg += '\nNo grade is given for this host.';
  if (retry) msg += ` (retry after ${retry} seconds)`;
  return clip(msg, 1200);
}

/** tools/call for check_certificate. Returns { result } or { error } (protocol error), plus HTTP headers to surface. */
async function callTool(params, deps, auth) {
  const { name } = params;
  const args = params.arguments === undefined ? {} : params.arguments;
  if (name !== TOOLS[0].name) return { error: { code: E.INVALID_PARAMS, message: `Unknown tool: ${clip(String(name), 80)}` } };
  if (!args || typeof args !== 'object' || Array.isArray(args)) return { error: { code: E.INVALID_PARAMS, message: 'arguments must be an object' } };
  // Input problems are tool-execution errors (isError) so the model can correct itself. No limiter/KV/socket is touched.
  const unknown = Object.keys(args).filter((k) => !TOOL_ARGS.includes(k));
  if (unknown.length) {
    return { result: toolError(`Unknown argument(s): ${clip(unknown.slice(0, 5).join(', '), 80)}. Allowed: ${TOOL_ARGS.join(', ')}.`, { code: 'invalid_arguments', httpStatus: 400 }) };
  }
  if (typeof args.host !== 'string') return { result: toolError('host is required and must be a string, e.g. "example.com".', { code: 'invalid_host', httpStatus: 400 }) };
  if (args.port !== undefined && args.port !== null && !Number.isInteger(args.port)) return { result: toolError(`port must be an integer; allowed: ${PORTS.join(', ')}.`, { code: 'invalid_port', httpStatus: 400 }) };
  if (args.include_raw !== undefined && typeof args.include_raw !== 'boolean') return { result: toolError('include_raw must be a boolean.', { code: 'invalid_arguments', httpStatus: 400 }) };
  const port = args.port === undefined || args.port === null ? undefined : args.port;
  // Same parser and rules as /api/v1/check (it runs again inside runCheck); pre-checked here so bad input costs no quota.
  try { parseTarget(args.host, port); } catch (e) {
    if (e instanceof TargetError) return { result: toolError(`${e.message}.`, { code: e.code, httpStatus: e.status }) };
    throw e;
  }
  const r = await deps.runCheck({ host: args.host, port, auth });
  const headers = { ...(r.headers || {}) };
  if (r.status !== 200) {
    const retry = headers['retry-after'] ? Number(headers['retry-after']) : undefined;
    const b = r.body || {};
    const e = b.error || {};
    return { result: toolError(failureText(r, retry), compact({ code: String(e.code || 'error'), reason: str(e.reason, 60), httpStatus: r.status, retryAfterSeconds: retry })), headers };
  }
  const summary = summarizeCheck(r.body, { origin: deps.origin, plan: auth.plan, cached: !!(r.body.cache && r.body.cache.hit), includeRaw: args.include_raw === true });
  return { result: { content: [{ type: 'text', text: summaryText(summary) }], structuredContent: summary, isError: false }, headers };
}

// ---------- transport helpers ----------

/** Origin policy: absent = OK (CLI / server-side clients). Present: must be a bare https origin or an http loopback
 * origin, or (if MCP_ALLOWED_ORIGINS is set) same-origin / listed. Malformed, "null" and plain-http remote → 403. */
export function originAllowed(origin, selfOrigin, allowList) {
  if (origin === null || origin === undefined) return true;
  if (origin === selfOrigin) return true;
  if (allowList) return String(allowList).split(',').map((s) => s.trim()).filter(Boolean).includes(origin);
  let u;
  try { u = new URL(origin); } catch { return false; }
  if (u.origin !== origin) return false;
  if (u.protocol === 'https:') return true;
  return u.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname);
}

async function readCapped(request, cap) {
  const cl = Number(request.headers.get('content-length'));
  if (Number.isFinite(cl) && cl > cap) return null;
  if (!request.body) return '';
  const reader = request.body.getReader();
  const chunks = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > cap) { try { await reader.cancel(); } catch { /* ignore */ } return null; }
    chunks.push(value);
  }
  const buf = new Uint8Array(size);
  let o = 0;
  for (const c of chunks) { buf.set(c, o); o += c.byteLength; }
  return new TextDecoder().decode(buf);
}

function decodeHeaderValue(v) {
  if (v == null) return v;
  const m = /^=\?base64\?([A-Za-z0-9+/=]*)\?=$/.exec(v);
  if (!m) return v;
  try { return new TextDecoder().decode(Uint8Array.from(atob(m[1]), (ch) => ch.charCodeAt(0))); } catch { return null; }
}

const isId = (id) => typeof id === 'string' || (typeof id === 'number' && Number.isFinite(id));
const rpcError = (id, code, message, data) => ({ jsonrpc: '2.0', ...(id !== undefined ? { id } : {}), error: { code, message, ...(data !== undefined ? { data } : {}) } });
const rpcResult = (id, result) => ({ jsonrpc: '2.0', id, result });

/**
 * Handle one JSON-RPC message. Returns { response?, status?, headers?, isCheck? }.
 * `response` undefined = notification accepted (202 when it's the whole request).
 */
async function handleMessage(msg, { modern, request, deps, auth, checkBudget }) {
  if (!msg || typeof msg !== 'object' || Array.isArray(msg)) return { response: rpcError(null, E.INVALID_REQUEST, 'Invalid Request'), status: 400 };
  const hasId = Object.prototype.hasOwnProperty.call(msg, 'id');
  if (msg.jsonrpc !== '2.0') return { response: rpcError(hasId && isId(msg.id) ? msg.id : null, E.INVALID_REQUEST, 'Invalid Request: jsonrpc must be "2.0"'), status: 400 };
  if (typeof msg.method !== 'string') {
    // A JSON-RPC response or garbage. Legacy clients may POST responses → accept like a notification.
    if (!modern && hasId && ('result' in msg || 'error' in msg)) return {};
    return { response: rpcError(hasId && isId(msg.id) ? msg.id : null, E.INVALID_REQUEST, 'Invalid Request: method is required'), status: 400 };
  }
  if (!hasId) return {}; // notification (notifications/initialized, cancelled, …): accepted, nothing to do
  if (!isId(msg.id)) return { response: rpcError(null, E.INVALID_REQUEST, 'Invalid Request: id must be a string or number'), status: 400 };
  const { id, method } = msg;
  const params = msg.params === undefined ? {} : msg.params;
  if (!params || typeof params !== 'object' || Array.isArray(params)) return { response: rpcError(id, E.INVALID_PARAMS, 'params must be an object') };

  // Modern results carry serverInfo in _meta; merge so a tool error's _meta["certguard/error"] is kept.
  const done = (result) => ({ response: rpcResult(id, modern ? { resultType: 'complete', ...result, _meta: { ...(result._meta || {}), [META_SERVER]: SERVER_INFO } } : result) });
  const notFound = () => ({ response: rpcError(id, E.METHOD_NOT_FOUND, `Method not found: ${clip(method, 80)}`), status: modern ? 404 : 200 });
  const instr = instructions(deps.limits);

  if (modern) {
    // MCP 2026-07-28 per-request validation (version, capabilities, mirrored headers).
    const hName = decodeHeaderValue(request.headers.get('mcp-name'));
    if (request.headers.get('mcp-method') !== method) return { response: rpcError(id, E.HEADER_MISMATCH, 'Header mismatch: Mcp-Method header is missing or does not match the body method'), status: 400 };
    if (!params._meta || typeof params._meta[META_CAPS] !== 'object' || params._meta[META_CAPS] === null) {
      return { response: rpcError(id, E.INVALID_PARAMS, `Missing required _meta field ${META_CAPS}`), status: 400 };
    }
    if (method === 'tools/call' && hName !== params.name) return { response: rpcError(id, E.HEADER_MISMATCH, 'Header mismatch: Mcp-Name header is missing or does not match params.name'), status: 400 };
    if (method === 'server/discover') {
      return done({ supportedVersions: SUPPORTED_VERSIONS, capabilities: { tools: { listChanged: false } }, instructions: instr, ttlMs: 3_600_000, cacheScope: 'public' });
    }
    if (method === 'tools/list') return done({ tools: TOOLS, ttlMs: 3_600_000, cacheScope: 'public' });
    if (method !== 'tools/call') return notFound(); // includes initialize and ping (removed in 2026-07-28)
  } else {
    if (method === 'initialize') {
      const req = params.protocolVersion;
      const protocolVersion = LEGACY_VERSIONS.includes(req) ? req : LEGACY_VERSIONS[0];
      return done({ protocolVersion, capabilities: { tools: { listChanged: false } }, serverInfo: SERVER_INFO, instructions: instr });
    }
    if (method === 'ping') return done({});
    if (method === 'tools/list') return done({ tools: TOOLS });
    if (method === 'server/discover') return done({ supportedVersions: SUPPORTED_VERSIONS, capabilities: { tools: { listChanged: false } }, serverInfo: SERVER_INFO, instructions: instr });
    if (method !== 'tools/call') return notFound();
  }

  // tools/call
  if (typeof params.name !== 'string') return { response: rpcError(id, E.INVALID_PARAMS, 'params.name (tool name) is required') };
  if (checkBudget.used >= MAX_CHECKS_PER_REQUEST) {
    return { response: rpcError(id, E.INVALID_REQUEST, `At most ${MAX_CHECKS_PER_REQUEST} tools/call per HTTP request; send each call as its own request.`) };
  }
  checkBudget.used++;
  const r = await callTool(params, deps, auth);
  if (r.error) return { response: rpcError(id, r.error.code, r.error.message), isCheck: true };
  return { ...done(r.result), headers: r.headers, isCheck: true };
}

/** Entry point from the router for every request to /mcp. */
export async function handleMcp(request, env, ctx, deps) {
  const base = { ...MCP_CORS, ...deps.security };
  const reply = (status, body, extra = {}) => new Response(body === null ? null : JSON.stringify(body), {
    status,
    headers: { ...(body === null ? {} : { 'content-type': 'application/json; charset=utf-8' }), 'cache-control': 'no-store', ...base, ...extra },
  });
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: { ...MCP_CORS, ...deps.security } });
  if (!originAllowed(request.headers.get('origin'), deps.origin, deps.allowedOrigins)) {
    return reply(403, rpcError(undefined, E.SERVER, 'Forbidden: Origin not allowed'));
  }
  if (request.method !== 'POST') {
    return reply(405, rpcError(undefined, E.SERVER, 'Method not allowed. This MCP endpoint is stateless: POST JSON-RPC messages (no SSE stream, no sessions). Docs: /llms.txt'), { allow: 'POST, OPTIONS' });
  }
  const text = await readCapped(request, MAX_BODY_BYTES);
  if (text === null) return reply(413, rpcError(undefined, E.INVALID_REQUEST, `Request body too large (max ${MAX_BODY_BYTES} bytes)`));
  let payload;
  try { payload = JSON.parse(text); } catch { return reply(400, rpcError(null, E.PARSE, 'Parse error: body must be valid JSON')); }

  // Era detection. Modern = per-request _meta version or a modern MCP-Protocol-Version header.
  const hVer = request.headers.get('mcp-protocol-version');
  const single = !Array.isArray(payload);
  const metaVer = single && payload && typeof payload === 'object' && payload.params && typeof payload.params === 'object'
    && payload.params._meta && typeof payload.params._meta === 'object' ? payload.params._meta[META_VERSION] : undefined;
  const modern = metaVer !== undefined || MODERN_VERSIONS.includes(hVer);
  const idOf = (p) => (p && typeof p === 'object' && isId(p.id) ? p.id : null);
  if (modern) {
    if (!single) return reply(400, rpcError(null, E.INVALID_REQUEST, 'JSON-RPC batches are not supported in protocol 2026-07-28; send one message per POST'));
    if (payload && typeof payload === 'object' && Object.prototype.hasOwnProperty.call(payload, 'id')) {
      if (metaVer === undefined && typeof payload.method === 'string') {
        return reply(400, rpcError(idOf(payload), E.INVALID_PARAMS, `Missing required _meta field ${META_VERSION}`));
      }
      if (metaVer !== undefined && !SUPPORTED_VERSIONS.includes(metaVer)) {
        return reply(400, rpcError(idOf(payload), E.UNSUPPORTED_VERSION, 'Unsupported protocol version', { supported: SUPPORTED_VERSIONS, requested: clip(String(metaVer), 40) }));
      }
      if (metaVer !== undefined && !MODERN_VERSIONS.includes(metaVer)) {
        return reply(400, rpcError(idOf(payload), E.UNSUPPORTED_VERSION, `Protocol version ${metaVer} uses the initialize handshake; per-request _meta requires one of: ${MODERN_VERSIONS.join(', ')}`, { supported: SUPPORTED_VERSIONS, requested: metaVer }));
      }
      if (hVer !== metaVer) return reply(400, rpcError(idOf(payload), E.HEADER_MISMATCH, 'Header mismatch: MCP-Protocol-Version header is missing or does not match _meta protocolVersion'));
    }
  } else if (hVer && !LEGACY_VERSIONS.includes(hVer)) {
    return reply(400, rpcError(single ? idOf(payload) : null, E.UNSUPPORTED_VERSION, 'Unsupported protocol version', { supported: SUPPORTED_VERSIONS, requested: clip(hVer, 40) }));
  }

  const msgs = single ? [payload] : payload;
  if (!msgs.length) return reply(400, rpcError(null, E.INVALID_REQUEST, 'Invalid Request: empty batch'));
  if (msgs.length > MAX_BATCH) return reply(400, rpcError(null, E.INVALID_REQUEST, `Batch too large (max ${MAX_BATCH} messages)`));

  // Light per-IP-bucket cap on non-check messages (checks are governed by the /api/v1/check limits inside runCheck).
  const nonCheck = msgs.filter((m) => !(m && m.method === 'tools/call')).length;
  for (let i = 0; i < nonCheck; i++) {
    if (!deps.memLimit(`mcp:${deps.ipBucket}`, DISCOVERY_PER_MIN, 60_000)) {
      return reply(429, rpcError(single ? idOf(payload) : null, E.SERVER, `Too many MCP requests from your IP (about ${DISCOVERY_PER_MIN} per minute). Retry in a minute.`, { code: 'rate_limited', retryAfterSeconds: 60 }), { 'retry-after': '60' });
    }
  }

  // Same key gate as /api/v1/check, evaluated once per HTTP request (bad key → 401 for every method).
  const auth = await deps.authenticate(request, env);
  if (!auth.ok) {
    // No WWW-Authenticate on /mcp: MCP clients treat a 401 Bearer challenge as "start OAuth discovery", which this
    // server doesn't offer; the JSON-RPC error body (data.code = invalid_api_key) is the useful signal.
    return reply(auth.status, rpcError(single ? idOf(payload) : null, E.SERVER, auth.message, { code: auth.code, httpStatus: auth.status }), { ...(auth.headers || {}) });
  }

  const mdeps = { ...deps, env, ctx };
  const checkBudget = { used: 0 };
  const responses = [];
  let status = 200;
  let headers = {};
  for (const m of msgs) {
    let out;
    try {
      out = await handleMessage(m, { modern, request, deps: mdeps, auth, checkBudget });
    } catch {
      out = { response: rpcError(idOf(m), E.INTERNAL, 'Internal error') };
    }
    if (out.response) responses.push(out.response);
    if (single) status = out.status || 200;
    if (out.headers) headers = out.headers; // the (single) tools/call's /api headers, for batches too
  }
  if (!responses.length) return reply(202, null);
  const exposed = {};
  for (const h of PASS_HEADERS) if (headers[h]) exposed[h] = headers[h];
  return reply(status, single ? responses[0] : responses, exposed);
}
