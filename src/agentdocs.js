/**
 * Agent-discovery documents (since v0.2.0): /llms.txt (llmstxt.org format), /openapi.json (OpenAPI 3.1) and the MCP
 * server card (/.well-known/mcp/server-card.json). Generated from code constants and config(env) so limits / versions /
 * URLs can't drift from what the Worker enforces.
 */
import { VERSION } from './check.js';
import { ALLOWED_PORTS } from './netguard.js';
import { TOOLS, SERVER_INFO, SUPPORTED_VERSIONS, MAX_BODY_BYTES, MAX_BATCH, DISCOVERY_PER_MIN } from './mcp.js';

export const CONTACT_EMAIL = 'digitalpromohub.support@gmail.com';
const fmt = (n) => Number(n).toLocaleString('en-US');

export function mcpClientConfig(origin) {
  return { mcpServers: { certguard: { type: 'http', url: `${origin}/mcp` } } };
}

/** MCP registry HTTP-namespace proof: only a well-formed PUBLIC key record is ever served (else 404). */
export function registryAuthProof(env) {
  const proof = String((env && env.MCP_REGISTRY_AUTH) || '').trim();
  return /^v=MCPv1; k=(ed25519|ecdsap384); p=[A-Za-z0-9+/=]{20,120}$/.test(proof) ? proof : null;
}

export function llmsTxt(origin, L) {
  const tool = TOOLS[0];
  return `# CertGuard

> Free SSL/TLS certificate checker: a live TLS handshake reports expiry, chain completeness and trust, hostname match, TLS version, cipher suite and key, with an A/B/C/F grade and findings. Public JSON API plus a remote MCP server for AI agents.

CertGuard connects to the host you name (ports ${ALLOWED_PORTS.join(', ')}) from Cloudflare Workers, reads the certificate chain the server sends and verifies it against Mozilla's root store. Revocation (OCSP/CRL) is never checked; every result says \`"revocation_checked": false\`. Hosts served from Cloudflare's own network cannot be checked live (Workers can't open sockets to Cloudflare IPs): they get \`live_unavailable\` and no grade. A failed handshake returns \`check_failed\` and no grade. Private, internal and reserved addresses are refused.

## For AI agents

- [MCP server](${origin}/mcp): remote MCP over Streamable HTTP at \`${origin}/mcp\` (POST only, stateless, JSON responses, no sessions). Protocol versions: ${SUPPORTED_VERSIONS.join(', ')} (2026-07-28 per-request \`_meta\`; older versions use \`initialize\`). One tool: \`${tool.name}\` with \`host\` (required), \`port\` and \`include_raw\` (optional). Read-only. Client config (most MCP clients accept this; some use a different format, for example VS Code uses a \`servers\` key): \`${JSON.stringify(mcpClientConfig(origin))}\`
- [OpenAPI 3.1 spec](${origin}/openapi.json): machine-readable description of the JSON API
- [JSON API docs](${origin}/docs): human-readable API reference with examples

## JSON API

- \`GET ${origin}/api/v1/check?host=example.com\` (optional \`&port=443\`; allowed ${ALLOWED_PORTS.join(', ')}), or \`POST\` with \`{"host":"example.com","port":443}\`: full result as JSON (\`grade\`, \`summary\`, \`expiry\`, \`certificate\`, \`hostname\`, \`tls\`, \`chain\`, \`issues\`, \`notChecked\`, \`revocation_checked\`, \`cache\`). CORS enabled.
- \`POST ${origin}/api/v1/keys\` with \`{}\` or \`{"email":"you@example.com"}\` (JSON, no CORS): free API key, shown once.
- \`GET ${origin}/api/v1/usage\` with your key: today's usage and quota.
- \`GET ${origin}/health\`: service status and \`version\` (${VERSION}).
- Errors: \`{ "ok": false, "error": { "code", "message" } }\` with HTTP 400 \`invalid_host\`/\`invalid_port\`/\`port_not_allowed\`/\`invalid_json\`, 401 \`invalid_api_key\`, 403 \`blocked_target\`, 413 \`payload_too_large\`, 422 \`nxdomain\`/\`no_address\`/\`live_check_unavailable\`, 429 \`rate_limited\`/\`ip_daily_quota\`/\`key_quota_exceeded\`/\`issuer_quota_exceeded\`/\`daily_cap_reached\` (see \`Retry-After\`), 502 \`check_failed\`/\`dns_error\`, 503 \`not_configured\`/\`live_check_unavailable\`.

## Limits and keys

- Anonymous (no key): about ${L.anonPerMin} checks per minute and ${fmt(L.anonDailyPerIp)} per UTC day per IP (IPv6: per /64, and ${fmt(L.anonDailyPer48)} per /48).
- Free API key: about ${L.keyPerMin} checks per minute and ${fmt(L.keyDailyQuota)} per UTC day; all keys issued to one IP share ${fmt(L.keyIssuerDailyQuota)} checks per day. Send \`X-API-Key: cg_…\` or \`Authorization: Bearer cg_…\`. At most ${L.keyIssuePerIpPerDay} new keys per IP per day.
- CertGuard Pro ($5/month, sold through Polar): ${fmt(L.proDailyQuota)} checks per UTC day per license on an allowance separate from the free service. Send the license key (\`CGPR-…\`) the same way. Checkout: https://buy.polar.sh/polar_cl_EU23jaHuY4BVGE1EIFLBs9npUZk9p9479tUvN2yrUcy. An inactive, cancelled or unknown key gets the same HTTP 401 \`invalid_api_key\` as any bad key.
- Limits apply to every check request, including ones answered from the cache. Successful live results are cached for up to ${Math.round(L.cacheTtl / 60)} minutes; failed checks are never cached.
- The MCP endpoint uses the same keys and the same counters: each \`tools/call\` is one check. \`initialize\`, \`tools/list\` and other non-check messages don't count as checks, but have a light cap of about ${DISCOVERY_PER_MIN} per minute per IP (over it: HTTP 429 with \`Retry-After\`). Over a check limit, the tool result has \`isError: true\` with the reason and \`retryAfterSeconds\`. An invalid key returns HTTP 401.
- MCP request caps: ${fmt(MAX_BODY_BYTES)}-byte body, JSON-RPC batches (legacy versions only) of at most ${MAX_BATCH} messages with at most one \`tools/call\`.

## Optional

- [Homepage and checker](${origin}/)
- Contact: ${CONTACT_EMAIL}
`;
}

/** SEP-1649-style server card (Smithery fallback). Generated from the same TOOLS as tools/list. */
export function serverCard(origin) {
  return {
    $schema: 'https://static.modelcontextprotocol.io/schemas/mcp-server-card/v1.json',
    version: '1.0',
    protocolVersion: SUPPORTED_VERSIONS[0],
    serverInfo: SERVER_INFO,
    description: 'Free SSL/TLS certificate checker: live TLS handshake, expiry, chain trust, hostname match, TLS version, A/B/C/F grade.',
    websiteUrl: `${origin}/`,
    transport: { type: 'streamable-http', url: `${origin}/mcp` },
    capabilities: { tools: { listChanged: false } },
    authentication: { required: false, schemes: ['bearer'] },
    tools: TOOLS,
    resources: [],
    prompts: [],
  };
}

const errorSchema = { $ref: '#/components/schemas/Error' };
const json = (schema) => ({ 'application/json': { schema } });
const errResp = (description, extraHeaders) => ({ description, ...(extraHeaders ? { headers: extraHeaders } : {}), content: json(errorSchema) });
const retryAfter = { 'Retry-After': { description: 'Seconds to wait before retrying', schema: { type: 'integer' } } };
const mcpNotAllowed = (m) => ({
  tags: ['mcp'],
  operationId: `mcp_${m}_not_allowed`,
  summary: 'Not supported (stateless server: no SSE stream, no sessions)',
  responses: {
    405: { description: 'Always 405 with `Allow: POST, OPTIONS` and a JSON-RPC error body', headers: { Allow: { schema: { type: 'string', const: 'POST, OPTIONS' } } }, content: json({ type: 'object' }) },
  },
});

export function openApiSpec(origin, L) {
  const checkHeaders = {
    'x-certguard-cache': { description: '`HIT` (served from the result cache), `MISS` (fresh check, or a negative answer that will be cached) or `BYPASS` (never cached: failed checks and temporary errors)', schema: { type: 'string', enum: ['HIT', 'MISS', 'BYPASS'] } },
    'x-certguard-plan': { description: '`anonymous` or `key`', schema: { type: 'string', enum: ['anonymous', 'key'] } },
  };
  const checkResponses = {
    200: { description: 'Check result (live handshake, or, only when a CT fallback is enabled, an estimate from Certificate Transparency logs with gradeEstimated: true)', headers: checkHeaders, content: json({ $ref: '#/components/schemas/CheckResult' }) },
    400: errResp('`invalid_host`, `invalid_port`, `port_not_allowed` or (POST) `invalid_json`'),
    401: errResp('`invalid_api_key`: a key was sent but is unknown or revoked'),
    403: errResp('`blocked_target`: private, internal or reserved address or name (also when DNS resolves to one)', checkHeaders),
    405: errResp('`method_not_allowed`', { Allow: { schema: { type: 'string' } } }),
    413: errResp('`payload_too_large`: POST body over 16 KB'),
    422: { description: '`nxdomain` / `no_address` (error body), or `status: "live_unavailable"` with `error.code = "live_check_unavailable"` and `grade: null` (Cloudflare-network target or socket refused by the runtime)', headers: checkHeaders, content: json({ oneOf: [errorSchema, { $ref: '#/components/schemas/FailedCheck' }] }) },
    429: errResp('`rate_limited` (per-minute), `ip_daily_quota`, `key_quota_exceeded`, `issuer_quota_exceeded` or `daily_cap_reached` (service-wide daily allowance)', retryAfter),
    500: errResp('`internal_error`'),
    502: { description: '`status: "check_failed"` (TLS handshake could not be completed; `grade: null`, never cached) or `dns_error`', headers: checkHeaders, content: json({ oneOf: [errorSchema, { $ref: '#/components/schemas/FailedCheck' }] }) },
    503: { description: '`not_configured` (deployment missing a secret) or a temporary `live_unavailable` (CT fallback unavailable)', headers: { ...retryAfter, ...checkHeaders }, content: json({ oneOf: [errorSchema, { $ref: '#/components/schemas/FailedCheck' }] }) },
  };
  const hostParam = { name: 'host', in: 'query', required: true, description: 'Hostname, public IP or https:// URL. Private/internal/reserved targets are rejected.', schema: { type: 'string', minLength: 1, maxLength: 300 }, example: 'example.com' };
  const portParam = { name: 'port', in: 'query', required: false, description: 'TCP port (default 443)', schema: { type: 'integer', enum: ALLOWED_PORTS, default: 443 } };
  const sec = [{}, { apiKeyHeader: [] }, { bearerAuth: [] }];
  return {
    openapi: '3.1.0',
    info: {
      title: 'CertGuard API',
      version: VERSION,
      summary: 'Live SSL/TLS certificate checks: expiry, chain trust, hostname match, TLS version, grade.',
      description: `Free JSON API behind ${origin}. No key needed for light use (about ${L.anonPerMin} checks/min and ${fmt(L.anonDailyPerIp)}/day per IP). A free API key (POST /api/v1/keys) allows about ${L.keyPerMin}/min and ${fmt(L.keyDailyQuota)}/day. Limits apply to cached answers too. There are no X-RateLimit-* headers; a 429 carries Retry-After. Revocation (OCSP/CRL) is never checked. AI agents can also use the remote MCP server at ${origin}/mcp (see /llms.txt).`,
      contact: { name: 'CertGuard', email: CONTACT_EMAIL, url: `${origin}/` },
    },
    servers: [{ url: origin }],
    externalDocs: { description: 'Human-readable API docs', url: `${origin}/docs` },
    tags: [{ name: 'checks' }, { name: 'keys' }, { name: 'meta' }, { name: 'mcp' }],
    components: {
      securitySchemes: {
        apiKeyHeader: { type: 'apiKey', in: 'header', name: 'X-API-Key', description: 'Free key (`cg_` + 32 characters). Optional on /api/v1/check and /mcp.' },
        bearerAuth: { type: 'http', scheme: 'bearer', description: 'Same key as apiKeyHeader, as `Authorization: Bearer cg_…`. X-API-Key wins when both are sent.' },
      },
      schemas: {
        Error: {
          type: 'object', required: ['ok', 'error'],
          properties: { ok: { const: false }, error: { type: 'object', required: ['code', 'message'], properties: { code: { type: 'string' }, message: { type: 'string' } } } },
        },
        Issue: { type: 'object', required: ['severity', 'code', 'message'], properties: { severity: { type: 'string', enum: ['critical', 'warning', 'info'] }, code: { type: 'string' }, message: { type: 'string' } } },
        CheckResult: {
          type: 'object',
          required: ['ok', 'status', 'revocation_checked', 'host', 'port', 'checkedAt', 'source', 'grade', 'summary', 'expiry', 'certificate', 'hostname', 'tls', 'chain', 'issues'],
          additionalProperties: true,
          properties: {
            ok: { const: true },
            status: { const: 'checked' },
            revocation_checked: { const: false },
            host: { type: 'string', examples: ['example.com'] },
            port: { type: 'integer', enum: ALLOWED_PORTS },
            checkedAt: { type: 'string', format: 'date-time' },
            source: { type: 'object', properties: { method: { type: 'string', enum: ['live_tls_handshake', 'certificate_transparency'] }, live: { type: 'boolean' }, ip: { type: 'string' }, attempts: { type: 'array', items: { type: 'object' } } } },
            grade: { type: 'string', enum: ['A', 'B', 'C', 'F'] },
            gradeEstimated: { type: 'boolean' },
            summary: { type: 'string' },
            expiry: { type: 'object', properties: { notBefore: { type: 'string' }, notAfter: { type: 'string' }, daysRemaining: { type: 'integer' }, status: { type: 'string', enum: ['ok', 'warning', 'critical', 'expired', 'not_yet_valid'] }, lifetimeDays: { type: 'integer' } } },
            certificate: { type: 'object', additionalProperties: true },
            hostname: { type: 'object', properties: { requested: { type: 'string' }, matches: { type: 'boolean' }, matchedName: { type: 'string' } } },
            tls: { type: 'object', additionalProperties: true },
            chain: { type: 'object', additionalProperties: true },
            issues: { type: 'array', items: { $ref: '#/components/schemas/Issue' } },
            measuredLive: { type: 'array', items: { type: 'string' } },
            notChecked: { type: 'array', items: { type: 'string' } },
            cache: { type: 'object', properties: { hit: { type: 'boolean' }, ageSeconds: { type: 'integer' }, ttlSeconds: { type: 'integer' } } },
            timingMs: { type: 'integer' },
          },
        },
        FailedCheck: {
          type: 'object', required: ['ok', 'status', 'grade', 'host', 'port', 'revocation_checked', 'error'],
          additionalProperties: true,
          properties: {
            ok: { const: false },
            status: { type: 'string', enum: ['check_failed', 'live_unavailable'] },
            grade: { type: 'null' },
            host: { type: 'string' },
            port: { type: 'integer' },
            revocation_checked: { const: false },
            error: { type: 'object', required: ['code', 'message'], properties: { code: { type: 'string', enum: ['check_failed', 'live_check_unavailable'] }, reason: { type: 'string' }, message: { type: 'string' } } },
            summary: { type: 'string' },
            source: { type: 'object', additionalProperties: true },
          },
        },
        JsonRpcMessage: {
          type: 'object', required: ['jsonrpc'],
          properties: { jsonrpc: { const: '2.0' }, id: { type: ['string', 'integer'] }, method: { type: 'string' }, params: { type: 'object' } },
        },
      },
    },
    paths: {
      '/api/v1/check': {
        get: { tags: ['checks'], operationId: 'checkCertificate', summary: 'Check a server\'s SSL/TLS certificate', security: sec, parameters: [hostParam, portParam], responses: checkResponses },
        post: {
          tags: ['checks'], operationId: 'checkCertificatePost', summary: 'Check a server\'s SSL/TLS certificate (JSON body)', security: sec,
          requestBody: { required: true, content: json({ type: 'object', required: ['host'], properties: { host: hostParam.schema, port: portParam.schema } }) },
          responses: checkResponses,
        },
      },
      '/api/v1/keys': {
        post: {
          tags: ['keys'], operationId: 'createKey', summary: 'Get a free API key (shown once; JSON only; no CORS)', security: [{}],
          requestBody: { required: true, content: json({ type: 'object', properties: { email: { type: 'string', format: 'email', maxLength: 254, description: 'Optional, unverified contact info' } } }) },
          responses: {
            201: { description: 'Key created', content: json({ type: 'object', required: ['ok', 'apiKey', 'keyId'], properties: { ok: { const: true }, apiKey: { type: 'string', pattern: '^cg_[A-Za-z0-9]{32}$' }, keyId: { type: 'string' }, plan: { const: 'free' }, dailyQuota: { type: 'integer' }, perMinute: { type: 'integer' }, note: { type: 'string' } } }) },
            400: errResp('`invalid_json` or `invalid_email`'),
            403: errResp('`cross_origin_forbidden`: requests from other websites are refused'),
            405: errResp('`method_not_allowed`', { Allow: { schema: { type: 'string' } } }),
            413: errResp('`payload_too_large`'),
            415: errResp('`unsupported_media_type`: send application/json'),
            429: errResp(`\`rate_limited\`, \`key_issue_limit\` (at most ${L.keyIssuePerIpPerDay} keys per IP per day) or \`daily_cap_reached\``, retryAfter),
            503: errResp('`not_configured` or `unavailable`'),
          },
        },
      },
      '/api/v1/usage': {
        get: {
          tags: ['keys'], operationId: 'usage', summary: 'Today\'s usage for your key', security: [{ apiKeyHeader: [] }, { bearerAuth: [] }],
          responses: {
            200: { description: 'Usage (approximate, batched counters)', content: json({ type: 'object', properties: { ok: { const: true }, keyId: { type: 'string' }, plan: { type: 'string' }, dailyQuota: { type: 'integer' }, usedToday: { type: 'integer' }, remainingToday: { type: 'integer' }, perMinute: { type: 'integer' }, resetsAt: { type: 'string', format: 'date-time' }, note: { type: 'string' } } }) },
            401: errResp('`missing_api_key` or `invalid_api_key`'),
            405: errResp('`method_not_allowed`', { Allow: { schema: { type: 'string' } } }),
          },
        },
      },
      '/health': {
        get: {
          tags: ['meta'], operationId: 'health', summary: 'Service status and deployed version', security: [{}],
          responses: {
            200: { description: 'OK', content: json({ type: 'object', required: ['ok', 'service', 'version'], properties: { ok: { const: true }, service: { const: 'certguard' }, version: { type: 'string', examples: [VERSION] }, environment: { type: 'string' }, time: { type: 'string', format: 'date-time' } } }) },
            405: errResp('`method_not_allowed`', { Allow: { schema: { type: 'string' } } }),
          },
        },
      },
      '/mcp': {
        post: {
          tags: ['mcp'],
          operationId: 'mcp',
          summary: 'Remote MCP server (Streamable HTTP, JSON-RPC 2.0)',
          description: `Model Context Protocol endpoint. Stateless, JSON responses only (no SSE, no Mcp-Session-Id). Supported protocol versions: ${SUPPORTED_VERSIONS.join(', ')}. Modern (2026-07-28) requests carry params._meta and the MCP-Protocol-Version, Mcp-Method and Mcp-Name headers; legacy clients use initialize. Tool: ${TOOLS[0].name}. Same keys and limits as /api/v1/check; each tools/call counts as one check. Body max ${MAX_BODY_BYTES} bytes; legacy batches max ${MAX_BATCH} messages with at most one tools/call.`,
          security: sec,
          parameters: [
            { name: 'MCP-Protocol-Version', in: 'header', required: false, schema: { type: 'string', enum: SUPPORTED_VERSIONS } },
            { name: 'Mcp-Method', in: 'header', required: false, description: 'Required for 2026-07-28; must equal the body method', schema: { type: 'string' } },
            { name: 'Mcp-Name', in: 'header', required: false, description: 'Required for 2026-07-28 tools/call; must equal params.name', schema: { type: 'string' } },
          ],
          requestBody: {
            required: true,
            content: json({ oneOf: [{ $ref: '#/components/schemas/JsonRpcMessage' }, { type: 'array', maxItems: MAX_BATCH, items: { $ref: '#/components/schemas/JsonRpcMessage' } }] }),
          },
          responses: {
            200: { description: 'JSON-RPC response (or batch of responses). Tool failures, including rate limits, are results with isError: true.', content: json({ type: ['object', 'array'] }) },
            202: { description: 'Notification(s) accepted; no body' },
            400: { description: 'Parse error (-32700), invalid request (-32600), header mismatch (-32020), unsupported protocol version (-32022) or missing _meta (-32602)', content: json({ type: 'object' }) },
            401: { description: 'Invalid API key (JSON-RPC error, data.code = invalid_api_key)', content: json({ type: 'object' }) },
            403: { description: 'Origin header present but not allowed', content: json({ type: 'object' }) },
            404: { description: 'Unknown method in a 2026-07-28 request (-32601)', content: json({ type: 'object' }) },
            413: { description: 'Body larger than the cap', content: json({ type: 'object' }) },
            429: { description: 'Too many non-check MCP messages from this IP', headers: retryAfter, content: json({ type: 'object' }) },
            500: errResp('Unexpected internal error (`internal_error`); per-message failures are JSON-RPC -32603 inside a 200 response instead'),
            503: { description: 'Deployment missing its HASH_PEPPER secret (`not_configured`)', content: json({ type: 'object' }) },
          },
        },
        get: mcpNotAllowed('get'),
        delete: mcpNotAllowed('delete'),
      },
    },
  };
}
