// HTTP router, quotas, caching. Platform-specific transport is injected (see index.js).
import { parseTarget, TargetError, ipBucket, ipBucket48 } from './netguard.js';
import { runCheck as runEngine, VERSION, CheckResponseError } from './check.js';
import { rateLimit, counterValue, counterIncr, utcDay, lookupKey, isValidEmail, generateKey, sha256hex, hmacHex } from './limits.js';
import { indexHtml, docsHtml, privacyHtml, appJs, faviconSvg } from './ui.js';
import { handleMcp } from './mcp.js';
import { llmsTxt, openApiSpec, serverCard, registryAuthProof } from './agentdocs.js';
import { validateFleetLicense } from './fleet-license.js';
import { PRO_PRODUCT_SLUG, looksLikeProKey, proKeyIdFor } from './pro.js';
import { isRapidApiPath, rapidGate, rapidTier, rapidUserKey, RAPIDAPI_PER_MIN, RAPIDAPI_BINDING } from './rapidapi.js';

export { ipBucket };

const MAX_BODY = 16 * 1024;
// Glama connector ownership claim, served at /.well-known/glama.json. Set your own glama.ai claim token as the GLAMA_CLAIM Worker secret (or replace the placeholder, if present).
export const GLAMA_CLAIM_JSON = '{"$schema":"https://glama.ai/mcp/schemas/connector.json","claim":"<GLAMA_CLAIM_TOKEN>"}';
const MEM_CACHE_MAX = 300;
const memCache = new Map(); // key -> { body, exp, stored }

const num = (v, d) => { const n = Number(v); return Number.isFinite(n) && n >= 0 ? n : d; };
export function config(env) {
  return {
    env: env.ENVIRONMENT || 'development',
    publicLaunch: env.PUBLIC_LAUNCH === 'true',
    anonPerMin: num(env.ANON_PER_MIN, 10),
    anonDailyPerIp: num(env.ANON_DAILY_PER_IP, 200),
    anonDailyPer48: num(env.ANON_DAILY_PER_IP48, 600),
    keyIssuerDailyQuota: num(env.KEY_ISSUER_DAILY_QUOTA, 1000),
    negCacheTtl: Math.min(600, Math.max(300, num(env.NEG_CACHE_TTL_SECONDS, 600))),
    blockedCacheTtl: Math.min(600, Math.max(300, num(env.BLOCKED_CACHE_TTL_SECONDS, 300))),
    keyPerMin: num(env.KEY_PER_MIN, 60),
    keyDailyQuota: num(env.KEY_DAILY_QUOTA, 1000),
    // CertGuard Pro (Polar): its own per-license daily quota and its own service-wide pool, separate from the free caps.
    proDailyQuota: num(env.PRO_DAILY_QUOTA, 10000),
    proGlobalDailyCap: num(env.PRO_GLOBAL_DAILY_CAP, 50000),
    // RapidAPI marketplace: its own service-wide daily pool (monthly quotas are enforced by RapidAPI).
    rapidGlobalDailyCap: num(env.RAPIDAPI_GLOBAL_DAILY_CAP, 20000),
    globalDailyRequestCap: num(env.GLOBAL_DAILY_REQUEST_CAP, 20000),
    globalDailyLiveCap: num(env.GLOBAL_DAILY_LIVE_CAP, 3000),
    cacheTtl: Math.max(60, num(env.CACHE_TTL_SECONDS, 600)),
    ctCacheTtl: Math.max(60, num(env.CT_CACHE_TTL_SECONDS, 3600)),
    ctHourlyBudget: num(env.CT_HOURLY_BUDGET, 80),
    keyIssuePerIpPerDay: num(env.KEY_ISSUE_PER_IP_PER_DAY, 3),
    keyIssueGlobalPerDay: num(env.KEY_ISSUE_GLOBAL_PER_DAY, 200),
    pepper: typeof env.HASH_PEPPER === 'string' && env.HASH_PEPPER.length >= 16 ? env.HASH_PEPPER : null,
    ctApiKey: typeof env.CERTSPOTTER_API_KEY === 'string' && env.CERTSPOTTER_API_KEY.trim() ? env.CERTSPOTTER_API_KEY.trim() : null,
  };
}

class HttpError extends Error {
  constructor(status, code, message, headers = {}) { super(message); this.status = status; this.code = code; this.headers = headers; }
}

function baseHeaders(cfg, extra = {}) {
  const h = {
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
    'x-frame-options': 'DENY',
    'permissions-policy': 'interest-cohort=()',
    'strict-transport-security': 'max-age=31536000',
    ...extra,
  };
  if (!cfg.publicLaunch) h['x-robots-tag'] = 'noindex, nofollow';
  return h;
}

const CORS = {
  'access-control-allow-origin': '*',
  'access-control-expose-headers': 'x-certguard-cache, x-certguard-plan, retry-after',
};

function json(cfg, status, obj, extra = {}, { cors = true } = {}) {
  return new Response(JSON.stringify(obj, null, 2), {
    status,
    headers: baseHeaders(cfg, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...(cors ? CORS : {}), ...extra }),
  });
}
function errJson(cfg, status, code, message, extra = {}, opts) {
  return json(cfg, status, { ok: false, error: { code, message } }, extra, opts);
}

const CSP = "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";
function staticResponse(cfg, method, body, contentType, extra = {}) {
  return new Response(method === 'HEAD' ? null : body, { headers: baseHeaders(cfg, { 'content-type': contentType, 'cache-control': 'public, max-age=300', ...extra }) });
}

async function readBodyCapped(req) {
  const cl = req.headers.get('content-length');
  if (cl && Number(cl) > MAX_BODY) throw new HttpError(413, 'payload_too_large', `request body exceeds ${MAX_BODY} bytes`);
  if (!req.body) return '';
  const reader = req.body.getReader();
  const chunks = []; let total = 0;
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_BODY) { try { await reader.cancel(); } catch { /* ignore */ } throw new HttpError(413, 'payload_too_large', `request body exceeds ${MAX_BODY} bytes`); }
    chunks.push(value);
  }
  const all = new Uint8Array(total); let p = 0;
  for (const c of chunks) { all.set(c, p); p += c.byteLength; }
  return new TextDecoder().decode(all);
}

async function readJson(req) {
  const text = await readBodyCapped(req);
  if (!text.trim()) throw new HttpError(400, 'invalid_json', 'request body must be a JSON object');
  let v;
  try { v = JSON.parse(text); } catch { throw new HttpError(400, 'invalid_json', 'request body is not valid JSON'); }
  if (!v || typeof v !== 'object' || Array.isArray(v)) throw new HttpError(400, 'invalid_json', 'request body must be a JSON object');
  return v;
}

const friendly429 = (what) => `CertGuard has reached its free ${what} for today to stay within its shared budget. Please try again after 00:00 UTC — cached results for recently checked hosts may still be available.`;

// ---------- cache ----------
async function cacheGet(env, key) {
  const m = memCache.get(key);
  if (m && m.exp > Date.now()) return m;
  if (m) memCache.delete(key);
  if (!env.CERTGUARD_KV) return null;
  const raw = await env.CERTGUARD_KV.get('cache:' + key).catch(() => null);
  if (!raw) return null;
  try {
    const v = JSON.parse(raw);
    if (v.exp <= Date.now()) return null;
    memSet(key, v);
    return v;
  } catch { return null; }
}
function memSet(key, v) {
  memCache.set(key, v);
  if (memCache.size > MEM_CACHE_MAX) memCache.delete(memCache.keys().next().value);
}
function cachePut(env, ctx, key, body, ttl, status = 200) {
  const v = { body, status, stored: Date.now(), exp: Date.now() + ttl * 1000, ttl };
  memSet(key, v);
  if (env.CERTGUARD_KV) {
    const p = env.CERTGUARD_KV.put('cache:' + key, JSON.stringify(v), { expirationTtl: Math.max(60, ttl) }).catch(() => {});
    if (ctx && ctx.waitUntil) ctx.waitUntil(p);
  }
}

// Log (visible in `wrangler tail`) once per isolate when a global cap crosses 50 / 80 / 100 %.
const capWarned = new Set();
export function capWarn(name, used, cap, day) {
  if (!cap) return null;
  const pct = (used / cap) * 100;
  for (const t of [100, 80, 50]) {
    if (pct >= t) {
      const k = `${name}:${day}:${t}`;
      if (capWarned.has(k)) return null;
      capWarned.add(k);
      if (capWarned.size > 200) capWarned.delete(capWarned.values().next().value);
      const msg = `certguard: global ${name} cap at ${Math.floor(pct)}% (${used}/${cap}) for ${day} UTC — threshold ${t}%`;
      console.warn(msg);
      return msg;
    }
  }
  return null;
}
export function _resetCapWarnForTests() { capWarned.clear(); }

function requirePepper(cfg) {
  if (!cfg.pepper) throw new HttpError(503, 'not_configured', 'This deployment is missing its HASH_PEPPER secret; the API is disabled until it is set.');
}
const clientIp = (req) => req.headers.get('cf-connecting-ip') || 'unknown';

// ---------- per-isolate light limiter (MCP discovery messages only) ----------
const memLimits = new Map();
export function memLimit(key, limit, periodMs) {
  const now = Date.now();
  const e = memLimits.get(key);
  if (!e || now - e.start > periodMs) { memLimits.set(key, { start: now, n: 1 }); return true; }
  if (e.n >= limit) return false;
  e.n++;
  if (memLimits.size > 5000) memLimits.clear();
  return true;
}
export function _resetMemLimitsForTests() { memLimits.clear(); }

// ---------- key gate + check (shared by /api/v1/check and /mcp tools/call) ----------
/** The presented API key: X-API-Key (wins when both are sent) or `Authorization: Bearer <key>`; null when none. */
function extractApiKey(req) {
  const x = req.headers.get('x-api-key');
  if (x !== null) return { key: x.trim(), via: 'x-api-key' };
  // An empty Bearer token, or another scheme (e.g. Basic added by a proxy), counts as "no key" (anonymous).
  const m = /^Bearer[ \t]+(\S.*)$/i.exec(req.headers.get('authorization') || '');
  if (m) return { key: m[1].trim(), via: 'bearer' };
  return null;
}

/**
 * Key gate shared by /api/v1/check and POST /mcp (identical behaviour = auth parity). Runs before the cache, so an
 * invalid key never gets a cached answer. Never echoes the key.
 * Returns { ok:true, plan:'anonymous'|'key', rec } or { ok:false, status, code, message, headers }.
 */
export async function authenticate(req, env, cfg = config(env)) {
  try {
    requirePepper(cfg);
    const presented = extractApiKey(req);
    if (!presented) return { ok: true, plan: 'anonymous', rec: null };
    const invalid = () => new HttpError(401, 'invalid_api_key', presented.via === 'x-api-key'
      ? 'X-API-Key is not valid. Omit the header for anonymous (lower-rate) use, or get a free key via POST /api/v1/keys.'
      : 'The Bearer API key is not valid. Omit the Authorization header for anonymous (lower-rate) use, or get a free key via POST /api/v1/keys.');
    if (looksLikeProKey(presented.key)) {
      // CertGuard Pro: READ-ONLY check of lic:<key> in the shared LICENSES KV. Anything that isn't an active
      // certguard-pro grant (unknown, revoked, expired, other product, malformed, missing binding, KV error) gets the
      // same 401 as any other bad key — no reason is ever exposed.
      const lic = await validateFleetLicense(env.LICENSES, presented.key, PRO_PRODUCT_SLUG).catch(() => ({ valid: false }));
      if (!lic.valid) throw invalid();
      return { ok: true, plan: 'pro', rec: { id: await proKeyIdFor(presented.key), plan: 'pro' } };
    }
    const rec = await lookupKey(env.CERTGUARD_KV, presented.key);
    if (!rec || rec.revoked) throw invalid();
    return { ok: true, plan: 'key', rec };
  } catch (e) {
    if (e instanceof HttpError) return { ok: false, status: e.status, code: e.code, message: e.message, headers: e.headers };
    throw e;
  }
}

/** Per-minute + daily limits for an authenticated caller (unchanged order and counters since v0.1.2). */
async function applyLimits(req, env, cfg, ctx, auth) {
  const bucket = ipBucket(clientIp(req));
  const day = utcDay();
  if (auth.plan === 'rapidapi') { // already authenticated by the proxy secret; per-tier per-user per-minute limit
    const tier = auth.rec.tier;
    if (!(await rateLimit(env[RAPIDAPI_BINDING[tier]], `rapidapi-${tier.toLowerCase()}:${auth.rec.userKey}`, RAPIDAPI_PER_MIN[tier]))) {
      throw new HttpError(429, 'rate_limited', `Too many requests for your RapidAPI ${tier} plan (about ${RAPIDAPI_PER_MIN[tier]} per minute). Please wait a minute.`, { 'retry-after': '60' });
    }
    return { plan: `rapidapi-${tier.toLowerCase()}` };
  }
  if (auth.plan === 'pro') { // Pro: own per-license daily quota; no issuer quota (separate from the free pool)
    const id = auth.rec.id;
    if (!(await rateLimit(env.KEY_LIMITER, 'k:' + id, cfg.keyPerMin))) {
      throw new HttpError(429, 'rate_limited', `Per-key rate limit (${cfg.keyPerMin}/min) exceeded. Slow down and retry in a minute.`, { 'retry-after': '60' });
    }
    const usedName = `q:pro:${id}:${day}`;
    if ((await counterValue(env.CERTGUARD_KV, usedName)) >= cfg.proDailyQuota) {
      throw new HttpError(429, 'key_quota_exceeded', `Daily quota for this Pro license (${cfg.proDailyQuota} checks/day) is used up. It resets at 00:00 UTC.`, { 'retry-after': '3600' });
    }
    await counterIncr(env.CERTGUARD_KV, usedName, ctx);
    return { plan: 'pro', keyId: id };
  }
  if (auth.plan === 'key') {
    const rec = auth.rec;
    if (!(await rateLimit(env.KEY_LIMITER, 'k:' + rec.id, cfg.keyPerMin))) {
      throw new HttpError(429, 'rate_limited', `Per-key rate limit (${cfg.keyPerMin}/min) exceeded. Slow down and retry in a minute.`, { 'retry-after': '60' });
    }
    const quota = rec.dailyQuota || cfg.keyDailyQuota;
    const usedName = `q:key:${rec.id}:${day}`;
    if ((await counterValue(env.CERTGUARD_KV, usedName)) >= quota) {
      throw new HttpError(429, 'key_quota_exceeded', `Daily quota for this API key (${quota} checks/day) is used up. It resets at 00:00 UTC.`, { 'retry-after': '3600' });
    }
    // Combined quota for all keys minted from the same IP bucket (so 3 keys/day from one IP can't drain the
    // global cap). Keys minted before v0.1.2 have no issuer tag and fall back to a per-key bucket.
    const issuerName = `q:issuer:${rec.issuer || 'legacy-' + rec.id}:${day}`;
    if ((await counterValue(env.CERTGUARD_KV, issuerName)) >= cfg.keyIssuerDailyQuota) {
      throw new HttpError(429, 'issuer_quota_exceeded', `Combined daily quota for API keys issued to your network (${cfg.keyIssuerDailyQuota} checks/day) is used up. It resets at 00:00 UTC.`, { 'retry-after': '3600' });
    }
    await counterIncr(env.CERTGUARD_KV, usedName, ctx);
    await counterIncr(env.CERTGUARD_KV, issuerName, ctx);
    return { plan: 'key', keyId: rec.id };
  }
  // Anonymous: per-minute burst (rate-limit binding) + per-IP daily quota (KV). IPv6 is bucketed by /64.
  if (!(await rateLimit(env.IP_LIMITER, 'ip:' + bucket, cfg.anonPerMin))) {
    throw new HttpError(429, 'rate_limited', `Anonymous rate limit (${cfg.anonPerMin} checks/min per IP) exceeded. Retry in a minute, or use a free API key (X-API-Key) for a higher limit.`, { 'retry-after': '60' });
  }
  const ipName = `q:ipday:${(await hmacHex(cfg.pepper, 'ip:' + bucket)).slice(0, 32)}:${day}`;
  if ((await counterValue(env.CERTGUARD_KV, ipName)) >= cfg.anonDailyPerIp) {
    throw new HttpError(429, 'ip_daily_quota', `Anonymous daily quota (${cfg.anonDailyPerIp} checks/day per IP) reached. It resets at 00:00 UTC; a free API key gives a higher quota.`, { 'retry-after': '3600' });
  }
  // Coarser IPv6 /48 aggregate (one site / customer allocation), so /64 rotation inside it doesn't multiply the quota.
  const b48 = ipBucket48(clientIp(req));
  let n48 = null;
  if (b48) {
    n48 = `q:ip48day:${(await hmacHex(cfg.pepper, 'ip48:' + b48)).slice(0, 32)}:${day}`;
    if ((await counterValue(env.CERTGUARD_KV, n48)) >= cfg.anonDailyPer48) {
      throw new HttpError(429, 'ip_daily_quota', `Anonymous daily quota for your IPv6 network (${cfg.anonDailyPer48} checks/day per /48) reached. It resets at 00:00 UTC; a free API key gives a higher quota.`, { 'retry-after': '3600' });
    }
  }
  // flush by count only, so one-off visitors cost no KV writes
  await counterIncr(env.CERTGUARD_KV, ipName, ctx, 1, { flushEvery: 10, maxAgeMs: Infinity, ttl: 2 * 86400 });
  if (n48) await counterIncr(env.CERTGUARD_KV, n48, ctx, 1, { flushEvery: 10, maxAgeMs: Infinity, ttl: 2 * 86400 });
  return { plan: 'anonymous' };
}

/**
 * One check with every per-minute / daily / global limit and the result cache applied exactly like /api/v1/check.
 * Used by the REST route and by MCP tools/call (one tools/call = one check against the same counters).
 * `auth` comes from authenticate(). Returns { status, body, headers } — the exact JSON body and extra headers the
 * REST route sends. Throws only on unexpected errors (→ 500 internal_error).
 */
export async function runCheck({ req, env, ctx, cfg = config(env), deps, auth, host, port }) {
  try {
    return await checkInner(req, env, ctx, cfg, deps, auth, { host, port });
  } catch (e) {
    if (e instanceof HttpError) return { status: e.status, body: { ok: false, error: { code: e.code, message: e.message } }, headers: e.headers || {} };
    if (e instanceof TargetError) return { status: e.status, body: { ok: false, error: { code: e.code, message: e.message } }, headers: {} };
    throw e;
  }
}

async function checkInner(req, env, ctx, cfg, deps, authIn, params) {
  requirePepper(cfg);
  const auth = await applyLimits(req, env, cfg, ctx, authIn);
  const kv = env.CERTGUARD_KV;
  const day = utcDay();
  const pro = auth.plan === 'pro';
  const rapid = auth.plan.startsWith('rapidapi');
  const paid = pro || rapid;
  // Pro and RapidAPI checks use their own service-wide pools, so free traffic can't exhaust them and they can't
  // exhaust the free caps.
  const reqCounter = pro ? `q:global:pro:${day}` : rapid ? `q:global:rapidapi:${day}` : `q:global:req:${day}`;
  const reqCap = pro ? cfg.proGlobalDailyCap : rapid ? cfg.rapidGlobalDailyCap : cfg.globalDailyRequestCap;
  const target = parseTarget(params.host, params.port); // 4xx here are NOT counted toward the global cap

  const ckey = `v2:${cfg.env}:${target.host}:${target.port}`;
  const cached = await cacheGet(env, ckey);
  const extra = { 'x-certguard-plan': auth.plan };
  if (cached) { // cache hits are NOT counted toward the global caps
    const body = JSON.parse(cached.body);
    const cacheInfo = { hit: true, ageSeconds: Math.round((Date.now() - cached.stored) / 1000), ttlSeconds: cached.ttl };
    const status = cached.status || 200;
    if (status === 200 || body.status === 'live_unavailable') body.cache = cacheInfo;
    return { status, body, headers: { ...extra, 'x-certguard-cache': 'HIT' } };
  }
  // Global caps apply only to uncached work; cached results stay available after a cap is reached.
  const reqUsed = await counterValue(kv, reqCounter);
  capWarn(pro ? 'pro-request' : rapid ? 'rapidapi-request' : 'request', reqUsed, reqCap, day);
  if (reqUsed >= reqCap) {
    throw new HttpError(429, 'daily_cap_reached', friendly429('request allowance'), { 'retry-after': '3600' });
  }
  // The live-check cap is checked and counted only when runCheck is about to open a real outbound connection
  // — not for Cloudflare-network targets (422) or DNS-blocked targets (403), which open no socket.
  const liveCounter = `q:global:live:${day}`;
  const beforeConnect = paid ? undefined : async () => { // Pro/RapidAPI live checks count in their own pool above
    const used = await counterValue(kv, liveCounter);
    capWarn('live-check', used, cfg.globalDailyLiveCap, day);
    if (used >= cfg.globalDailyLiveCap) throw new HttpError(429, 'daily_cap_reached', friendly429('live-check allowance'), { 'retry-after': '3600' });
    await counterIncr(kv, liveCounter, ctx);
  };
  try {
    const result = await runEngine(target, { ...deps, kv, ctx, ctApiKey: cfg.ctApiKey, ctHourlyBudget: cfg.ctHourlyBudget, beforeConnect });
    await counterIncr(kv, reqCounter, ctx);
    const ttl = result.source.live ? cfg.cacheTtl : cfg.ctCacheTtl;
    cachePut(env, ctx, ckey, JSON.stringify(result), ttl);
    result.cache = { hit: false, ageSeconds: 0, ttlSeconds: ttl };
    return { status: 200, body: result, headers: { ...extra, 'x-certguard-cache': 'MISS' } };
  } catch (e) {
    if (e instanceof CheckResponseError) {
      if (e.status >= 500) { // real work was done; check_failed / CT-unavailable are never cached
        await counterIncr(kv, reqCounter, ctx);
        return { status: e.status, body: e.body, headers: { ...extra, ...e.headers, 'x-certguard-cache': 'BYPASS' } };
      }
      if (e.status === 422 && e.negCacheable && e.body && e.body.status === 'live_unavailable') { // Only Cloudflare-IP-list 422s
        cachePut(env, ctx, ckey, JSON.stringify(e.body), cfg.negCacheTtl, 422);
        e.body.cache = { hit: false, ageSeconds: 0, ttlSeconds: cfg.negCacheTtl };
        return { status: 422, body: e.body, headers: { ...extra, ...e.headers, 'x-certguard-cache': 'MISS' } };
      }
      return { status: e.status, body: e.body, headers: { ...extra, ...e.headers, 'x-certguard-cache': 'BYPASS' } };
    }
    if (e instanceof TargetError && e.status === 403) { // DNS-resolved-to-private (blocked) → negative-cache per host
      cachePut(env, ctx, ckey, JSON.stringify({ ok: false, error: { code: e.code, message: e.message } }), cfg.blockedCacheTtl, 403);
      return { status: 403, body: { ok: false, error: { code: e.code, message: e.message } }, headers: { ...extra, 'x-certguard-cache': 'MISS' } };
    }
    if (!(e instanceof TargetError) || e.status >= 500) await counterIncr(kv, reqCounter, ctx);
    throw e;
  }
}

async function handleCheck(req, env, ctx, cfg, deps, params) {
  const auth = await authenticate(req, env, cfg);
  if (!auth.ok) throw new HttpError(auth.status, auth.code, auth.message, auth.headers);
  const r = await runCheck({ req, env, ctx, cfg, deps, auth, host: params.host, port: params.port });
  return json(cfg, r.status, r.body, r.headers);
}

async function handleKeys(req, env, ctx, cfg) {
  const kv = env.CERTGUARD_KV;
  if (!kv) throw new HttpError(503, 'unavailable', 'key issuance is not configured');
  requirePepper(cfg);
  // No CORS here. Also refuse cross-site form posts: require JSON and same-origin (or no) Origin.
  const origin = req.headers.get('origin');
  if (origin && origin !== new URL(req.url).origin) throw new HttpError(403, 'cross_origin_forbidden', 'API keys can only be requested from this site or directly (e.g. curl), not from other websites.');
  if (!/^application\/json\b/i.test(req.headers.get('content-type') || '')) throw new HttpError(415, 'unsupported_media_type', 'send the request body as application/json');
  const bucket = ipBucket(clientIp(req));
  if (!(await rateLimit(env.IP_LIMITER, 'keys:' + bucket, cfg.anonPerMin))) throw new HttpError(429, 'rate_limited', 'Too many requests. Retry in a minute.', { 'retry-after': '60' });
  const body = await readJson(req);
  let email = null;
  if (body.email !== undefined && body.email !== null && body.email !== '') {
    email = typeof body.email === 'string' ? body.email.trim() : '';
    if (!isValidEmail(email)) throw new HttpError(400, 'invalid_email', '"email" is optional, but if given it must be a valid address');
  }
  const day = utcDay();
  const ipName = `q:keyissue:${(await hmacHex(cfg.pepper, 'ip:' + bucket)).slice(0, 32)}:${day}`;
  const gName = `q:keyissue:global:${day}`;
  const [ipCount, gCount] = await Promise.all([kv.get(ipName), kv.get(gName)]);
  const ipN = Number(ipCount || 0); const gN = Number(gCount || 0);
  if (ipN >= cfg.keyIssuePerIpPerDay) throw new HttpError(429, 'key_issue_limit', `At most ${cfg.keyIssuePerIpPerDay} keys per IP (IPv6: per /64) per day.`, { 'retry-after': '3600' });
  if (gN >= cfg.keyIssueGlobalPerDay) throw new HttpError(429, 'daily_cap_reached', friendly429('key-issuance allowance'), { 'retry-after': '3600' });
  // Reserve the quota BEFORE minting (KV has no atomic increment; this narrows, but cannot close, the race
  // window for parallel bursts — see README "Known limitations").
  await Promise.all([
    kv.put(ipName, String(ipN + 1), { expirationTtl: 2 * 86400 }),
    kv.put(gName, String(gN + 1), { expirationTtl: 2 * 86400 }),
  ]);
  const apiKey = generateKey();
  const keyHash = await sha256hex(apiKey);
  const id = keyHash.slice(0, 16);
  // Email is unverified contact info only: no uniqueness, no lookup index (no squatting / enumeration).
  const rec = { id, created: new Date().toISOString(), plan: 'free', dailyQuota: cfg.keyDailyQuota, issuer: (await hmacHex(cfg.pepper, 'issuer:' + bucket)).slice(0, 32) };
  if (email) rec.contactHmac = await hmacHex(cfg.pepper, 'email:' + email.toLowerCase());
  await kv.put('key:' + keyHash, JSON.stringify(rec));
  return json(cfg, 201, {
    ok: true, apiKey, keyId: id, plan: 'free', dailyQuota: cfg.keyDailyQuota, perMinute: cfg.keyPerMin,
    note: 'Store this key now — it is shown only once (we keep only a hash). Send it as the X-API-Key header.',
  }, {}, { cors: false });
}

async function handleUsage(req, env, cfg) {
  const presented = extractApiKey(req);
  if (!presented || !presented.key) throw new HttpError(401, 'missing_api_key', 'send your key in the X-API-Key header');
  if (looksLikeProKey(presented.key)) {
    const auth = await authenticate(req, env, cfg);
    if (!auth.ok) throw new HttpError(401, 'invalid_api_key', 'X-API-Key is not valid');
    const used = await counterValue(env.CERTGUARD_KV, `q:pro:${auth.rec.id}:${utcDay()}`);
    return json(cfg, 200, { ok: true, plan: 'pro', dailyQuota: cfg.proDailyQuota, usedToday: used, remainingToday: Math.max(0, cfg.proDailyQuota - used), perMinute: cfg.keyPerMin, resetsAt: utcDay(new Date(Date.now() + 86400000)) + 'T00:00:00Z', note: 'usage counts are approximate (batched counters)' });
  }
  const rec = await lookupKey(env.CERTGUARD_KV, presented.key);
  if (!rec) throw new HttpError(401, 'invalid_api_key', 'X-API-Key is not valid');
  const used = await counterValue(env.CERTGUARD_KV, `q:key:${rec.id}:${utcDay()}`);
  const quota = rec.dailyQuota || cfg.keyDailyQuota;
  return json(cfg, 200, { ok: true, keyId: rec.id, plan: rec.plan, dailyQuota: quota, usedToday: used, remainingToday: Math.max(0, quota - used), perMinute: cfg.keyPerMin, resetsAt: utcDay(new Date(Date.now() + 86400000)) + 'T00:00:00Z', note: 'usage counts are approximate (batched counters)' });
}

// ---------- RapidAPI marketplace (/rapidapi/v1/*) ----------
async function handleRapidApi(req, env, ctx, cfg, deps, url, path, method) {
  const g = await rapidGate(req, env); // secret first: nothing else (tier, body, limits) is looked at before this
  if (g) throw new HttpError(g.status, g.code, g.message);
  const tier = rapidTier(req);
  const plan = { 'x-certguard-plan': `rapidapi-${tier.toLowerCase()}` };
  if (path === '/rapidapi/v1/health') {
    if (method !== 'GET' && method !== 'HEAD') throw new HttpError(405, 'method_not_allowed', 'use GET', { allow: 'GET, HEAD' });
    return json(cfg, 200, { ok: true, service: 'certguard', version: VERSION, plan: 'rapidapi', tier }, plan, { cors: false });
  }
  if (path === '/rapidapi/v1/check') {
    if (method !== 'GET' && method !== 'POST') throw new HttpError(405, 'method_not_allowed', 'use GET or POST', { allow: 'GET, POST' });
    requirePepper(cfg);
    let host, port;
    if (method === 'GET') { host = url.searchParams.get('host'); port = url.searchParams.get('port'); }
    else { const b = await readJson(req); host = b.host; port = b.port; }
    const auth = { ok: true, plan: 'rapidapi', rec: { tier, userKey: await rapidUserKey(req, ipBucket(clientIp(req))) } };
    const r = await runCheck({ req, env, ctx, cfg, deps, auth, host, port });
    return json(cfg, r.status, r.body, { ...r.headers, ...plan }, { cors: false });
  }
  throw new HttpError(404, 'not_found', 'Unknown RapidAPI endpoint. Use /rapidapi/v1/check or /rapidapi/v1/health.');
}

function sitemap(origin) {
  return `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n  <url><loc>${origin}/</loc><changefreq>weekly</changefreq><priority>1.0</priority></url>\n  <url><loc>${origin}/docs</loc><changefreq>monthly</changefreq><priority>0.6</priority></url>\n  <url><loc>${origin}/privacy</loc><changefreq>yearly</changefreq><priority>0.2</priority></url>\n</urlset>\n`;
}

// Route table: path → allowed methods. Anything else on a known path → 405 with Allow.
const ROUTES = {
  '/': ['GET', 'HEAD'],
  '/docs': ['GET', 'HEAD'],
  '/privacy': ['GET', 'HEAD'],
  '/app.js': ['GET', 'HEAD'],
  '/health': ['GET', 'HEAD'],
  '/robots.txt': ['GET', 'HEAD'],
  '/sitemap.xml': ['GET', 'HEAD'],
  '/api/v1/check': ['GET', 'POST', 'OPTIONS'],
  '/api/v1/keys': ['POST'],
  '/api/v1/usage': ['GET', 'OPTIONS'],
  '/favicon.svg': ['GET', 'HEAD'],
  '/llms.txt': ['GET', 'HEAD', 'OPTIONS'],
  '/openapi.json': ['GET', 'HEAD', 'OPTIONS'],
  '/.well-known/mcp/server-card.json': ['GET', 'HEAD', 'OPTIONS'],
  '/.well-known/mcp-registry-auth': ['GET', 'HEAD'],
  '/.well-known/glama.json': ['GET', 'HEAD'],
};
// /mcp is handled by handleMcp (POST + OPTIONS; GET/DELETE/other → 405 with Allow: POST, OPTIONS).
export const ROUTE_TABLE = ROUTES;

export function createApp(deps) {
  return {
    async fetch(req, env, ctx) {
      const cfg = config(env);
      const url = new URL(req.url);
      const path = url.pathname.replace(/\/+$/, '') || '/';
      const method = req.method;
      try {
        if (isRapidApiPath(path)) return await handleRapidApi(req, env, ctx, cfg, deps, url, path, method);
        if (path === '/mcp') {
          // v0.2.0: remote MCP server (Streamable HTTP, stateless, JSON responses). Same key gate + limits as /api/v1/check.
          return await handleMcp(req, env, ctx, {
            authenticate: (r, e) => authenticate(r, e, cfg),
            runCheck: ({ host, port, auth }) => runCheck({ req, env, ctx, cfg, deps, auth, host, port }),
            ipBucket: ipBucket(clientIp(req)), memLimit, origin: url.origin, security: baseHeaders(cfg),
            allowedOrigins: env.MCP_ALLOWED_ORIGINS, limits: cfg,
          });
        }
        const allowed = ROUTES[path];
        if (!allowed) {
          if (path.startsWith('/api/')) throw new HttpError(404, 'not_found', 'unknown endpoint; see /docs');
          return new Response(method === 'HEAD' ? null : 'Not found', { status: 404, headers: baseHeaders(cfg, { 'content-type': 'text/plain; charset=utf-8' }) });
        }
        if (!allowed.includes(method)) {
          throw new HttpError(405, 'method_not_allowed', `use ${allowed.join(', ')}`, { allow: allowed.join(', ') });
        }
        if (method === 'OPTIONS') { // CORS preflight only for /check and /usage (never /keys)
          return new Response(null, { status: 204, headers: baseHeaders(cfg, {
            'access-control-allow-origin': '*', 'access-control-allow-methods': allowed.join(', '),
            'access-control-allow-headers': 'content-type, x-api-key, authorization', 'access-control-max-age': '86400' }) });
        }
        switch (path) {
          case '/': return staticResponse(cfg, method, indexHtml(cfg, url.origin), 'text/html; charset=utf-8', { 'content-security-policy': CSP });
          case '/docs': return staticResponse(cfg, method, docsHtml(cfg, url.origin), 'text/html; charset=utf-8', { 'content-security-policy': CSP });
          case '/privacy': return staticResponse(cfg, method, privacyHtml(cfg), 'text/html; charset=utf-8', { 'content-security-policy': CSP });
          case '/app.js': return staticResponse(cfg, method, appJs, 'application/javascript; charset=utf-8');
          case '/robots.txt': return staticResponse(cfg, method, cfg.publicLaunch
            ? `User-agent: *\nDisallow: /api/\nSitemap: ${url.origin}/sitemap.xml\n`
            : 'User-agent: *\nDisallow: /\n', 'text/plain; charset=utf-8');
          case '/sitemap.xml': return staticResponse(cfg, method, sitemap(url.origin), 'application/xml; charset=utf-8');
          case '/favicon.svg': return staticResponse(cfg, method, faviconSvg, 'image/svg+xml', { 'cache-control': 'public, max-age=86400' });
          // v0.2.0: agent discovery documents (generated from code constants + config, so they can't drift)
          case '/llms.txt': return staticResponse(cfg, method, llmsTxt(url.origin, cfg), 'text/plain; charset=utf-8', { 'cache-control': 'public, max-age=3600', ...CORS });
          case '/openapi.json': return staticResponse(cfg, method, JSON.stringify(openApiSpec(url.origin, cfg), null, 2), 'application/json; charset=utf-8', { 'cache-control': 'public, max-age=3600', ...CORS });
          case '/.well-known/mcp/server-card.json': return staticResponse(cfg, method, JSON.stringify(serverCard(url.origin), null, 2), 'application/json; charset=utf-8', { 'cache-control': 'public, max-age=3600', ...CORS });
          case '/.well-known/glama.json': return staticResponse(cfg, method, GLAMA_CLAIM_JSON, 'application/json', { 'cache-control': 'public, max-age=3600' });
          case '/.well-known/mcp-registry-auth': { // Official MCP Registry HTTP-namespace proof: PUBLIC key record only; 404 unless well-formed
            const proof = registryAuthProof(env);
            if (proof) return staticResponse(cfg, method, proof + '\n', 'text/plain; charset=utf-8', { 'cache-control': 'no-store' });
            return new Response(method === 'HEAD' ? null : 'Not found', { status: 404, headers: baseHeaders(cfg, { 'content-type': 'text/plain; charset=utf-8' }) });
          }
          case '/health': {
            const r = json(cfg, 200, { ok: true, service: 'certguard', version: VERSION, environment: cfg.env, time: new Date().toISOString(),
              kv: !!env.CERTGUARD_KV, licenses: !!env.LICENSES, rateLimiters: { ip: !!env.IP_LIMITER, key: !!env.KEY_LIMITER },
              secrets: { hashPepper: !!cfg.pepper, certSpotterKey: !!cfg.ctApiKey }, ctFallback: cfg.ctApiKey ? 'enabled' : 'disabled (no API key)' });
            return method === 'HEAD' ? new Response(null, { status: 200, headers: r.headers }) : r;
          }
          case '/api/v1/check':
            if (method === 'GET') return await handleCheck(req, env, ctx, cfg, deps, { host: url.searchParams.get('host'), port: url.searchParams.get('port') });
            { const body = await readJson(req); return await handleCheck(req, env, ctx, cfg, deps, { host: body.host, port: body.port }); }
          case '/api/v1/keys': return await handleKeys(req, env, ctx, cfg);
          case '/api/v1/usage': return await handleUsage(req, env, cfg);
        }
        throw new HttpError(404, 'not_found', 'unknown endpoint');
      } catch (e) {
        const opts = { cors: path !== '/api/v1/keys' };
        if (e instanceof HttpError) return errJson(cfg, e.status, e.code, e.message, e.headers, opts);
        if (e instanceof TargetError) return errJson(cfg, e.status, e.code, e.message, {}, opts);
        return errJson(cfg, 500, 'internal_error', 'unexpected error while checking the certificate', {}, opts);
      }
    },
  };
}

export function _clearMemCache() { memCache.clear(); }
