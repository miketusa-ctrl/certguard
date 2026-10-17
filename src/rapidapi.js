// RapidAPI marketplace route /rapidapi/v1/* (shared pattern: UAParse v0.5.1 src/lib/rapidapi.js). RapidAPI's proxy adds
// X-RapidAPI-Proxy-Secret (must equal the Worker secret RAPIDAPI_PROXY_SECRET), X-RapidAPI-User and
// X-RapidAPI-Subscription. Compare is constant time (SHA-256 digests + XOR). Wrong/missing secret → uniform 401
// unauthorized; secret unset → 503. Tier is read only AFTER the secret check (unknown → BASIC). Per-minute limit per
// RapidAPI user on RAPIDAPI_BASIC_LIMITER 10/min and RAPIDAPI_PRO_LIMITER 120/min. RapidAPI checks use their own
// service-wide daily pool (q:global:rapidapi:<day>), never the free per-IP/per-key counters or the Pro pool. Monthly
// quotas are enforced by RapidAPI (hard limit). cg_/CGPR keys and the Authorization header are never read on this path.
export const RAPIDAPI_PREFIX = '/rapidapi';
export const RAPIDAPI_TIERS = ['BASIC', 'PRO'];
export const RAPIDAPI_PER_MIN = { BASIC: 10, PRO: 120 };
/** Monthly hard quotas, enforced by RapidAPI (Studio plan settings). */
export const RAPIDAPI_PER_MONTH = { BASIC: 100, PRO: 20_000 };
export const RAPIDAPI_PRICE_USD = { BASIC: 0, PRO: 7 };
export const RAPIDAPI_BINDING = { BASIC: 'RAPIDAPI_BASIC_LIMITER', PRO: 'RAPIDAPI_PRO_LIMITER' };

export function isRapidApiPath(path) { return path === RAPIDAPI_PREFIX || path.startsWith(`${RAPIDAPI_PREFIX}/`); }

/** X-RapidAPI-Subscription → tier; missing/unknown counts as BASIC (the lower limit). */
export function rapidTier(req) {
  const t = String(req.headers.get('x-rapidapi-subscription') || '').trim().toUpperCase();
  return RAPIDAPI_TIERS.includes(t) ? t : 'BASIC';
}

async function digest(s) { return new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(String(s)))); }

/** Constant-time equality over fixed-length SHA-256 digests. */
export async function safeEqual(a, b) {
  const [x, y] = await Promise.all([digest(a), digest(b)]);
  let d = 0;
  for (let i = 0; i < x.length; i++) d |= x[i] ^ y[i];
  return d === 0;
}

/** Limiter key (16 hex): hashed X-RapidAPI-User (fallback: caller's IP bucket). Never stores the raw username. */
export async function rapidUserKey(req, fallback) {
  const u = String(req.headers.get('x-rapidapi-user') || '').trim().slice(0, 128);
  return [...(await digest(u ? `u:${u}` : `ip:${fallback}`))].slice(0, 8).map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** null when allowed, else { status, code, message }. Never echoes the secret or the presented value. */
export async function rapidGate(req, env) {
  const secret = typeof env.RAPIDAPI_PROXY_SECRET === 'string' ? env.RAPIDAPI_PROXY_SECRET : '';
  if (!secret) return { status: 503, code: 'rapidapi_not_configured', message: 'The RapidAPI route is not configured yet. Use the free API at /api/v1 directly.' };
  const presented = req.headers.get('x-rapidapi-proxy-secret');
  if (!presented || !(await safeEqual(presented, secret))) {
    return { status: 401, code: 'unauthorized', message: 'Missing or invalid RapidAPI proxy secret. Subscribe on RapidAPI, or use the free public API at /api/v1.' };
  }
  return null;
}
