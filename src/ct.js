// Certificate Transparency fallback — used ONLY for targets a Worker cannot reach live (Cloudflare's own
// network). Data is INFERRED: the newest currently-valid certificate publicly logged for the name, not
// necessarily the certificate the server presents.
//
// Provider: SSLMate Cert Spotter API. Per SSLMate's terms, unauthenticated use is for evaluation only, so
// CertGuard NEVER calls it without an API key (wrangler secret CERTSPOTTER_API_KEY, sent as a Bearer token).
// Without a key the fallback is disabled and the caller reports "live check unavailable".
//
// Cost/abuse controls (all KV-backed, per environment):
//  - global hourly budget of API calls (CT_HOURLY_BUDGET, default 80 < the free plan's 100/hour);
//  - at most 2 API calls (pages) per lookup;
//  - per-host negative cache after errors (5 min) and after 429s (10 min);
//  - global circuit breaker after a 429 with exponential backoff (60 s → 120 s → … → 600 s).
//
// "Newest first": Cert Spotter returns unexpired issuances oldest-discovered first and paginates with
// `after=<issuance id>`. Issuance IDs grow with discovery time, so CertGuard keeps a small watermark table of
// (id, not_before) pairs learned from earlier responses and starts the query at an id from ~WINDOW_DAYS ago.
// That returns the most recent issuances in one page for virtually every name; if the window is empty it
// falls back to one oldest-first page.
import { b64decode } from './asn1.js';
import { parseCertificate } from './x509.js';
import { counterIncr, counterValue } from './limits.js';

const CERTSPOTTER = 'https://api.certspotter.com/v1/issuances';
export const MAX_PAGES = 2;
const PAGE_FULL = 100;          // Cert Spotter page size; a page this long may have more after it
const WINDOW_DAYS = 120;        // skip-ahead window (CA/B max validity is ≤ 200 days and shrinking)
const WM_SLACK_DAYS = 7;
const NEG_TTL_ERROR = 300;
const NEG_TTL_429 = 600;
const DAY = 86400000;

export class CtUnavailable extends Error {
  constructor(reason, message, retryAfter = null) { super(message); this.reason = reason; this.retryAfter = retryAfter; }
}

function covers(names, host) {
  return names.some((n) => {
    n = String(n).toLowerCase();
    if (n === host) return true;
    if (n.startsWith('*.')) { const s = n.slice(1); return host.endsWith(s) && !host.slice(0, -s.length).includes('.'); }
    return false;
  });
}

// ---------- watermark (issuance id ↔ time) ----------
const mem = { wm: null, wmAt: 0, wmDirty: false, wmWrittenAt: 0, breakerUntil: 0, neg: new Map() };
export function _resetCtStateForTests() { mem.wm = null; mem.wmAt = 0; mem.wmDirty = false; mem.wmWrittenAt = 0; mem.breakerUntil = 0; mem.neg.clear(); }

async function loadWatermark(kv) {
  if (mem.wm && Date.now() - mem.wmAt < 600000) return mem.wm;
  let list = [];
  try { list = JSON.parse((kv && (await kv.get('ct:wm'))) || '[]'); } catch { list = []; }
  // merge with in-memory points
  if (mem.wm) list = list.concat(mem.wm);
  mem.wm = normalizeWm(list); mem.wmAt = Date.now();
  return mem.wm;
}
function normalizeWm(list) {
  const byDay = new Map();
  for (const [id, nb] of list) {
    if (!/^\d+$/.test(String(id)) || !nb) continue;
    const day = String(nb).slice(0, 10);
    const cur = byDay.get(day);
    if (!cur || BigInt(id) < BigInt(cur[0])) byDay.set(day, [String(id), day]);
  }
  return [...byDay.values()].sort((a, b) => (a[1] < b[1] ? -1 : 1)).slice(-400);
}
export function learnWatermark(items) {
  const pts = items.filter((x) => x && x.id && x.not_before).map((x) => [String(x.id), String(x.not_before).slice(0, 10)]);
  if (!pts.length) return;
  mem.wm = normalizeWm((mem.wm || []).concat(pts)); mem.wmDirty = true;
}
/** Cursor id such that issuances discovered after (now - WINDOW_DAYS) have larger ids; null if unknown. */
export function cursorFor(wm, now) {
  const target = new Date(+now - WINDOW_DAYS * DAY).toISOString().slice(0, 10);
  const before = new Date(+now - (WINDOW_DAYS + WM_SLACK_DAYS) * DAY).toISOString().slice(0, 10);
  let maxOld = null; let minNew = null;
  for (const [id, day] of wm) {
    const v = BigInt(id);
    if (day < before) { if (maxOld === null || v > maxOld) maxOld = v; }
    if (day >= target) { if (minNew === null || v < minNew) minNew = v; }
  }
  if (maxOld === null) return null;
  const c = minNew !== null && minNew < maxOld ? minNew : maxOld;
  return c.toString();
}
async function persistWatermark(kv, ctx) {
  if (!kv || !mem.wmDirty || Date.now() - mem.wmWrittenAt < 3600000) return;
  mem.wmDirty = false; mem.wmWrittenAt = Date.now();
  const p = kv.put('ct:wm', JSON.stringify(mem.wm), { expirationTtl: 60 * 86400 }).catch(() => {});
  if (ctx && ctx.waitUntil) ctx.waitUntil(p); else await p;
}

// ---------- guards ----------
async function negGet(kv, host) {
  const m = mem.neg.get(host);
  if (m && m.until > Date.now()) return m;
  const raw = kv ? await kv.get('ctneg:' + host).catch(() => null) : null;
  if (!raw) return null;
  try { const v = JSON.parse(raw); if (v.until > Date.now()) { mem.neg.set(host, v); return v; } } catch { /* ignore */ }
  return null;
}
function negPut(kv, ctx, host, reason, ttl) {
  const v = { reason, until: Date.now() + ttl * 1000 };
  mem.neg.set(host, v);
  if (mem.neg.size > 2000) mem.neg.clear();
  if (kv) { const p = kv.put('ctneg:' + host, JSON.stringify(v), { expirationTtl: Math.max(60, ttl) }).catch(() => {}); if (ctx && ctx.waitUntil) ctx.waitUntil(p); }
}
async function breakerOpen(kv) {
  if (mem.breakerUntil > Date.now()) return mem.breakerUntil;
  const raw = kv ? await kv.get('ct:breaker').catch(() => null) : null;
  if (raw) { try { const v = JSON.parse(raw); if (v.until > Date.now()) { mem.breakerUntil = v.until; return v.until; } } catch { /* ignore */ } }
  return 0;
}
async function tripBreaker(kv, ctx) {
  let level = 0;
  try { level = (JSON.parse((kv && (await kv.get('ct:breaker:level'))) || '{}').level || 0) + 1; } catch { level = 1; }
  const secs = Math.min(600, 60 * 2 ** (level - 1));
  mem.breakerUntil = Date.now() + secs * 1000;
  if (kv) {
    const p = Promise.all([
      kv.put('ct:breaker', JSON.stringify({ until: mem.breakerUntil }), { expirationTtl: Math.max(60, secs) }),
      kv.put('ct:breaker:level', JSON.stringify({ level }), { expirationTtl: 3600 }), // backoff level decays after 1 h
    ]).catch(() => {});
    if (ctx && ctx.waitUntil) ctx.waitUntil(p); else await p;
  }
  return secs;
}

const hourKey = (now = new Date()) => 'q:ct:' + now.toISOString().slice(0, 13);

/**
 * Guarded CT lookup. Throws CtUnavailable(reason) when the fallback can't be used right now:
 *   no_api_key | ct_backoff | ct_recent_error | ct_budget_exhausted | ct_rate_limited | ct_error
 * deps: { apiKey, kv, ctx, fetchImpl, timeoutMs, now, hourlyBudget }
 */
export async function ctLookup(host, deps = {}) {
  const { apiKey, kv = null, ctx = null, fetchImpl = fetch, timeoutMs = 6000, hourlyBudget = 80 } = deps;
  const now = deps.now || new Date();
  if (!apiKey) throw new CtUnavailable('no_api_key', 'Certificate Transparency fallback is not configured (no Cert Spotter API key).');
  const until = await breakerOpen(kv);
  if (until) throw new CtUnavailable('ct_backoff', 'Certificate Transparency source is rate-limiting us; backing off.', Math.ceil((until - Date.now()) / 1000));
  const neg = await negGet(kv, host);
  if (neg) throw new CtUnavailable('ct_recent_error', `Certificate Transparency lookup for this host failed recently (${neg.reason}); not retrying yet.`, Math.ceil((neg.until - Date.now()) / 1000));

  const hk = hourKey(now);
  const deadline = Date.now() + timeoutMs;
  let calls = 0;
  const fetchPage = async (after) => {
    if ((await counterValue(kv, hk)) >= hourlyBudget) throw new CtUnavailable('ct_budget_exhausted', `Hourly Certificate Transparency budget (${hourlyBudget} lookups) is used up.`, 3600 - (Math.floor(Date.now() / 1000) % 3600));
    const left = deadline - Date.now();
    if (left < 300) throw new CtUnavailable('ct_error', 'Certificate Transparency lookup timed out.');
    await counterIncr(kv, hk, ctx, 1, { flushEvery: 1, ttl: 7200 });
    calls++;
    const u = new URL(CERTSPOTTER);
    u.searchParams.set('domain', host);
    u.searchParams.set('match_wildcards', 'true');
    for (const e of ['dns_names', 'issuer', 'cert_der']) u.searchParams.append('expand', e);
    if (after) u.searchParams.set('after', after);
    let res;
    try {
      res = await fetchImpl(u.toString(), { headers: { accept: 'application/json', authorization: `Bearer ${apiKey}`, 'user-agent': 'CertGuard/0.1 (+certificate checker)' }, signal: AbortSignal.timeout(left) });
    } catch (e) {
      negPut(kv, ctx, host, 'network error', NEG_TTL_ERROR);
      throw new CtUnavailable('ct_error', `Certificate Transparency source unreachable (${e.name || 'error'}).`, NEG_TTL_ERROR);
    }
    if (res.status === 429) {
      const secs = await tripBreaker(kv, ctx);
      negPut(kv, ctx, host, 'rate limited', NEG_TTL_429);
      throw new CtUnavailable('ct_rate_limited', 'Certificate Transparency source rate-limited the request.', secs);
    }
    if (!res.ok) {
      negPut(kv, ctx, host, `HTTP ${res.status}`, NEG_TTL_ERROR);
      throw new CtUnavailable('ct_error', `Certificate Transparency source returned HTTP ${res.status}.`, NEG_TTL_ERROR);
    }
    const text = await res.text();
    if (text.length > 3_000_000) throw new CtUnavailable('ct_error', 'Certificate Transparency response too large.');
    let batch;
    try { batch = JSON.parse(text); } catch { batch = null; }
    if (!Array.isArray(batch)) { negPut(kv, ctx, host, 'bad response', NEG_TTL_ERROR); throw new CtUnavailable('ct_error', 'Certificate Transparency source returned an unexpected response.'); }
    learnWatermark(batch);
    return batch;
  };

  const isCurrent = (x) => Array.isArray(x.dns_names) && covers(x.dns_names, host) && new Date(x.not_before) <= now && new Date(x.not_after) > now && !x.revoked;
  const wm = await loadWatermark(kv);
  const cursor = cursorFor(wm, now);
  let items = [];
  let mode;
  let truncated = false;
  if (cursor) {
    mode = 'recent_window';
    const p1 = await fetchPage(cursor);
    items = p1;
    if (p1.length >= PAGE_FULL) { const p2 = await fetchPage(p1[p1.length - 1].id); items = items.concat(p2); truncated = p2.length >= PAGE_FULL; }
    if (!items.some(isCurrent) && calls < MAX_PAGES) { mode = 'oldest_first_fallback'; const p = await fetchPage(null); items = p; truncated = p.length >= PAGE_FULL; }
  } else {
    mode = 'oldest_first';
    const p1 = await fetchPage(null);
    items = p1;
    if (p1.length >= PAGE_FULL) { const p2 = await fetchPage(p1[p1.length - 1].id); items = items.concat(p2); truncated = p2.length >= PAGE_FULL; }
  }
  await persistWatermark(kv, ctx);

  const current = items.filter(isCurrent);
  if (!current.length) return { found: false, count: 0, calls, mode };
  current.sort((a, b) => new Date(b.not_before) - new Date(a.not_before));
  const newest = current[0];
  let cert = null;
  try { if (newest.cert_der) cert = parseCertificate(b64decode(newest.cert_der)); } catch { cert = null; }
  const earliest = current.reduce((m, x) => (new Date(x.not_after) < new Date(m.not_after) ? x : m), current[0]);
  return {
    found: true, calls, mode, truncated,
    count: current.length,
    newest: { id: newest.id, notBefore: newest.not_before, notAfter: newest.not_after, issuer: newest.issuer && newest.issuer.name, dnsNames: newest.dns_names, sha256: newest.cert_sha256 },
    cert,
    earliestNotAfter: earliest.not_after,
    candidates: current.slice(0, 10).map((x) => ({ issuer: x.issuer && (x.issuer.friendly_name || x.issuer.name), issuerName: x.issuer && x.issuer.name, notBefore: x.not_before, notAfter: x.not_after, names: x.dns_names.length })),
  };
}
