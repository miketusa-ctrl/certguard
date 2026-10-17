// Static UI: single-page checker, API docs, and client script (served from /app.js so the CSP can forbid inline script).
import { VERSION } from './check.js';
import { mcpClientConfig } from './agentdocs.js';
import { PRO_CHECKOUT_URL, PRO_PORTAL_URL, PRO_PRICE_USD, PRO_KEY_PREFIX } from './pro.js';

export const CONTACT_EMAIL = 'digitalpromohub.support@gmail.com';
const ext = (href, text) => `<a href="${href}" target="_blank" rel="noopener noreferrer">${text}</a>`;
const fmtN = (n) => Number(n).toLocaleString('en-US');
const footLinks = `<p class="mut" style="font-size:13px"><a href="/docs">API docs</a> · <a href="/#pro">CertGuard Pro</a> · <a href="/privacy">Privacy</a> · Contact: <a href="mailto:${CONTACT_EMAIL}">${CONTACT_EMAIL}</a></p>`;

function proSection(cfg) {
  return `<section id="pro" class="card"><h2 style="font-size:18px;margin:0 0 6px">CertGuard Pro — $${PRO_PRICE_USD}/month</h2>
<p>For scripts, monitoring jobs and AI agents that check many certificates: ${fmtN(cfg.proDailyQuota)} checks per day per license (the free key gives ${fmtN(cfg.keyDailyQuota)}), on a daily allowance kept separate from the free service, so busy free days don&#39;t block you. Same API and MCP server; send the license key (<code>${PRO_KEY_PREFIX}-…</code>) as <code>X-API-Key</code> or <code>Authorization: Bearer</code>. Cancel any time.</p>
<p>${ext(PRO_CHECKOUT_URL, '<b>Get CertGuard Pro</b>')} · ${ext(PRO_PORTAL_URL, 'Manage or cancel')}</p>
<p class="mut" style="font-size:13px">Payments are handled by Polar (merchant of record); see <a href="/privacy">Privacy</a>. Pro doesn&#39;t change what is checked: revocation is still not checked, and Cloudflare-hosted sites still can&#39;t be checked live.</p></section>`;
}

const escHtml = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

export const faviconSvg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="14" fill="#0f172a"/><path d="M32 10l18 7v13c0 12-8 20-18 24-10-4-18-12-18-24V17z" fill="#38bdf8"/><path d="M24 32l6 6 11-12" stroke="#0f172a" stroke-width="5" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>';

const STYLE = `
:root{--bg:#0f172a;--card:#111c33;--fg:#e2e8f0;--mut:#94a3b8;--ok:#22c55e;--warn:#f59e0b;--bad:#ef4444;--acc:#38bdf8;--line:#1e2a44}
*{box-sizing:border-box}body{margin:0;font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--fg)}
main{max-width:920px;margin:0 auto;padding:28px 18px 60px}h1{margin:0 0 4px;font-size:28px}h1 span{color:var(--acc)}
p.sub{margin:0 0 22px;color:var(--mut)}a{color:var(--acc)}
form{display:flex;gap:8px;flex-wrap:wrap;background:var(--card);padding:14px;border-radius:12px;border:1px solid var(--line)}
input,select,button{font:inherit;border-radius:8px;border:1px solid #334155;background:#0b1325;color:var(--fg);padding:10px 12px}
input{flex:1 1 320px}button{background:var(--acc);color:#04111f;border:0;font-weight:600;cursor:pointer;padding:10px 18px}button:disabled{opacity:.6}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px 18px;margin-top:16px}
.head{display:flex;gap:16px;align-items:center}.grade{font-size:40px;font-weight:800;width:72px;height:72px;border-radius:14px;display:flex;align-items:center;justify-content:center;flex:none}
.gA{background:#14532d;color:#86efac}.gB{background:#3f3f12;color:#fde047}.gC{background:#4a2a0a;color:#fdba74}.gF{background:#4c1010;color:#fca5a5}
.badge{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;font-weight:600;margin-left:6px;vertical-align:middle}
.b-ok{background:#14532d;color:#86efac}.b-warn{background:#4a3a0a;color:#fde68a}.b-bad{background:#4c1010;color:#fca5a5}.b-info{background:#0c3550;color:#7dd3fc}
table{width:100%;border-collapse:collapse;font-size:14px}td,th{text-align:left;padding:6px 8px;border-top:1px solid var(--line);vertical-align:top}th{color:var(--mut);font-weight:500;width:34%}
.chain td{font-size:13px}.mut{color:var(--mut)}code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px}
pre{background:#0b1325;padding:12px;border-radius:8px;overflow:auto;max-height:420px;border:1px solid var(--line)}
ul.issues{margin:6px 0 0;padding-left:18px}.err{color:#fca5a5}footer{margin-top:30px;color:var(--mut);font-size:13px}
details summary{cursor:pointer;color:var(--mut)}
#agents h2{font-size:18px;margin:0 0 6px}#agents pre{max-height:none}
@media (max-width:560px){#mcp-config{white-space:pre-wrap;word-break:break-all}}
`;

export function indexHtml(cfg, origin = '') {
  const mcpUrl = `${origin}/mcp`;
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CertGuard — free SSL/TLS certificate checker</title>
<link rel="canonical" href="/">
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<link rel="alternate" type="text/plain" href="/llms.txt" title="llms.txt">
<link rel="service-desc" type="application/json" href="/openapi.json" title="OpenAPI 3.1">
<meta name="description" content="Check any site's SSL/TLS certificate: expiry, chain, trust, hostname match, TLS version and key — free, with a JSON API.">
${cfg.publicLaunch ? '' : '<meta name="robots" content="noindex,nofollow">'}
<style>${STYLE}</style></head><body><main>
<h1>Cert<span>Guard</span></h1>
<p class="sub">Free SSL/TLS certificate checker — expiry, chain &amp; trust, hostname match, TLS version, key and signature. <a href="/docs">JSON API</a></p>
<form id="f" autocomplete="off">
  <input id="host" name="host" placeholder="example.com" maxlength="300" required aria-label="Hostname" spellcheck="false" autocapitalize="off">
  <select id="port" name="port" aria-label="Port"><option>443</option><option>8443</option><option>465</option><option>993</option><option>995</option></select>
  <button id="go" type="submit">Check</button>
</form>
<p class="mut" id="nocheck" style="font-size:13px;margin:10px 2px 0">What we don&#39;t check: sites hosted behind Cloudflare (a large share of the web) can&#39;t be checked live — they show &ldquo;live check unavailable&rdquo; and get no grade; certificate revocation (OCSP/CRL) — a revoked certificate can still get a passing grade here; whether the server also accepts old TLS 1.0/1.1; and full cipher-suite enumeration.</p>
<div id="out"></div>
<section id="agents" class="card"><h2>For AI agents (MCP)</h2>
<p>CertGuard is also a remote <a href="https://modelcontextprotocol.io/" target="_blank" rel="noopener noreferrer">Model Context Protocol</a> (MCP) server with one read-only tool, <code>check_certificate</code>. Most MCP clients accept this config; some use a different format (for example, VS Code uses a <code>servers</code> key). Clients with a settings screen just need the URL <code>${escHtml(mcpUrl)}</code>.</p>
<pre><code id="mcp-config">${escHtml(JSON.stringify(mcpClientConfig(origin), null, 2))}</code></pre>
<p class="mut" style="font-size:13px">Same limits and optional free API key as the JSON API (send it as <code>X-API-Key</code> or <code>Authorization: Bearer</code>). Machine-readable docs: <a href="/llms.txt">llms.txt</a> · <a href="/openapi.json">OpenAPI 3.1 spec</a> · <a href="/docs">API docs</a></p></section>
${proSection(cfg)}
${footLinks}
<footer>CertGuard v${VERSION} · Results come from a real TLS handshake run from Cloudflare's edge. Sites hosted on Cloudflare's own network can't be reached that way; for them CertGuard says "live check unavailable" (or, where a Certificate Transparency fallback is enabled, shows an estimate clearly labelled "from CT logs — not live"). Successful live results are cached for up to 10 minutes (CT estimates up to 60 minutes; &ldquo;live check unavailable&rdquo; answers 10 minutes; blocked targets 5 minutes); failed checks are never cached. We don't store the hosts you check beyond that cache.</footer>
</main><script src="/app.js"></script></body></html>`;
}

export function docsHtml(cfg, origin) {
  const o = origin;
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CertGuard API docs</title>${cfg.publicLaunch ? '' : '<meta name="robots" content="noindex,nofollow">'}<style>${STYLE}</style></head><body><main>
<h1>Cert<span>Guard</span> API</h1><p class="sub"><a href="/">← checker</a></p>
<div class="card"><h3>GET /api/v1/check</h3>
<pre>curl '${o}/api/v1/check?host=example.com'
curl '${o}/api/v1/check?host=mail.example.com&amp;port=993'</pre>
<p>Parameters: <code>host</code> (hostname, IP, or https:// URL — required), <code>port</code> (443 default; allowed: 443, 8443, 465, 993, 995).</p>
<h3>POST /api/v1/check</h3>
<pre>curl -X POST '${o}/api/v1/check' -H 'content-type: application/json' -d '{"host":"example.com","port":443}'</pre>
<p>JSON body, max 16 KB (larger → <code>413</code>).</p></div>
<div class="card"><h3>Response (abridged)</h3><pre>{
  "ok": true, "status": "checked", "host": "example.com", "port": 443,
  "revocation_checked": false,
  "source": { "method": "live_tls_handshake" | "certificate_transparency", "live": true, ... },
  "grade": "A", "summary": "...",
  "expiry": { "notBefore", "notAfter", "daysRemaining", "status": "ok|warning|critical|expired|not_yet_valid" },
  "certificate": { "subject", "issuer", "sans", "key": {"type","bits","curve"}, "signatureAlgorithm", "sha256Fingerprint", ... },
  "hostname": { "matches": true, "matchedName": "*.example.com" },
  "tls": { "version": "TLS 1.3", "cipherSuite", "keyExchangeGroup", "alpn", "ocspStapled" },
  "chain": { "complete": true, "trusted": true, "trustAnchor", "certificates": [ ... ] },
  "issues": [ { "severity", "code", "message" } ],
  "notChecked": [ "revocation (OCSP/CRL status)", ... ],
  "cache": { "hit": false, "ttlSeconds": 600 }
}

// failed live check (HTTP 502) — never graded, never cached
{ "ok": false, "status": "check_failed", "grade": null, "revocation_checked": false,
  "error": { "code": "check_failed", "reason": "connect_timeout", "message": "..." },
  "source": { "attempts": [ { "offered": "TLS 1.3+1.2", "result": "connect_timeout", ... } ] } }</pre>
<p>Status thresholds: <code>warning</code> &lt; 30 days, <code>critical</code> &lt; 7 days. Grades: A (good), B (expires &lt;30d or no TLS 1.3), C (expires &lt;7d, weak key, TLS &lt;1.2), F (expired or not yet valid, wrong host, untrusted/self-signed, incomplete chain, expired or SHA-1/MD5-signed intermediate, <code>issuer_not_ca</code> — an issuing certificate that isn&#39;t a CA or lacks keyCertSign, <code>path_len_exceeded</code> — a CA pathLen constraint violated). No grade (<code>null</code>) for <code>check_failed</code> and <code>live_unavailable</code>.</p>
<p>Every result carries <code>"revocation_checked": false</code>. Grades and summaries describe expiry, chain and hostname only.</p>
<p><b>Failed checks get no grade.</b> If the live handshake can't complete (port closed/filtered, timeout, server rejects every cipher we offer, oversized certificate message, not TLS…), the API returns <code>502</code> with <code>"status": "check_failed"</code>, <code>"grade": null</code> and the <code>attempts</code> made. These are never cached.</p>
<p><b>Cloudflare-hosted sites.</b> Cloudflare Workers cannot open TCP sockets to Cloudflare's own IP ranges. For those hosts — and only those — the API returns <code>"status": "live_unavailable"</code>, <code>"grade": null</code> (HTTP 422, or 503 if temporary). When a Certificate Transparency fallback is enabled on the deployment (it is not, currently), for hosts on Cloudflare&#39;s published IP list it instead returns the newest certificate logged in public CT logs with <code>source.method = "certificate_transparency"</code>, <code>source.live = false</code> and <code>gradeEstimated: true</code>: inferred, not observed. If the Workers runtime refuses the socket to an address that is <i>not</i> on Cloudflare&#39;s published IP list, the reason is <code>socket_blocked</code> (platform restriction or transient runtime error); that answer gets no grade, never uses CT and is never cached, so a retry re-checks.</p>
<p class="mut">What we don&#39;t check: sites hosted behind Cloudflare (a large share of the web) can&#39;t be checked live; certificate revocation (OCSP/CRL) — a revoked certificate can still get a passing grade here; whether the server also accepts old TLS 1.0/1.1; and full cipher-suite enumeration.</p></div>
<div class="card"><h3>Limits &amp; free API keys</h3>
<p>Anonymous: ${cfg.anonPerMin} checks/minute per IP. With a free key (<code>X-API-Key</code> header): ${cfg.keyPerMin}/minute and ${cfg.keyDailyQuota}/day. With a <a href="/#pro">CertGuard Pro</a> license ($${PRO_PRICE_USD}/month, key <code>${PRO_KEY_PREFIX}-…</code>): ${cfg.keyPerMin}/minute and ${fmtN(cfg.proDailyQuota)}/day on a separate allowance.</p>
<pre>curl -X POST '${o}/api/v1/keys' -H 'content-type: application/json' -d '{"email":"you@example.com"}'
curl -H 'X-API-Key: cg_...' '${o}/api/v1/check?host=example.com'
curl -H 'X-API-Key: cg_...' '${o}/api/v1/usage'</pre>
<p>Anonymous use is also capped at ${cfg.anonDailyPerIp} checks/day per IP (IPv6: per /64, and ${cfg.anonDailyPer48}/day per /48). All keys issued to the same IP (or IPv6 /64) share a combined ${cfg.keyIssuerDailyQuota} checks/day. <code>email</code> is optional contact info and is not verified; keys are limited per IP per day. &ldquo;Live check unavailable&rdquo; (422) answers are cached per host for 10 minutes and blocked-target (403) answers for 5 minutes; failed checks (502) are never cached.</p>
<p>Errors: <code>400</code> invalid input, <code>401</code> bad key, <code>403</code> blocked target (private/internal), <code>405</code> wrong method, <code>413</code> body too large, <code>415</code> keys endpoint needs JSON, <code>422</code> not resolvable / live check unavailable, <code>429</code> rate limit or daily cap, <code>502</code> check failed (no grade), <code>503</code> temporarily unavailable.</p></div>
<div class="card"><h3>MCP server for AI agents</h3><p><code>POST ${o}/mcp</code> — remote MCP (Streamable HTTP, stateless, JSON responses). One read-only tool, <code>check_certificate</code> (<code>host</code>, optional <code>port</code> and <code>include_raw</code>). Same keys, limits and cache as <code>/api/v1/check</code>; each <code>tools/call</code> is one check. Keys may be sent as <code>X-API-Key</code> or <code>Authorization: Bearer</code> (on the JSON API too). Machine-readable: <a href="/llms.txt">/llms.txt</a>, <a href="/openapi.json">/openapi.json</a>.</p></div>
<div class="card"><h3>Other</h3><p><code>GET /health</code> — service status. <code>/sitemap.xml</code>, <code>/robots.txt</code>.</p></div>
${footLinks}
</main></body></html>`;
}

export function privacyHtml(cfg) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CertGuard privacy</title>${cfg.publicLaunch ? '' : '<meta name="robots" content="noindex,nofollow">'}<link rel="icon" type="image/svg+xml" href="/favicon.svg"><style>${STYLE}</style></head><body><main>
<h1>Cert<span>Guard</span> privacy</h1><p class="sub"><a href="/">← checker</a></p>
<div class="card"><ul>
<li><b>Hosts you check.</b> Results are cached by host and port for a few minutes (see the footer of the checker) so repeat checks are fast; we don&#39;t keep a history of the hosts you check beyond that cache.</li>
<li><b>Rate limits.</b> Per-IP and per-key counters are stored under a keyed one-way hash (HMAC) of your IP address or key, never the raw value, and expire within a few days.</li>
<li><b>Free API keys.</b> We store only a hash of the key. The optional email is stored only as a keyed hash and is not verified.</li>
<li><b>CertGuard Pro payments.</b> Pro subscriptions are sold and billed by ${ext('https://polar.sh/', 'Polar')} (merchant of record), which processes your payment details and email address under its own privacy policy. CertGuard never receives card details.</li>
<li><b>Pro license keys.</b> Polar issues the license key. Polar notifies a small companion service run by the CertGuard operator, which stores the key with its status, plan, expiry and Polar&#39;s customer and subscription IDs (no name, email or payment data) in Cloudflare Workers KV so CertGuard can check it. CertGuard only reads that record, never logs the key, and counts your usage under a one-way hash of the key. Cancelled, revoked or expired keys stop working.</li>
<li><b>RapidAPI (only for calls to <code>/rapidapi/v1/*</code>).</b> If you use CertGuard through the ${ext('https://rapidapi.com/', 'RapidAPI')} marketplace, RapidAPI is a processor for those calls: it handles your account, API key, subscription, billing and usage counting, and forwards each request to CertGuard under its own privacy policy. CertGuard receives the host and port you ask about plus RapidAPI&#39;s username and plan headers; it uses a one-way hash of the username only for per-minute rate limiting and stores nothing else about you. Direct calls to <code>/api/v1</code> and <code>/mcp</code> do not involve RapidAPI.</li>
<li><b>No cookies or analytics.</b> There are no cookies and the pages load no third-party scripts.</li>
<li><b>Infrastructure.</b> CertGuard runs on Cloudflare Workers; Cloudflare processes requests as our infrastructure provider.</li>
<li><b>Contact.</b> <a href="mailto:${CONTACT_EMAIL}">${CONTACT_EMAIL}</a></li>
</ul></div>
${footLinks}
</main></body></html>`;
}

export const appJs = `(() => {
  const $ = (s) => document.querySelector(s);
  const mc = document.getElementById('mcp-config');
  if (mc) mc.textContent = JSON.stringify({ mcpServers: { certguard: { type: 'http', url: location.origin + '/mcp' } } }, null, 2);
  const out = $('#out');
  const el = (tag, attrs = {}, ...kids) => { const e = document.createElement(tag); for (const [k, v] of Object.entries(attrs)) { if (k === 'class') e.className = v; else e.setAttribute(k, v); } for (const k of kids) e.append(k && k.nodeType ? k : String(k ?? '')); return e; };
  const badge = (text, kind) => el('span', { class: 'badge b-' + kind }, text);
  const row = (k, v) => el('tr', {}, el('th', {}, k), el('td', {}, v));
  const statusKind = { ok: 'ok', warning: 'warn', critical: 'bad', expired: 'bad', not_yet_valid: 'bad' };
  const sevKind = { critical: 'bad', warning: 'warn', info: 'info' };
  const yn = (v, good = true) => v === null || v === undefined ? badge('unknown', 'info') : badge(v ? 'yes' : 'no', v === good ? 'ok' : 'bad');
  function render(r) {
    out.replaceChildren();
    if (!r.ok) {
      const card = el('div', { class: 'card' });
      if (r.status === 'check_failed' || r.status === 'live_unavailable') {
        card.append(el('div', { class: 'head' }, el('div', { class: 'grade gF', style: 'font-size:22px' }, '—'),
          el('div', {}, el('div', {}, el('b', {}, r.host + ':' + r.port), badge(r.status === 'check_failed' ? 'check failed — no grade' : 'live check unavailable — no grade', r.status === 'check_failed' ? 'bad' : 'warn')),
            el('div', {}, r.error.message))));
        const a = (r.source && r.source.attempts) || [];
        if (a.length) {
          const ul = el('ul', { class: 'issues' });
          for (const x of a) ul.append(el('li', {}, x.offered + ': ' + x.result + (x.message ? ' — ' + x.message : '')));
          card.append(el('div', { class: 'mut', style: 'margin-top:8px' }, 'Attempts made:'), ul);
        }
      } else card.append(el('div', { class: 'err' }, (r.error && r.error.message) || 'Error'));
      out.append(card); return;
    }
    const head = el('div', { class: 'card' }, el('div', { class: 'head' },
      el('div', { class: 'grade g' + r.grade }, r.grade + (r.gradeEstimated ? '?' : '')),
      el('div', {}, el('div', {}, el('b', {}, r.host + ':' + r.port), r.source.live ? badge('live handshake', 'ok') : badge('from CT logs — not live', 'warn'), r.cache && r.cache.hit ? badge('cached ' + r.cache.ageSeconds + 's', 'info') : ''),
        el('div', {}, r.summary), el('div', { class: 'mut' }, r.source.description))));
    out.append(head);
    const c = r.certificate, x = r.expiry, h = r.hostname, t = r.tls || {}, ch = r.chain || {};
    out.append(el('div', { class: 'card' }, el('table', {},
      row('Expires', el('span', {}, x.notAfter + ' ', badge(x.status.replace(/_/g, ' ') + ' · ' + x.daysRemaining + ' days', statusKind[x.status] || 'info'))),
      row('Valid from', x.notBefore),
      row('Hostname match', el('span', {}, yn(h.matches), ' ', h.matchedName || h.note || '')),
      row('Subject', c.subject || ''),
      row('Issuer', c.issuer || ''),
      row('Names (SAN)', (c.sans || []).slice(0, 12).join(', ') + ((c.sans || []).length > 12 ? ' …(+' + ((c.sans.length) - 12) + ')' : '')),
      row('Key', c.key ? c.key.label : 'unknown'),
      row('Signature', c.signatureAlgorithm || 'unknown'),
      row('TLS version', t.version || el('span', { class: 'mut' }, t.note || 'not observed')),
      row('Cipher / group', t.cipherSuite ? t.cipherSuite + (t.keyExchangeGroup ? ' · ' + t.keyExchangeGroup : '') : '—'),
      row('Chain trusted', el('span', {}, yn(ch.trusted), ' ', ch.trustAnchor ? 'anchor: ' + ch.trustAnchor : (ch.note || ''))),
      row('Chain complete', yn(ch.complete)),
      row('Revocation', el('span', {}, badge('not checked', 'warn'), ' OCSP/CRL status is not queried')),
      row('SHA-256', el('code', {}, c.sha256Fingerprint || '—')))));
    if (ch.certificates && ch.certificates.length) {
      const tb = el('table', { class: 'chain' }, el('tr', {}, el('th', {}, '#'), el('th', {}, 'Subject → Issuer'), el('th', {}, 'Expires / key')));
      for (const cc of ch.certificates) tb.append(el('tr', {}, el('td', {}, cc.index + ' ' + cc.role), el('td', {}, (cc.subjectCN || cc.subject) + ' → ' + (cc.issuerCN || cc.issuer)), el('td', {}, cc.notAfter.slice(0, 10) + ' · ' + cc.key.label + (cc.expired ? ' (EXPIRED)' : ''))));
      out.append(el('div', { class: 'card' }, el('b', {}, 'Certificate chain as sent by the server'), tb));
    }
    if (r.issues && r.issues.length) {
      const ul = el('ul', { class: 'issues' });
      for (const i of r.issues) ul.append(el('li', {}, badge(i.severity, sevKind[i.severity] || 'info'), ' ', i.message));
      out.append(el('div', { class: 'card' }, el('b', {}, 'Findings'), ul));
    }
    if (r.notChecked && r.notChecked.length) {
      const ul = el('ul', { class: 'issues' });
      for (const n of r.notChecked) ul.append(el('li', {}, n));
      out.append(el('div', { class: 'card' }, el('b', {}, 'Not checked'), el('span', { class: 'mut' }, ' — revocation_checked: ' + String(r.revocation_checked)), ul));
    }
    const raw = el('details', {}, el('summary', {}, 'Raw JSON'), el('pre', {}, JSON.stringify(r, null, 2)));
    out.append(el('div', { class: 'card' }, raw));
  }
  async function check(host, port) {
    $('#go').disabled = true; out.replaceChildren(el('div', { class: 'card mut' }, 'Checking ' + host + ':' + port + ' …'));
    try {
      const res = await fetch('/api/v1/check?host=' + encodeURIComponent(host) + '&port=' + encodeURIComponent(port));
      render(await res.json());
      history.replaceState(null, '', '?host=' + encodeURIComponent(host) + (port !== '443' ? '&port=' + port : ''));
    } catch (e) { out.replaceChildren(el('div', { class: 'card err' }, 'Request failed: ' + e.message)); }
    finally { $('#go').disabled = false; }
  }
  $('#f').addEventListener('submit', (e) => { e.preventDefault(); const h = $('#host').value.trim(); if (h) check(h, $('#port').value); });
  const q = new URLSearchParams(location.search);
  if (q.get('host')) { $('#host').value = q.get('host'); if (q.get('port')) $('#port').value = q.get('port'); check(q.get('host'), $('#port').value); }
})();`;
