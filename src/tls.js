// Manual TLS handshake probe. Sends a ClientHello over a *plain* TCP stream and reads the
// server's handshake far enough to obtain the certificate chain:
//  - TLS 1.2 and older: the Certificate message is plaintext; we parse it directly.
//  - TLS 1.3: the Certificate message is encrypted under the handshake traffic keys. We do a real
//    (EC)DHE key exchange (X25519 or P-256 via WebCrypto), run the RFC 8446 key schedule
//    (HKDF via HMAC), and AES-GCM-decrypt the server's handshake flight. We stop after reading
//    the Certificate (we never send Finished / application data), then close the socket.
// We do NOT authenticate the server's CertificateVerify signature: we are inspecting what the
// server presents, not establishing a trusted channel.

const enc = new TextEncoder();
const subtle = globalThis.crypto.subtle;

export class TlsProbeError extends Error {
  constructor(code, message, extra = {}) { super(message); this.code = code; Object.assign(this, extra); }
}

export const TLS_VERSIONS = { 0x0300: 'SSL 3.0', 0x0301: 'TLS 1.0', 0x0302: 'TLS 1.1', 0x0303: 'TLS 1.2', 0x0304: 'TLS 1.3' };

export const CIPHER_SUITES = {
  0x1301: 'TLS_AES_128_GCM_SHA256', 0x1302: 'TLS_AES_256_GCM_SHA384', 0x1303: 'TLS_CHACHA20_POLY1305_SHA256',
  0xc02b: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256', 0xc02f: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
  0xc02c: 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384', 0xc030: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
  0xcca9: 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256', 0xcca8: 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
  0xc009: 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA', 0xc013: 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
  0xc00a: 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA', 0xc014: 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
  0xc023: 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256', 0xc027: 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',
  0x009e: 'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256', 0x009f: 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384',
  0x009c: 'TLS_RSA_WITH_AES_128_GCM_SHA256', 0x009d: 'TLS_RSA_WITH_AES_256_GCM_SHA384',
  0x003c: 'TLS_RSA_WITH_AES_128_CBC_SHA256', 0x002f: 'TLS_RSA_WITH_AES_128_CBC_SHA', 0x0035: 'TLS_RSA_WITH_AES_256_CBC_SHA',
  0x000a: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA', 0x0033: 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA', 0x0039: 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA',
};
const TLS13_SUITES = { 0x1301: { hash: 'SHA-256', hashLen: 32, keyLen: 16 }, 0x1302: { hash: 'SHA-384', hashLen: 48, keyLen: 32 } };
const OFFERED_SUITES_13 = [0x1301, 0x1302];
const OFFERED_SUITES_12 = [0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc023, 0xc027, 0xc009, 0xc013, 0xc00a, 0xc014,
  0x009e, 0x009f, 0x009c, 0x009d, 0x003c, 0x002f, 0x0035, 0x0033, 0x0039, 0x000a];
export const GROUPS = { 0x001d: 'x25519', 0x0017: 'secp256r1', 0x0018: 'secp384r1', 0x0019: 'secp521r1', 0x001e: 'x448', 0x11ec: 'X25519MLKEM768' };

export const ALERTS = {
  0: 'close_notify', 10: 'unexpected_message', 20: 'bad_record_mac', 40: 'handshake_failure', 42: 'bad_certificate',
  47: 'illegal_parameter', 50: 'decode_error', 51: 'decrypt_error', 70: 'protocol_version', 71: 'insufficient_security',
  80: 'internal_error', 86: 'inappropriate_fallback', 90: 'user_canceled', 109: 'missing_extension', 110: 'unsupported_extension',
  112: 'unrecognized_name', 116: 'certificate_required', 120: 'no_application_protocol',
};

// HelloRetryRequest magic random (RFC 8446 §4.1.3)
const HRR_RANDOM = Uint8Array.from([0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
  0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c]);

// ---------- byte helpers ----------
function concat(...arrs) {
  let n = 0; for (const a of arrs) n += a.length;
  const out = new Uint8Array(n); let p = 0;
  for (const a of arrs) { out.set(a, p); p += a.length; }
  return out;
}
const u8 = (n) => Uint8Array.of(n & 0xff);
const u16 = (n) => Uint8Array.of((n >> 8) & 0xff, n & 0xff);
const u24 = (n) => Uint8Array.of((n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff);
const vec8 = (b) => concat(u8(b.length), b);
const vec16 = (b) => concat(u16(b.length), b);
const vec24 = (b) => concat(u24(b.length), b);
const ext = (type, body) => concat(u16(type), vec16(body));
const rnd = (n) => crypto.getRandomValues(new Uint8Array(n));

class Reader {
  constructor(buf, what = 'message') { this.b = buf; this.p = 0; this.what = what; }
  need(n) { if (this.p + n > this.b.length) throw new TlsProbeError('decode_error', `truncated ${this.what}`); }
  u8() { this.need(1); return this.b[this.p++]; }
  u16() { this.need(2); const v = (this.b[this.p] << 8) | this.b[this.p + 1]; this.p += 2; return v; }
  u24() { this.need(3); const v = (this.b[this.p] << 16) | (this.b[this.p + 1] << 8) | this.b[this.p + 2]; this.p += 3; return v; }
  bytes(n) { this.need(n); const v = this.b.subarray(this.p, this.p + n); this.p += n; return v; }
  vec8() { return this.bytes(this.u8()); }
  vec16() { return this.bytes(this.u16()); }
  vec24() { return this.bytes(this.u24()); }
  get left() { return this.b.length - this.p; }
}

// ---------- ClientHello ----------
/**
 * Build a ClientHello.
 * opts: { sni: string|null, tls13: boolean, keyShares: [{group, pub}], alpn: string[]|null }
 * Returns the handshake message bytes (type+len+body) — the record wrapper is added by caller.
 */
export function buildClientHello({ sni, tls13 = true, keyShares = [], alpn = null, random = rnd(32), sessionId = rnd(32), cookie = null }) {
  const suites = tls13 ? [...OFFERED_SUITES_13, ...OFFERED_SUITES_12] : OFFERED_SUITES_12;
  const exts = [];
  if (sni) {
    const name = enc.encode(sni);
    exts.push(ext(0x0000, vec16(concat(u8(0), vec16(name)))));
  }
  exts.push(ext(0x0017, new Uint8Array(0))); // extended_master_secret
  exts.push(ext(0xff01, Uint8Array.of(0))); // renegotiation_info
  exts.push(ext(0x000a, vec16(concat(u16(0x001d), u16(0x0017), u16(0x0018))))); // supported_groups
  exts.push(ext(0x000b, vec8(Uint8Array.of(0)))); // ec_point_formats: uncompressed
  exts.push(ext(0x0005, Uint8Array.of(1, 0, 0, 0, 0))); // status_request (OCSP)
  exts.push(ext(0x0012, new Uint8Array(0))); // signed_certificate_timestamp
  const sigalgs = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0603, 0x0807, 0x0203, 0x0201];
  exts.push(ext(0x000d, vec16(concat(...sigalgs.map(u16)))));
  if (alpn && alpn.length) exts.push(ext(0x0010, vec16(concat(...alpn.map((p) => vec8(enc.encode(p)))))));
  if (tls13) {
    exts.push(ext(0x002b, vec8(concat(u16(0x0304), u16(0x0303))))); // supported_versions
    exts.push(ext(0x002d, vec8(Uint8Array.of(1)))); // psk_key_exchange_modes: psk_dhe_ke
    exts.push(ext(0x0033, vec16(concat(...keyShares.map((k) => concat(u16(k.group), vec16(k.pub))))))); // key_share
    if (cookie) exts.push(ext(0x002c, vec16(cookie))); // cookie (echoed after HelloRetryRequest)
  }
  const body = concat(
    u16(0x0303), random, vec8(sessionId),
    vec16(concat(...suites.map(u16))),
    vec8(Uint8Array.of(0)), // compression: null
    vec16(concat(...exts)),
  );
  return concat(u8(1), vec24(body));
}

export function wrapRecord(type, payload, version = 0x0301) {
  return concat(u8(type), u16(version), vec16(payload));
}

// ---------- record / handshake stream ----------
class RecordStream {
  constructor(transport, { maxBytes = 96 * 1024 } = {}) {
    this.t = transport; this.buf = new Uint8Array(0); this.total = 0; this.maxBytes = maxBytes; this.eof = false;
  }
  async fill(n) {
    while (this.buf.length < n) {
      if (this.eof) throw new TlsProbeError('connection_closed', 'server closed the connection during handshake');
      const chunk = await this.t.read();
      if (!chunk) { this.eof = true; continue; }
      this.total += chunk.length;
      if (this.total > this.maxBytes) throw new TlsProbeError('too_large', `server handshake exceeded the ${this.maxBytes / 1024} KB limit`);
      this.buf = concat(this.buf, chunk);
    }
  }
  async next() {
    await this.fill(5);
    const type = this.buf[0];
    const version = (this.buf[1] << 8) | this.buf[2];
    const len = (this.buf[3] << 8) | this.buf[4];
    if (type < 20 || type > 24 || (this.buf[1] !== 0x03)) {
      // Not TLS — e.g. plaintext HTTP or SMTP banner
      const preview = new TextDecoder().decode(this.buf.subarray(0, Math.min(40, this.buf.length))).replace(/[^\x20-\x7e]/g, '.');
      throw new TlsProbeError('not_tls', `server did not respond with TLS (got: "${preview}")`);
    }
    if (len > 18432) throw new TlsProbeError('decode_error', 'record too large');
    await this.fill(5 + len);
    const header = this.buf.subarray(0, 5);
    const payload = this.buf.subarray(5, 5 + len);
    const rec = { type, version, header: header.slice(), payload: payload.slice() };
    this.buf = this.buf.slice(5 + len);
    return rec;
  }
}

/** Splits a byte stream of handshake records into handshake messages. */
class HandshakeAssembler {
  constructor() { this.buf = new Uint8Array(0); }
  push(bytes) { this.buf = concat(this.buf, bytes); }
  *messages() {
    while (this.buf.length >= 4) {
      const len = (this.buf[1] << 16) | (this.buf[2] << 8) | this.buf[3];
      if (len > 65536) throw new TlsProbeError('too_large', `handshake message of ${len} bytes exceeds the 64 KB limit`);
      if (this.buf.length < 4 + len) return;
      const raw = this.buf.slice(0, 4 + len);
      this.buf = this.buf.slice(4 + len);
      yield { type: raw[0], body: raw.subarray(4), raw };
    }
  }
}

function alertError(payload) {
  const level = payload[0]; const desc = payload[1];
  const name = ALERTS[desc] || `alert_${desc}`;
  return new TlsProbeError('tls_alert', `server sent TLS alert: ${name}${level === 2 ? ' (fatal)' : ''}`, { alert: name, alertCode: desc });
}

// ---------- ServerHello ----------
export function parseServerHello(body) {
  const r = new Reader(body, 'ServerHello');
  const legacyVersion = r.u16();
  const random = r.bytes(32);
  const sessionId = r.vec8();
  const cipherSuite = r.u16();
  const compression = r.u8();
  const out = { legacyVersion, version: legacyVersion, random, sessionId, cipherSuite, compression, keyShare: null, alpn: null, isHrr: false, extensions: [] };
  out.isHrr = random.every((b, i) => b === HRR_RANDOM[i]);
  if (r.left >= 2) {
    const er = new Reader(r.vec16(), 'ServerHello extensions');
    while (er.left > 0) {
      const type = er.u16(); const data = er.vec16();
      out.extensions.push(type);
      const d = new Reader(data, 'extension');
      if (type === 0x002b) out.version = d.u16();
      else if (type === 0x0033) {
        const group = d.u16();
        out.keyShare = out.isHrr ? { group, pub: null } : { group, pub: d.vec16() };
      } else if (type === 0x0010) { const list = new Reader(d.vec16()); out.alpn = new TextDecoder().decode(list.vec8()); }
      else if (type === 0x002c) out.cookie = d.vec16().slice();
    }
  }
  return out;
}

// ---------- Certificate message ----------
export function parseCertificateMessage(body, tls13) {
  const r = new Reader(body, 'Certificate');
  const certs = [];
  let ocspStapled = false;
  if (tls13) r.vec8(); // certificate_request_context
  const list = new Reader(r.vec24(), 'certificate_list');
  while (list.left > 0) {
    const der = list.vec24();
    certs.push(der.slice());
    if (tls13) {
      const exts = new Reader(list.vec16(), 'cert entry extensions');
      while (exts.left > 0) { const t = exts.u16(); exts.vec16(); if (t === 0x0005) ocspStapled = true; }
    }
    if (certs.length > 20) throw new TlsProbeError('decode_error', 'too many certificates');
  }
  return { certs, ocspStapled };
}

// ---------- TLS 1.3 key schedule ----------
async function hmac(hash, key, data) {
  const k = await subtle.importKey('raw', key, { name: 'HMAC', hash }, false, ['sign']);
  return new Uint8Array(await subtle.sign('HMAC', k, data));
}
export async function hkdfExtract(hash, salt, ikm) { return hmac(hash, salt, ikm); }
export async function hkdfExpandLabel(hash, secret, label, context, length) {
  const full = enc.encode('tls13 ' + label);
  const info = concat(u16(length), vec8(full), vec8(context));
  // HKDF-Expand: T(n) = HMAC(PRK, T(n-1) | info | n)
  let t = new Uint8Array(0); let out = new Uint8Array(0);
  for (let i = 1; out.length < length; i++) {
    t = await hmac(hash, secret, concat(t, info, u8(i)));
    out = concat(out, t);
  }
  return out.slice(0, length);
}
export async function digest(hash, data) { return new Uint8Array(await subtle.digest(hash, data)); }

export async function deriveServerHandshakeKeys(suiteId, sharedSecret, transcriptHash) {
  const s = TLS13_SUITES[suiteId];
  const zeros = new Uint8Array(s.hashLen);
  const early = await hkdfExtract(s.hash, zeros, zeros);
  const emptyHash = await digest(s.hash, new Uint8Array(0));
  const derived = await hkdfExpandLabel(s.hash, early, 'derived', emptyHash, s.hashLen);
  const hs = await hkdfExtract(s.hash, derived, sharedSecret);
  const sHs = await hkdfExpandLabel(s.hash, hs, 's hs traffic', transcriptHash, s.hashLen);
  const key = await hkdfExpandLabel(s.hash, sHs, 'key', new Uint8Array(0), s.keyLen);
  const iv = await hkdfExpandLabel(s.hash, sHs, 'iv', new Uint8Array(0), 12);
  return { key, iv };
}

async function makeDecryptor({ key, iv }) {
  const k = await subtle.importKey('raw', key, { name: 'AES-GCM' }, false, ['decrypt']);
  let seq = 0n;
  return async (header, ciphertext) => {
    const nonce = iv.slice();
    let s = seq++;
    for (let i = 11; i >= 4; i--) { nonce[i] ^= Number(s & 0xffn); s >>= 8n; }
    let pt;
    try {
      pt = new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: nonce, additionalData: header, tagLength: 128 }, k, ciphertext));
    } catch {
      throw new TlsProbeError('decrypt_failed', 'could not decrypt TLS 1.3 handshake (key schedule mismatch)');
    }
    let end = pt.length;
    while (end > 0 && pt[end - 1] === 0) end--;
    if (end === 0) throw new TlsProbeError('decode_error', 'empty TLSInnerPlaintext');
    return { type: pt[end - 1], data: pt.subarray(0, end - 1) };
  };
}

const EC_CURVES = { 0x0017: ['P-256', 256], 0x0018: ['P-384', 384] };
async function genShare(group) {
  if (group === 0x001d) {
    const kp = await subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
    return { group, priv: kp.privateKey, pub: new Uint8Array(await subtle.exportKey('raw', kp.publicKey)) };
  }
  const c = EC_CURVES[group];
  if (!c) return null;
  const kp = await subtle.generateKey({ name: 'ECDH', namedCurve: c[0] }, true, ['deriveBits']);
  return { group, priv: kp.privateKey, pub: new Uint8Array(await subtle.exportKey('raw', kp.publicKey)) };
}

async function genKeyShares() {
  const shares = [];
  try {
    const kp = await subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
    shares.push({ group: 0x001d, priv: kp.privateKey, pub: new Uint8Array(await subtle.exportKey('raw', kp.publicKey)) });
  } catch { /* X25519 unavailable */ }
  const kp2 = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  shares.push({ group: 0x0017, priv: kp2.privateKey, pub: new Uint8Array(await subtle.exportKey('raw', kp2.publicKey)) });
  return shares;
}

async function computeShared(share, serverPub) {
  if (share.group === 0x001d) {
    if (serverPub.length !== 32) throw new TlsProbeError('decode_error', 'bad x25519 key share');
    const pk = await subtle.importKey('raw', serverPub, { name: 'X25519' }, false, []);
    return new Uint8Array(await subtle.deriveBits({ name: 'X25519', public: pk }, share.priv, 256));
  }
  const [curve, bits] = EC_CURVES[share.group];
  if (serverPub[0] !== 4) throw new TlsProbeError('decode_error', `bad ${curve} key share`);
  const pk = await subtle.importKey('raw', serverPub, { name: 'ECDH', namedCurve: curve }, false, []);
  return new Uint8Array(await subtle.deriveBits({ name: 'ECDH', public: pk }, share.priv, bits));
}

/**
 * Run one handshake probe over an already-open transport.
 * transport: { write(Uint8Array), read(): Promise<Uint8Array|null>, close() }
 * opts: { sni, tls13 (offer 1.3), alpn }
 * Resolves: { version, versionName, cipherSuite, cipherName, group, alpn, certs: [Uint8Array], ocspStapled, hrr }
 */
export async function handshakeProbe(transport, { sni = null, tls13 = true, alpn = null } = {}) {
  let shares = tls13 ? await genKeyShares() : [];
  const random = rnd(32);
  const sessionId = rnd(32);
  let ch = buildClientHello({ sni, tls13, keyShares: shares, alpn, random, sessionId });
  await transport.write(wrapRecord(22, ch));

  const rs = new RecordStream(transport);
  const hsA = new HandshakeAssembler();
  let sh = null;
  let transcript = ch; // handshake bytes hashed for the TLS 1.3 key schedule
  let decrypt = null;
  let sawHrr = false;
  const result = { hrr: false, ocspStapled: false, certs: null, alpn: null };

  for (let records = 0; records < 64; records++) {
    const rec = await rs.next();
    if (rec.type === 21) throw alertError(rec.payload);
    if (rec.type === 20) continue; // ChangeCipherSpec (middlebox compat) — ignore
    let hsBytes;
    if (rec.type === 22 && !decrypt) hsBytes = rec.payload;
    else if (rec.type === 23 && decrypt) {
      const inner = await decrypt(rec.header, rec.payload);
      if (inner.type === 21) throw alertError(inner.data);
      if (inner.type !== 22) continue;
      hsBytes = inner.data;
    } else throw new TlsProbeError('unexpected_message', `unexpected record type ${rec.type}`);
    hsA.push(hsBytes);

    for (const msg of hsA.messages()) {
      if (!sh) {
        if (msg.type !== 2) throw new TlsProbeError('unexpected_message', `expected ServerHello, got handshake type ${msg.type}`);
        const hello = parseServerHello(msg.body);
        Object.assign(result, {
          version: hello.version, versionName: TLS_VERSIONS[hello.version] || `0x${hello.version.toString(16)}`,
          cipherSuite: hello.cipherSuite, cipherName: CIPHER_SUITES[hello.cipherSuite] || `0x${hello.cipherSuite.toString(16).padStart(4, '0')}`,
          group: hello.keyShare ? (GROUPS[hello.keyShare.group] || `0x${hello.keyShare.group.toString(16)}`) : null,
        });
        if (hello.alpn) result.alpn = hello.alpn;
        if (hello.isHrr) {
          // RFC 8446 §4.1.4: send a second ClientHello with a share for the requested group.
          if (sawHrr) throw new TlsProbeError('unexpected_message', 'second HelloRetryRequest', { partial: result });
          sawHrr = true; result.hrr = true;
          const share = hello.keyShare ? await genShare(hello.keyShare.group).catch(() => null) : null;
          if (!share) throw new TlsProbeError('hello_retry', `server requested unsupported key-exchange group ${result.group}`, { partial: result });
          if (!TLS13_SUITES[hello.cipherSuite]) throw new TlsProbeError('unsupported_suite', `server chose unsupported TLS 1.3 suite ${result.cipherName}`, { partial: result });
          const h = TLS13_SUITES[hello.cipherSuite].hash;
          const ch1Hash = await digest(h, transcript);
          const messageHash = concat(Uint8Array.of(254, 0, 0, ch1Hash.length), ch1Hash);
          shares = [share];
          const ch2 = buildClientHello({ sni, tls13, keyShares: shares, alpn, random, sessionId, cookie: hello.cookie || null });
          transcript = concat(messageHash, msg.raw, ch2);
          await transport.write(wrapRecord(22, ch2, 0x0303));
          continue;
        }
        sh = hello;
        transcript = concat(transcript, msg.raw);
        if (sh.version === 0x0304) {
          if (!TLS13_SUITES[sh.cipherSuite]) throw new TlsProbeError('unsupported_suite', `server chose unsupported TLS 1.3 suite ${result.cipherName}`, { partial: result });
          const share = shares.find((s) => sh.keyShare && s.group === sh.keyShare.group);
          if (!share || !sh.keyShare.pub) throw new TlsProbeError('decode_error', 'server key_share does not match offered groups', { partial: result });
          const shared = await computeShared(share, sh.keyShare.pub);
          const th = await digest(TLS13_SUITES[sh.cipherSuite].hash, transcript);
          decrypt = await makeDecryptor(await deriveServerHandshakeKeys(sh.cipherSuite, shared, th));
          hsA.buf = new Uint8Array(0);
          break;
        }
        continue;
      }
      // after ServerHello
      if (msg.type === 8) { // EncryptedExtensions (TLS 1.3) — ALPN lives here
        try {
          const r = new Reader(msg.body); const er = new Reader(r.vec16());
          while (er.left > 0) {
            const t = er.u16(); const d = er.vec16();
            if (t === 0x0010) { const l = new Reader(new Reader(d).vec16()); result.alpn = new TextDecoder().decode(l.vec8()); }
          }
        } catch { /* ignore */ }
      } else if (msg.type === 11) {
        const cm = parseCertificateMessage(msg.body, sh.version === 0x0304);
        result.certs = cm.certs;
        if (cm.ocspStapled) result.ocspStapled = true;
        if (sh.version === 0x0304) return result; // stapled OCSP in 1.3 arrives inside Certificate
      } else if (msg.type === 22) {
        result.ocspStapled = true; // CertificateStatus (TLS 1.2)
      } else if (msg.type === 14) { // ServerHelloDone
        if (!result.certs) throw new TlsProbeError('no_certificate', 'server sent no certificate (anonymous cipher?)', { partial: result });
        return result;
      } else if (msg.type === 20) {
        throw new TlsProbeError('no_certificate', 'server finished handshake without a certificate (PSK?)', { partial: result });
      }
    }
  }
  if (result.certs) return result;
  throw new TlsProbeError('decode_error', 'handshake did not complete within record budget', { partial: result });
}
