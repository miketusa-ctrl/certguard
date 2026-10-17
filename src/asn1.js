// Minimal, defensive DER (ASN.1) reader. Only what X.509 parsing needs.
// Every read is bounds-checked; malformed input throws Asn1Error.

export class Asn1Error extends Error {}

const MAX_DEPTH = 32;

/**
 * Parse one TLV at `offset` in `buf` (Uint8Array).
 * Returns { tag, cls, constructed, tagNum, start, headerLen, len, end, value(): Uint8Array, raw(): Uint8Array }.
 */
export function readTLV(buf, offset = 0, limit = buf.length) {
  if (offset >= limit) throw new Asn1Error('truncated: no tag');
  const tag = buf[offset];
  const cls = tag >> 6;
  const constructed = (tag & 0x20) !== 0;
  let tagNum = tag & 0x1f;
  let p = offset + 1;
  if (tagNum === 0x1f) {
    // high-tag-number form (rare in X.509); support up to 4 bytes
    tagNum = 0;
    for (let i = 0; i < 4; i++) {
      if (p >= limit) throw new Asn1Error('truncated: tag');
      const b = buf[p++];
      tagNum = (tagNum << 7) | (b & 0x7f);
      if (!(b & 0x80)) break;
      if (i === 3) throw new Asn1Error('tag too long');
    }
  }
  if (p >= limit) throw new Asn1Error('truncated: length');
  let len = buf[p++];
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4) throw new Asn1Error('unsupported length form');
    if (p + n > limit) throw new Asn1Error('truncated: long length');
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[p++];
  }
  const start = p;
  const end = start + len;
  if (end > limit) throw new Asn1Error('truncated: value');
  return {
    tag, cls, constructed, tagNum, offset, start, len, end,
    value: () => buf.subarray(start, end),
    raw: () => buf.subarray(offset, end),
  };
}

/** Return array of child TLVs of a constructed TLV. */
export function children(buf, tlv, depth = 0) {
  if (depth > MAX_DEPTH) throw new Asn1Error('too deep');
  const out = [];
  let p = tlv.start;
  while (p < tlv.end) {
    const c = readTLV(buf, p, tlv.end);
    out.push(c);
    p = c.end;
    if (out.length > 10000) throw new Asn1Error('too many children');
  }
  return out;
}

export function expectTag(tlv, tag, what) {
  if (tlv.tag !== tag) throw new Asn1Error(`expected tag 0x${tag.toString(16)} for ${what}, got 0x${tlv.tag.toString(16)}`);
  return tlv;
}

export function decodeOID(bytes) {
  if (!bytes.length) throw new Asn1Error('empty OID');
  const parts = [];
  let v = 0;
  let first = true;
  for (let i = 0; i < bytes.length; i++) {
    v = v * 128 + (bytes[i] & 0x7f);
    if (v > Number.MAX_SAFE_INTEGER / 256) throw new Asn1Error('OID arc too large');
    if (!(bytes[i] & 0x80)) {
      if (first) {
        if (v < 40) parts.push(0, v);
        else if (v < 80) parts.push(1, v - 40);
        else parts.push(2, v - 80);
        first = false;
      } else parts.push(v);
      v = 0;
    }
  }
  return parts.join('.');
}

const latin1 = (b) => { let s = ''; for (const c of b) s += String.fromCharCode(c); return s; };

export function decodeString(tlv) {
  const v = tlv.value();
  switch (tlv.tag) {
    case 0x0c: return new TextDecoder('utf-8', { fatal: false }).decode(v); // UTF8String
    case 0x13: case 0x16: case 0x1a: case 0x12: return latin1(v); // Printable, IA5, Visible, Numeric
    case 0x14: return latin1(v); // T61 (treated as latin1)
    case 0x1e: { // BMPString UTF-16BE
      let s = '';
      for (let i = 0; i + 1 < v.length; i += 2) s += String.fromCharCode((v[i] << 8) | v[i + 1]);
      return s;
    }
    case 0x1c: { // UniversalString UTF-32BE
      let s = '';
      for (let i = 0; i + 3 < v.length; i += 4) s += String.fromCodePoint(((v[i] << 24) | (v[i + 1] << 16) | (v[i + 2] << 8) | v[i + 3]) >>> 0);
      return s;
    }
    default: return latin1(v);
  }
}

/** UTCTime / GeneralizedTime → Date */
export function decodeTime(tlv) {
  const s = latin1(tlv.value());
  let m;
  if (tlv.tag === 0x17) {
    m = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$/.exec(s);
    if (!m) throw new Asn1Error('bad UTCTime ' + s);
    let y = +m[1];
    y += y >= 50 ? 1900 : 2000;
    return new Date(Date.UTC(y, +m[2] - 1, +m[3], +m[4], +m[5], +(m[6] || 0)));
  }
  if (tlv.tag === 0x18) {
    m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(?:\.\d+)?Z$/.exec(s);
    if (!m) throw new Asn1Error('bad GeneralizedTime ' + s);
    return new Date(Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +(m[6] || 0)));
  }
  throw new Asn1Error('not a time');
}

export function toHex(bytes, sep = '') {
  let s = '';
  for (let i = 0; i < bytes.length; i++) {
    s += (i && sep ? sep : '') + bytes[i].toString(16).padStart(2, '0');
  }
  return s;
}

/** Bit length of an unsigned big-endian INTEGER value (ignores leading zero bytes). */
export function intBitLength(bytes) {
  let i = 0;
  while (i < bytes.length && bytes[i] === 0) i++;
  if (i === bytes.length) return 0;
  return (bytes.length - i - 1) * 8 + (32 - Math.clz32(bytes[i]));
}

export function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

export function b64encode(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  return btoa(s);
}

export function b64decode(str) {
  const s = atob(str);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

export function pemToDers(pem) {
  const out = [];
  const re = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g;
  let m;
  while ((m = re.exec(pem))) out.push(b64decode(m[1].replace(/\s+/g, '')));
  return out;
}
