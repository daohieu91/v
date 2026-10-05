import { URL_PREFIX } from './config';

/**
 * Seal payload v1 (spec §4.1 + §12 amendment): a port of the app's SealCodec.kt, rule for rule.
 * Decode is CANONICAL ONLY (ruling P17): the header is re-encoded from the parsed fields and must equal the bytes received, so no byte
 * that decoding drops (reserved flag bits, location fields without the location flag, skew without the GPS-time flag, …) is free to edit.
 * Decode order, identical to the app and to vectors_check.py: empty, version, length, inverted frame, signature range, GPS sentinel,
 * NO_FINGERPRINT with a fingerprint (P26), field ranges, canonical. `rule` names the check, as in the vectors' `rule` keys.
 *
 * Flags (u16, bit 0 = 0x0001; payload byte 2 holds bits 0–7): 0 location · 1 approximate · 2 stale · 3 automatic time · 4 GPS time ·
 * 5 software key · 6 recovery bit (not signed) · 7 NO_FINGERPRINT (P26: the photo was too dark/flat to fingerprint; phash MUST be 0) ·
 * 8–15 reserved (must be 0).
 */
export type PayloadRule = 'empty' | 'version' | 'length' | 'inverted_frame' | 'signature_range' | 'gps_time_without_skew' | 'out_of_range'
  | 'noncanonical' | 'base64url_length' | 'base64url_char' | 'base64url_pad_bits' | 'fragment_too_long';
export class PayloadError extends Error {
  constructor(readonly rule: PayloadRule) { super(rule); this.name = 'PayloadError'; }
}
export interface SealLocation { latE5: number; lngE5: number; accuracyM: number; ageTens: number; approximate: boolean; stale: boolean }
export interface SealFields { version: number; epochSeconds: number; tzOffsetMinutes: number; location: SealLocation | null; autoTime: boolean;
  clockSkewSeconds: number | null; softwareKey: boolean; phash: bigint; frame: [number, number, number, number]; keyTag: number;
  /** P26: sealed without a fingerprint (phash is 0). A verifier never compares a hash for it (P28: it measures the texture instead). */
  noFingerprint: boolean }
/** `signed` = header(fields, recoveryBit 0): the 39 bytes the key signed (the recovery bit is not signed). */
export interface SealPayload { fields: SealFields; recoveryBit: 0 | 1; signature: Uint8Array; signed: Uint8Array }

export const SIZE_V1 = 103;
export const HEADER_V1 = 39;
/** base64url length of the longest supported payload (v1: 103 B → 138 chars), checked before any decoding (P18 c). */
export const MAX_FRAGMENT_LEN = 138;
const SKEW_NONE = -32768;
const MAX_TZ_MIN = 18 * 60;
const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
/** RFC 4648 §5, no padding. */
export function b64urlEncode(b: Uint8Array): string {
  let s = ''; let i = 0;
  for (; i + 3 <= b.length; i += 3) { const n = (b[i] << 16) | (b[i + 1] << 8) | b[i + 2]; s += A[n >> 18] + A[(n >> 12) & 63] + A[(n >> 6) & 63] + A[n & 63]; }
  if (b.length - i === 1) { const n = b[i] << 16; s += A[n >> 18] + A[(n >> 12) & 63]; }
  if (b.length - i === 2) { const n = (b[i] << 16) | (b[i + 1] << 8); s += A[n >> 18] + A[(n >> 12) & 63] + A[(n >> 6) & 63]; }
  return s;
}
/** Strict: no '=' padding, no standard-alphabet characters, and the unused pad bits must be zero (one spelling per byte string, P18 b). */
export function b64urlDecode(s: string): Uint8Array {
  if (s.length % 4 === 1) throw new PayloadError('base64url_length');
  const out = new Uint8Array(Math.floor((s.length * 3) / 4)); let o = 0; let buf = 0; let bits = 0;
  for (let k = 0; k < s.length; k++) {
    const v = A.indexOf(s[k]); if (v < 0) throw new PayloadError('base64url_char');
    buf = (buf << 6) | v; bits += 6;
    if (bits >= 8) { bits -= 8; out[o++] = (buf >> bits) & 0xff; }
    buf &= (1 << bits) - 1;
  }
  if (buf !== 0) throw new PayloadError('base64url_pad_bits');
  return out.subarray(0, o);
}

/** SealCodec.header: the 39-byte header of `f`. Fields outside their slots are rejected (the buffer would silently truncate them). */
export function encodeHeader(f: SealFields, recoveryBit: 0 | 1): Uint8Array {
  const loc = f.location; const skew = f.clockSkewSeconds;
  const int = (x: number, lo: number, hi: number) => Number.isInteger(x) && x >= lo && x <= hi;
  if (f.version !== 1 || (recoveryBit !== 0 && recoveryBit !== 1)) throw new PayloadError('version');
  if (f.noFingerprint && f.phash !== 0n) throw new PayloadError('noncanonical');   // P26, as SealCodec.header's require
  if (!int(f.epochSeconds, 0, 2 ** 40 - 1) || !int(f.tzOffsetMinutes, -MAX_TZ_MIN, MAX_TZ_MIN) || (skew !== null && !int(skew, -32767, 32767))
    || !int(f.keyTag, -(2 ** 31), 2 ** 31 - 1) || f.phash < 0n || f.phash >= 1n << 64n || !f.frame.every(x => int(x, 0, 255)))
    throw new PayloadError('out_of_range');
  if (loc && !(int(loc.latE5, -9_000_000, 9_000_000) && int(loc.lngE5, -18_000_000, 18_000_000) && int(loc.accuracyM, 0, 65535) && int(loc.ageTens, 0, 255)))
    throw new PayloadError('out_of_range');
  let flags = 0;
  if (loc) flags |= 0x01;
  if (loc?.approximate) flags |= 0x02;
  if (loc?.stale) flags |= 0x04;
  if (f.autoTime) flags |= 0x08;
  if (skew !== null) flags |= 0x10;
  if (f.softwareKey) flags |= 0x20;
  if (recoveryBit === 1) flags |= 0x40;
  if (f.noFingerprint) flags |= 0x80;
  const b = new Uint8Array(HEADER_V1); const v = new DataView(b.buffer);
  b[0] = 1;
  v.setUint16(1, flags);
  b[3] = Math.floor(f.epochSeconds / 2 ** 32); v.setUint32(4, f.epochSeconds % 2 ** 32);   // 5-byte epoch: never a 32-bit operator
  v.setInt16(8, f.tzOffsetMinutes);
  v.setInt32(10, loc?.latE5 ?? 0); v.setInt32(14, loc?.lngE5 ?? 0);
  v.setUint16(18, loc?.accuracyM ?? 65535); b[20] = loc?.ageTens ?? 0;
  v.setInt16(21, skew ?? SKEW_NONE);
  v.setBigUint64(23, f.phash);
  b.set(f.frame, 31);
  v.setInt32(35, f.keyTag);
  return b;
}

/** Every version ever shipped stays decodable, forever (spec §4.1). Throws only PayloadError. */
export function decodePayload(b: Uint8Array): SealPayload {
  if (b.length === 0) throw new PayloadError('empty');
  switch (b[0]) { case 1: return decodeV1(b); default: throw new PayloadError('version'); }
}

const big = (b: Uint8Array) => b.reduce((a, x) => (a << 8n) | BigInt(x), 0n);

/**
 * v1 decode up to (not including) the canonical re-encode compare: every check before it, in the app's order. Exported so the tests can
 * prove the explicit P26 rule on its own (inside decodeV1 the re-encode would also reject those bytes). Throws only PayloadError.
 */
export function parseV1(b: Uint8Array): { fields: SealFields; recoveryBit: 0 | 1; signature: Uint8Array } {
  if (b.length !== SIZE_V1) throw new PayloadError('length');
  const v = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const flags = v.getUint16(1);
  const skew = v.getInt16(21);
  const frame: [number, number, number, number] = [b[31], b[32], b[33], b[34]];
  if (frame[0] > frame[2] || frame[1] > frame[3]) throw new PayloadError('inverted_frame');
  const signature = b.slice(HEADER_V1, SIZE_V1);
  const r = big(signature.subarray(0, 32)); const s = big(signature.subarray(32, 64));
  // r, s ∈ [1, n−1]: an out-of-range scalar is a malformed payload, not merely "does not verify".
  if (r === 0n || r >= N || s === 0n || s >= N) throw new PayloadError('signature_range');
  if ((flags & 0x10) !== 0 && skew === SKEW_NONE) throw new PayloadError('gps_time_without_skew');
  const noFingerprint = (flags & 0x80) !== 0;
  // P26, part of the canonical rule, explicit because the re-encode below reproduces the flag: after the GPS sentinel, before the
  // re-encode compare (same order as SealCodec.decode). A zero phash alone never implies the flag.
  if (noFingerprint && v.getBigUint64(23) !== 0n) throw new PayloadError('noncanonical');
  const fields: SealFields = {
    version: 1,
    epochSeconds: b[3] * 2 ** 32 + v.getUint32(4),
    tzOffsetMinutes: v.getInt16(8),
    location: (flags & 0x01) !== 0 ? { latE5: v.getInt32(10), lngE5: v.getInt32(14), accuracyM: v.getUint16(18), ageTens: b[20],
      approximate: (flags & 0x02) !== 0, stale: (flags & 0x04) !== 0 } : null,
    autoTime: (flags & 0x08) !== 0,
    clockSkewSeconds: (flags & 0x10) !== 0 ? skew : null,
    softwareKey: (flags & 0x20) !== 0,
    phash: v.getBigUint64(23),
    frame,
    keyTag: v.getInt32(35),
    noFingerprint,
  };
  return { fields, recoveryBit: ((flags >> 6) & 1) as 0 | 1, signature };
}

function decodeV1(b: Uint8Array): SealPayload {
  const { fields, recoveryBit, signature } = parseV1(b);
  const header = encodeHeader(fields, recoveryBit);
  for (let i = 0; i < HEADER_V1; i++) if (header[i] !== b[i]) throw new PayloadError('noncanonical');
  return { fields, recoveryBit, signature, signed: encodeHeader(fields, 0) };
}

/** The URL fragment (after '#') → payload. Its length is bounded before any decoding: a pasted or scanned URL is untrusted (P18 c). */
export function decodeFragment(fragment: string): SealPayload {
  if (fragment.length > MAX_FRAGMENT_LEN) throw new PayloadError('fragment_too_long');
  return decodePayload(b64urlDecode(fragment));
}

/** Only `https://daohieu91.github.io/v/#<fragment>`; anything else, or any malformed payload, is null. */
export function payloadFromUrl(text: string): SealPayload | null {
  if (!text.startsWith(URL_PREFIX)) return null;
  try { return decodeFragment(text.slice(URL_PREFIX.length)); } catch { return null; }
}

/**
 * The one identity of a seal (ruling P18 a): header(fields, 0) + r, as hex. Never the payload bytes or the URL: the ECDSA s-twin
 * (r, n − s, recovery bit flipped) is a second valid encoding of the same seal, so bytes are not unique.
 */
export function sealIdentity(p: SealPayload): string {
  const h = (x: Uint8Array) => [...x].map(c => c.toString(16).padStart(2, '0')).join('');
  return h(p.signed) + h(p.signature.subarray(0, 32));
}
