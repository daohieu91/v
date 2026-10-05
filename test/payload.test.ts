import { describe, expect, it } from 'vitest';
import { URL_PREFIX } from '../src/config';
import { PayloadError, decodeFragment, decodePayload, encodeHeader, parseV1, payloadFromUrl } from '../src/payload';

// v1_case0 of the vectors (canonical, verifies with the test key).
const CASE0 = 'AQBZAGjebTwCHAAt9vkA1nOxAAYAAAJaWgD_EjRWeATK_P_xj6IbuqLxMMXX5vqvpubWTR6LKm-v9YRbdDg_b5aOp0enHN0uTUZawGmvB5pwzFM4WJY8HxrvNbs5DNOoroy7_VECPQ';
const ruleOf = (f: () => unknown) => { try { f(); return 'ACCEPTED'; } catch (e) { return e instanceof PayloadError ? e.rule : 'THREW ' + String(e); } };

describe('payload', () => {
  it('rejects unknown versions and wrong lengths', () => {
    expect(() => decodePayload(new Uint8Array([2, ...new Uint8Array(102)]))).toThrow(PayloadError);
    expect(() => decodePayload(new Uint8Array([1, ...new Uint8Array(101)]))).toThrow(PayloadError);
    expect(() => decodePayload(new Uint8Array())).toThrow(PayloadError);
  });
  it('accepts only the verify URL', () => {
    expect(payloadFromUrl(URL_PREFIX + CASE0)).not.toBeNull();
    // Same length as the real prefix, so only the prefix check can reject them (a shorter one would garble the fragment anyway).
    for (const evil of ['https://daohieu91.github.io/w/#', 'https://daohieu91.github.iO/v/#', 'https://evil.example.com/v/abc#']) {
      expect(evil).toHaveLength(URL_PREFIX.length); expect(payloadFromUrl(evil + CASE0), evil).toBeNull();
    }
    expect(payloadFromUrl('http://daohieu91.github.io/v/#' + CASE0)).toBeNull();
    expect(payloadFromUrl('https://daohieu91.github.io/v/#***')).toBeNull();
    expect(payloadFromUrl(URL_PREFIX + CASE0 + 'A')).toBeNull();
  });
  it('bounds the fragment before decoding: a huge input is rejected by length, not parsed', () => {
    expect(ruleOf(() => decodeFragment(CASE0 + '*'.repeat(1_000_000)))).toBe('fragment_too_long');
  });
  // Kotlin SealCodec.header() range checks run inside the canonical comparison; the vectors have no entry for them.
  it('rejects canonical-looking fields outside their ranges (zone offset, coordinates), never throwing anything else', () => {
    const b = Uint8Array.from(Buffer.from(CASE0, 'base64url'));
    const tz = b.slice(); new DataView(tz.buffer).setInt16(8, 18 * 60 + 1);
    expect(ruleOf(() => decodePayload(tz))).toBe('out_of_range');
    const lat = b.slice(); new DataView(lat.buffer).setInt32(10, 9_000_001);
    expect(ruleOf(() => decodePayload(lat))).toBe('out_of_range');
    const lng = b.slice(); new DataView(lng.buffer).setInt32(14, -18_000_001);
    expect(ruleOf(() => decodePayload(lng))).toBe('out_of_range');
    const ok = b.slice(); new DataView(ok.buffer).setInt16(8, -18 * 60);
    expect(ruleOf(() => decodePayload(ok))).toBe('ACCEPTED');
  });
  it('decodePayload throws only PayloadError on arbitrary input', () => {
    let s = 12345;
    for (let i = 0; i < 2000; i++) {
      const b = new Uint8Array(i % 7 === 0 ? 103 : i % 120);
      for (let j = 0; j < b.length; j++) { s = (Math.imul(s, 1664525) + 1013904223) >>> 0; b[j] = s >>> 24; }
      if (b.length) b[0] = i % 3 === 0 ? 1 : b[0];
      expect(ruleOf(() => decodePayload(b))).not.toMatch(/^THREW/);
    }
  });
  it('encodeHeader round-trips the decoded fields byte for byte', () => {
    const b = Uint8Array.from(Buffer.from(CASE0, 'base64url'));
    const d = decodePayload(b);
    expect(encodeHeader(d.fields, d.recoveryBit)).toEqual(b.slice(0, 39));
    expect(d.signed).toEqual(encodeHeader(d.fields, 0));
  });
  // P26: NO_FINGERPRINT is flag bit 7 (0x80 of byte 2); with it set the 8 phash bytes must be zero. Same order as SealCodec.decode:
  // after the GPS-time check, before the re-encode compare (and so before the field-range checks that run inside it).
  it('NO_FINGERPRINT with a fingerprint is noncanonical, after the GPS-time check and before the re-encode compare', () => {
    const b = Uint8Array.from(Buffer.from(CASE0, 'base64url')); expect(b.slice(23, 31).some(x => x !== 0)).toBe(true);
    const flagged = b.slice(); flagged[2] |= 0x80;
    expect(ruleOf(() => decodePayload(flagged))).toBe('noncanonical');
    const gps = flagged.slice(); new DataView(gps.buffer).setInt16(21, -32768);          // GPS-time flag (0x10) with no skew: that rule first
    expect(gps[2] & 0x10).toBe(0x10); expect(ruleOf(() => decodePayload(gps))).toBe('gps_time_without_skew');
    const tz = flagged.slice(); new DataView(tz.buffer).setInt16(8, 18 * 60 + 1);        // a range error only the re-encode would see
    expect(ruleOf(() => decodePayload(tz))).toBe('noncanonical');
    const zero = flagged.slice(); zero.fill(0, 23, 31);                                  // phash 0: canonical, decodes with the flag
    const d = decodePayload(zero); expect(d.fields.noFingerprint).toBe(true); expect(d.fields.phash).toBe(0n);
    expect(encodeHeader(d.fields, d.recoveryBit)).toEqual(zero.slice(0, 39));
    expect(decodePayload(b).fields.noFingerprint).toBe(false);
  });
  it('encodeHeader sets 0x80 for NO_FINGERPRINT and refuses it with a fingerprint', () => {
    const d = decodePayload(Uint8Array.from(Buffer.from(CASE0, 'base64url')));
    expect(encodeHeader({ ...d.fields, phash: 0n, noFingerprint: true }, 0)[2] & 0x80).toBe(0x80);
    expect(encodeHeader({ ...d.fields, phash: 0n, noFingerprint: false }, 0)[2] & 0x80).toBe(0);
    expect(ruleOf(() => encodeHeader({ ...d.fields, noFingerprint: true }, 0))).toBe('noncanonical');
  });
  // The explicit P26 rule on its own: parseV1 is decode before the canonical re-encode compare, so the re-encode (and encodeHeader's own
  // refusal) cannot reject these bytes first. Only the rule after the GPS sentinel can.
  it('the decode step before the re-encode compare rejects NO_FINGERPRINT with a fingerprint by itself', () => {
    const b = Uint8Array.from(Buffer.from(CASE0, 'base64url')); const flagged = b.slice(); flagged[2] |= 0x80;
    expect(ruleOf(() => parseV1(flagged))).toBe('noncanonical');
    const zero = flagged.slice(); zero.fill(0, 23, 31);
    expect(parseV1(zero).fields).toMatchObject({ noFingerprint: true, phash: 0n });
    expect(parseV1(b).fields.noFingerprint).toBe(false);
    const gps = flagged.slice(); new DataView(gps.buffer).setInt16(21, -32768); expect(ruleOf(() => parseV1(gps))).toBe('gps_time_without_skew');
  });
});
