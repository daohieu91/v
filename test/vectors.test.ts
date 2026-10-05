import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { TEXTURE_FLOOR, THRESHOLDS, URL_PREFIX } from '../src/config';
import { MAX_FRAGMENT_LEN, PayloadError, b64urlDecode, b64urlEncode, decodeFragment, decodePayload, encodeHeader, payloadFromUrl, sealIdentity } from '../src/payload';
import { checkSeal, keyIdOf, recoverPublicKey, recoverRaw } from '../src/crypto';
import { TABLE, fingerprintRgba, hamming, phashHex, phashRgba } from '../src/phash';
import { decodePng } from './helpers/png';
import { GEN } from './helpers/gen';

const RAW = readFileSync('test/vectors/verify-vectors.json');
const V = JSON.parse(RAW.toString('utf8'));
const hex = (b: Uint8Array) => [...b].map(x => x.toString(16).padStart(2, '0')).join('');
const unhex = (s: string) => (s === '' ? new Uint8Array() : Uint8Array.from(s.match(/../g)!.map(x => parseInt(x, 16))));
const sha = (b: Uint8Array) => createHash('sha256').update(b).digest('hex');
/** The key that signed exactly the RECEIVED header bytes (recovery bit cleared): what a verifier without the canonical rule would trust. */
const signedOver = (b: Uint8Array) => { const msg = b.slice(0, 41); msg[2] &= ~0x40;
  return recoverRaw(msg, BigInt('0x' + hex(b.slice(41, 73))), BigInt('0x' + hex(b.slice(73, 105))), ((b[2] >> 6) & 1) as 0 | 1); };
const ruleOf = (f: () => unknown): string => {
  try { f(); } catch (e) { if (e instanceof PayloadError) return e.rule; throw e; }
  return 'ACCEPTED';
};
type P = { name: string; bytesHex: string; base64url: string; url: string; expectKeyId: string | null; recoveryBit: number; tamper?: string; fields: any };
const PAY: P[] = V.payloads;
const byName = (n: string) => PAY.find(x => x.name === n)!;
/** Step 7 (P26): every pHash entry pins its texture and its flat flag (texture < textureFloor); the hash stays the raw Step 6 hash. */
const expectFingerprint = (e: { name: string; phash: string; texture: number; noFingerprint: boolean }, rgba: ArrayLike<number>, w: number, h: number, frame: [number, number, number, number]) => {
  const fp = fingerprintRgba(rgba, w, h, frame);
  expect(phashHex(fp.hash), e.name).toBe(e.phash); expect(fp.texture, e.name).toBe(e.texture); expect(fp.flat, e.name).toBe(e.noFingerprint);
  expect(typeof e.texture === 'number' && typeof e.noFingerprint === 'boolean', e.name).toBe(true);
  expect(e.noFingerprint, e.name).toBe(e.texture < V.textureFloor);
  expect(phashRgba(rgba, w, h, frame), e.name).toBe(fp.hash);
};

describe('golden vectors (shared with the Android app; one bit off fails both sides)', () => {
  it('the copy matches its recorded SHA-256 (same .sha256 file as the app)', () => {
    const rec = readFileSync('test/vectors/verify-vectors.json.sha256', 'utf8');
    expect(rec).toMatch(/^[0-9a-f]{64}  verify-vectors\.json\n$/);
    expect(sha(RAW)).toBe(rec.slice(0, 64));
  });
  it('constants', () => {
    expect(V.schema).toBe(1); expect(V.urlPrefix).toBe(URL_PREFIX); expect([...THRESHOLDS]).toEqual(V.thresholds);
    expect(V.maxFragmentLength).toBe(MAX_FRAGMENT_LEN);
    expect(TABLE.map(r => [...r])).toEqual(V.table);
    expect(V.textureFloor).toBe(262144); expect(TEXTURE_FLOOR).toBe(V.textureFloor);
  });
  it('perceptual hash of every inline image', () => {
    expect(V.images.length).toBeGreaterThan(0);
    for (const im of V.images) {
      const rgba = Uint8Array.from(Buffer.from(im.rgbaB64, 'base64'));
      expect(rgba, im.name).toEqual(GEN[im.gen](im.w, im.h, im.seed));
      expectFingerprint(im, rgba, im.w, im.h, im.frame);
    }
  });
  it('PNG fixtures: file pin, decoded RGBA pin, perceptual hash', () => {
    expect(V.phashFixtures.length).toBeGreaterThan(0);
    for (const fx of V.phashFixtures) {
      const file = readFileSync('test/vectors/' + fx.file);
      expect(sha(file), fx.name).toBe(fx.fileSha256);
      const png = decodePng(file);
      expect(png.chunks.filter(c => !['IHDR', 'IDAT', 'IEND'].includes(c)), fx.name).toEqual([]);
      expect([png.w, png.h], fx.name).toEqual([fx.w, fx.h]);
      expect(sha(png.rgba), fx.name).toBe(fx.rgbaSha256);
      if (fx.source === 'synth') expect(png.rgba, fx.name).toEqual(GEN.synth(fx.w, fx.h, Number(/_s(\d+)/.exec(fx.name)![1])));
      expectFingerprint(fx, png.rgba, png.w, png.h, fx.frame);
    }
  });
  it('generated images: every halving count, odd sizes, dilation and degenerate cases', () => {
    expect(V.phashGenerated.length).toBeGreaterThan(0);
    for (const g of V.phashGenerated) { expect(GEN[g.gen], g.gen).toBeTypeOf('function'); expectFingerprint(g, GEN[g.gen](g.w, g.h, g.seed), g.w, g.h, g.frame); }
    expect(Object.keys(GEN).sort()).toEqual(Object.keys(V.generators).sort());
    // The floor pair (P26): 511 lit cells sit one below the floor, 512 exactly on it (not flat: the comparison is strict).
    const at = (n: string) => V.phashGenerated.find((g: { name: string }) => g.name === n);
    expect(at('cells_640x640_s511_dark_below_floor')).toMatchObject({ texture: TEXTURE_FLOOR - 1, noFingerprint: true });
    expect(at('cells_640x640_s512_dark_at_floor')).toMatchObject({ texture: TEXTURE_FLOOR, noFingerprint: false });
  }, 120_000);
  it('payload decode, base64url, key recovery and key tag', () => {
    expect(PAY.length).toBeGreaterThan(0);
    for (const p of PAY) {
      const bytes = unhex(p.bytesHex);
      expect(b64urlEncode(bytes), p.name).toBe(p.base64url); expect(b64urlDecode(p.base64url), p.name).toEqual(bytes);
      expect(p.url).toBe(URL_PREFIX + p.base64url);
      const d = decodePayload(bytes);                      // every payload vector is canonical: it must decode
      expect(hex(encodeHeader(d.fields, d.recoveryBit)), p.name).toBe(p.bytesHex.slice(0, 82));
      expect(bytes.length, p.name).toBe(105); expect(p.url.length, p.name).toBe(171);
      expect(payloadFromUrl(p.url), p.name).toEqual(d);
      const s = checkSeal(d);
      if (p.expectKeyId === null) { expect(p.tamper, p.name).toBeTruthy(); expect(s, p.name).toEqual({ ok: false, keyIdHex: null }); continue; }
      expect(s.ok, p.name).toBe(true); expect(s.keyIdHex).toBe(p.expectKeyId); expect(s.keyIdHex).toBe(V.testKey.keyId);
      expect(s.keyIdHex).toHaveLength(16);                 // the full 8-byte key id (P18 e)
      expect(hex(recoverPublicKey(d)!)).toBe(V.testKey.publicKey);
      expect(d.recoveryBit, p.name).toBe(p.recoveryBit);
      const f = p.fields;
      expect(d.fields.epochSeconds).toBe(f.epochSeconds); expect(d.fields.tzOffsetMinutes).toBe(f.tzOffsetMinutes);
      expect(d.fields.location).toEqual(f.location); expect(d.fields.autoTime).toBe(f.autoTime);
      expect(d.fields.clockSkewSeconds).toBe(f.clockSkewSeconds); expect(d.fields.softwareKey).toBe(f.softwareKey);
      expect(phashHex(d.fields.phash)).toBe(f.phash); expect([...d.fields.frame]).toEqual(f.frame); expect(d.fields.keyTag).toBe(f.keyTag);
      expect(typeof f.noFingerprint, p.name).toBe('boolean'); expect(d.fields.noFingerprint, p.name).toBe(f.noFingerprint);
      expect(d.fields.aspect, p.name).toBe(f.aspect); expect(d.fields.locationWithheld, p.name).toBe(f.locationWithheld);
      expect(typeof f.locationWithheld, p.name).toBe('boolean'); expect(Number.isInteger(f.aspect) && f.aspect >= 1, p.name).toBe(true);
    }
  });
  it('NO_FINGERPRINT (P26): flag bit 7 (0x80 of byte 2) with phash 0 verifies; clearing the flag loses the key', () => {
    const c7 = byName('v1_case7'); const b = unhex(c7.bytesHex);
    expect(b[2] & 0x80).toBe(0x80); expect(c7.fields).toMatchObject({ noFingerprint: true, phash: '0000000000000000' });
    const d = decodePayload(b);
    expect(d.fields.noFingerprint).toBe(true); expect(d.fields.phash).toBe(0n); expect(checkSeal(d)).toEqual({ ok: true, keyIdHex: V.testKey.keyId });
    const t = byName('v1_tampered_no_fingerprint_cleared'); expect(t.tamper).toBe('flag_no_fingerprint');
    const td = decodePayload(unhex(t.bytesHex)); expect(td.fields.noFingerprint).toBe(false); expect(checkSeal(td)).toEqual({ ok: false, keyIdHex: null });
    expect(PAY.filter(p => p.fields?.noFingerprint === false).length).toBeGreaterThan(0);
  });
  it('NO_FINGERPRINT with a fingerprint is non-canonical, even when the test key really signed it', () => {
    const r = V.rejects.find((x: { name: string }) => x.name === 'nc_no_fingerprint_with_phash_validly_signed');
    expect(r.signedDespiteRule).toBe(true);
    const b = unhex(r.bytesHex); expect(b[2] & 0x80).toBe(0x80); expect(b.slice(23, 31).some(x => x !== 0)).toBe(true);
    expect(ruleOf(() => decodePayload(b))).toBe('noncanonical');
    // With the rule skipped it would verify: the signature covers exactly these header bytes (recovery bit cleared) under the test key.
    expect(hex(signedOver(b)!)).toBe(V.testKey.publicKey);
    expect(ruleOf(() => decodePayload(unhex(V.rejects.find((x: { name: string }) => x.name === 'nc_no_fingerprint_flag_with_phash').bytesHex)))).toBe('noncanonical');
    // Bit 7 is no longer reserved: the reserved-bit reject moved to bit 9 (0x02 of byte 1).
    const names = V.rejects.map((x: { name: string }) => x.name);
    expect(names).toContain('nc_reserved_flag_bit9'); expect(names).not.toContain('nc_reserved_flag_bit7');
    expect(unhex(V.rejects.find((x: { name: string }) => x.name === 'nc_reserved_flag_bit9').bytesHex)[1]).toBe(0x02);
  });
  it('LOCATION_WITHHELD (P42): flag bit 8 (0x01 of byte 1), no location, zero location bytes; clearing it loses the key', () => {
    const c8 = byName('v1_case8'); const b = unhex(c8.bytesHex);
    expect(b[1] & 0x01).toBe(0x01); expect(b[2] & 0x01).toBe(0); expect([...b.slice(10, 21)].every(x => x === 0)).toBe(true);
    const d = decodePayload(b);
    expect(d.fields.locationWithheld).toBe(true); expect(d.fields.location).toBeNull(); expect(checkSeal(d)).toEqual({ ok: true, keyIdHex: V.testKey.keyId });
    const t = byName('v1_tampered_location_withheld_cleared'); expect(t.tamper).toBe('flag_location_withheld');
    const td = decodePayload(unhex(t.bytesHex)); expect(td.fields.locationWithheld).toBe(false); expect(checkSeal(td)).toEqual({ ok: false, keyIdHex: null });
    // Every no-location payload (withheld or never fixed) has lat, lng, accuracy and age all 0 (accuracy used to be 65535).
    for (const p of PAY.filter(x => x.fields && x.fields.location === null)) expect([...unhex(p.bytesHex).slice(10, 21)].every(x => x === 0), p.name).toBe(true);
  });
  it('aspect (P41b): u16 BE at header bytes 39–40, signed', () => {
    for (const p of PAY.filter(x => x.fields)) { const b = unhex(p.bytesHex); expect((b[39] << 8) | b[40], p.name).toBe(p.fields.aspect); }
    const t = byName('v1_tampered_aspect'); expect(t.tamper).toBe('aspect');
    expect(checkSeal(decodePayload(unhex(t.bytesHex)))).toEqual({ ok: false, keyIdHex: null });
  });
  it('every signedDespiteRule reject really verifies over its received header bytes, and is still rejected', () => {
    const sd = V.rejects.filter((r: { signedDespiteRule?: boolean }) => r.signedDespiteRule);
    expect(sd.map((r: { name: string }) => r.name).sort()).toEqual(['nc_aspect_zero_validly_signed', 'nc_lat_with_withheld_validly_signed',
      'nc_no_fingerprint_with_phash_validly_signed', 'nc_withheld_with_location_validly_signed']);
    for (const r of sd) {
      const b = unhex(r.bytesHex); expect(hex(signedOver(b)!), r.name).toBe(V.testKey.publicKey);
      expect(ruleOf(() => decodePayload(b)), r.name).toBe('noncanonical');
    }
  });
  it('every reject fails with the same rule as the app, as a fragment, a URL and as bytes', () => {
    expect(V.rejects.length).toBeGreaterThan(0);
    for (const r of V.rejects) {
      expect(ruleOf(() => decodeFragment(r.fragment)), r.name).toBe(r.fragmentRule ?? r.rule);
      expect(payloadFromUrl(URL_PREFIX + r.fragment), r.name).toBeNull();
      if (r.bytesHex !== undefined) {
        expect(b64urlEncode(unhex(r.bytesHex)), r.name).toBe(r.fragment);
        expect(ruleOf(() => decodePayload(unhex(r.bytesHex))), r.name).toBe(r.rule);
      }
    }
    expect(new Set(V.rejects.map((r: { rule: string }) => r.rule))).toEqual(new Set(['noncanonical', 'gps_time_without_skew', 'signature_range',
      'inverted_frame', 'version', 'length', 'empty', 'base64url_pad_bits', 'base64url_length', 'base64url_char', 'fragment_too_long']));
  });
  it('hamming', () => { for (const h of V.hamming) expect(hamming(BigInt('0x' + h.a), BigInt('0x' + h.b))).toBe(h.d); });
  // Spike item 4 / preflight F-M5: the Android Keystore emits high-S about half the time. The app normalises (Task 5), but the page must
  // not depend on it: v1_high_s is (r, n − s) with the recovery bit flipped — a valid signature that must verify, with the same key.
  it('a high-S payload recovers the same key', () => {
    const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
    const d = decodePayload(unhex(byName('v1_high_s').bytesHex));
    expect(BigInt('0x' + hex(d.signature.slice(32))) > N / 2n).toBe(true);
    expect(checkSeal(d)).toEqual({ ok: true, keyIdHex: V.testKey.keyId });
    expect(hex(recoverPublicKey(d)!)).toBe(V.testKey.publicKey);
  });
  it('identity is header + r: the s-twin is the same seal, a different seal is not (P18 a)', () => {
    const c0 = decodePayload(unhex(byName('v1_case0').bytesHex)); const hs = decodePayload(unhex(byName('v1_high_s').bytesHex));
    expect(hex(c0.signature)).not.toBe(hex(hs.signature));
    expect(sealIdentity(hs)).toBe(sealIdentity(c0));
    expect(sealIdentity(decodePayload(unhex(byName('v1_case1').bytesHex)))).not.toBe(sealIdentity(c0));
    expect(sealIdentity(decodePayload(unhex(byName('v1_tampered_r').bytesHex)))).not.toBe(sealIdentity(c0));
  });
  it('the signed cases carry both recovery bits', () => {
    expect(new Set(PAY.filter(x => x.name.startsWith('v1_case')).map(x => x.recoveryBit))).toEqual(new Set([0, 1]));
  });
  it('key id is SHA-256 of the uncompressed point, first 8 bytes; key tag is its first 4 bytes as int32', () => {
    expect(hex(keyIdOf(unhex(V.testKey.publicKey)))).toBe(V.testKey.keyId);
    expect(new DataView(unhex(V.testKey.keyId).buffer).getInt32(0)).toBe(V.testKey.keyTag);
  });
});
