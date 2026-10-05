import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { THRESHOLDS, URL_PREFIX } from '../src/config';
import { MAX_FRAGMENT_LEN, PayloadError, b64urlDecode, b64urlEncode, decodeFragment, decodePayload, encodeHeader, payloadFromUrl, sealIdentity } from '../src/payload';
import { checkSeal, keyIdOf, recoverPublicKey } from '../src/crypto';
import { TABLE, hamming, phashHex, phashRgba } from '../src/phash';
import { decodePng } from './helpers/png';
import { GEN } from './helpers/gen';

const RAW = readFileSync('test/vectors/verify-vectors.json');
const V = JSON.parse(RAW.toString('utf8'));
const hex = (b: Uint8Array) => [...b].map(x => x.toString(16).padStart(2, '0')).join('');
const unhex = (s: string) => (s === '' ? new Uint8Array() : Uint8Array.from(s.match(/../g)!.map(x => parseInt(x, 16))));
const sha = (b: Uint8Array) => createHash('sha256').update(b).digest('hex');
const ruleOf = (f: () => unknown): string => {
  try { f(); } catch (e) { if (e instanceof PayloadError) return e.rule; throw e; }
  return 'ACCEPTED';
};
type P = { name: string; bytesHex: string; base64url: string; url: string; expectKeyId: string | null; recoveryBit: number; tamper?: string; fields: any };
const PAY: P[] = V.payloads;
const byName = (n: string) => PAY.find(x => x.name === n)!;

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
  });
  it('perceptual hash of every inline image', () => {
    expect(V.images.length).toBeGreaterThan(0);
    for (const im of V.images) {
      const rgba = Uint8Array.from(Buffer.from(im.rgbaB64, 'base64'));
      expect(rgba, im.name).toEqual(GEN[im.gen](im.w, im.h, im.seed));
      expect(phashHex(phashRgba(rgba, im.w, im.h, im.frame)), im.name).toBe(im.phash);
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
      expect(phashHex(phashRgba(png.rgba, png.w, png.h, fx.frame)), fx.name).toBe(fx.phash);
    }
  });
  it('generated images: every halving count, odd sizes, dilation and degenerate cases', () => {
    expect(V.phashGenerated.length).toBeGreaterThan(0);
    for (const g of V.phashGenerated) expect(phashHex(phashRgba(GEN[g.gen](g.w, g.h, g.seed), g.w, g.h, g.frame)), g.name).toBe(g.phash);
  }, 120_000);
  it('payload decode, base64url, key recovery and key tag', () => {
    expect(PAY.length).toBeGreaterThan(0);
    for (const p of PAY) {
      const bytes = unhex(p.bytesHex);
      expect(b64urlEncode(bytes), p.name).toBe(p.base64url); expect(b64urlDecode(p.base64url), p.name).toEqual(bytes);
      expect(p.url).toBe(URL_PREFIX + p.base64url);
      const d = decodePayload(bytes);                      // every payload vector is canonical: it must decode
      expect(hex(encodeHeader(d.fields, d.recoveryBit)), p.name).toBe(p.bytesHex.slice(0, 78));
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
