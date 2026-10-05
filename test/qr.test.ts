import jpeg from 'jpeg-js';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { findSeal, findSealUrl, scanPlan, type Img } from '../src/qr';
import { analyze } from '../src/analyze';
import { payloadFromUrl } from '../src/payload';
import { checkSeal } from '../src/crypto';
import { FLAT_MISMATCH_TEXTURE } from '../src/config';
const V = JSON.parse(readFileSync('test/vectors/verify-vectors.json', 'utf8'));
const load = (f: string): Img => { const j = jpeg.decode(readFileSync(`e2e/fixtures/${f}`), { useTArray: true, formatAsRGBA: true });
  return { data: Uint8ClampedArray.from(j.data), w: j.width, h: j.height }; };
const fixtureUrl = 'https://daohieu91.github.io/v/#';
describe('QR detection (P22: several scales before "no code")', () => {
  it('reads the seal URL from every fixture that keeps its QR', () => {
    for (const f of ['sealed.jpg', 'sealed_1600_q70.jpg', 'copied_qr.jpg', 'edited.jpg', 'cropped.jpg']) expect(findSealUrl(load(f)), f).toMatch(new RegExp('^' + fixtureUrl.replace(/[.#/]/g, '\\$&')));
  });
  it('finds nothing when the QR was cropped away', () => expect(findSealUrl(load('cropped_no_qr.jpg'))).toBeNull());
  it('plans: full image, ~1600 and ~1000 px wide, the bottom-right stamp crop, then the whole bottom band', () => {
    const p = scanPlan(4000, 3000);
    expect(p.map(s => s.kind)).toEqual(['full', 'scale', 'scale', 'corner', 'band']);
    expect(p[1].w).toBe(1600); expect(p[2].w).toBe(1000);
    expect(p[3]).toMatchObject({ x0: 2200, y0: 1500, w: 1800, h: 1500 }); expect(p[4]).toMatchObject({ x0: 0, y0: 1500, w: 4000, h: 1500 });
    expect(scanPlan(1200, 900).map(s => s.kind)).toEqual(['full', 'scale', 'corner', 'band']);   // never upscales
  });
  it('tries each later scale when the earlier ones miss', () => {
    const im: Img = { data: new Uint8ClampedArray(4000 * 3000 * 4), w: 4000, h: 3000 };
    for (let k = 0; k < 5; k++) { const seen: string[] = [];
      const r = findSealUrl(im, (x) => { seen.push(`${x.w}x${x.h}`); return seen.length === k + 1 ? { url: 'HIT', finders: null } : null; });
      expect(r, `step ${k}`).toBe('HIT'); expect(seen.length).toBe(k + 1); }
    const seen: string[] = []; expect(findSealUrl(im, (x) => { seen.push(`${x.w}x${x.h}`); return null; })).toBeNull();
    expect(seen).toEqual(['4000x3000', '1600x1200', '1000x750', '1800x1500', '4000x1500']);
  });
});
describe('finder points for P41 are in the full picture\'s pixels, whichever step read the QR', () => {
  it('maps a scale step back by the scale, a crop step by its origin', () => {
    const im: Img = { data: new Uint8ClampedArray(4000 * 3000 * 4), w: 4000, h: 3000 };
    const f = { tl: { x: 10, y: 20 }, tr: { x: 110, y: 20 }, bl: { x: 10, y: 120 } };
    const at = (k: number) => { let n = 0; return findSeal(im, () => (n++ === k ? { url: 'HIT', finders: f } : null))!.finders!; };
    expect(at(0).tl).toEqual({ x: 10, y: 20 });                                           // full
    expect(at(1).tr).toEqual({ x: 110 * 2.5, y: 20 * 2.5 });                              // 1600 × 1200: × 2.5
    expect(at(2).bl).toEqual({ x: 10 * 4, y: 120 * 4 });                                  // 1000 × 750: × 4
    expect(at(3).tl).toEqual({ x: 10 + 2200, y: 20 + 1500 });                              // the bottom-right corner crop
    expect(at(4).tl).toEqual({ x: 10, y: 20 + 1500 });                                    // the bottom band
  });
  it('the real fixture read at a downscaled step lands where the full-size read does', () => {
    const im = load('sealed.jpg'); const full = findSeal(im)!.finders!;
    let n = 0; const viaScale = findSeal(im, x => (n++ === 0 ? null : findSeal(x)))!.finders!;   // skip the full step: the 1600-px copy reads it
    expect(Math.abs(viaScale.tl.x - full.tl.x)).toBeLessThan(2); expect(Math.abs(viaScale.tl.y - full.tl.y)).toBeLessThan(2);
  });
});
describe('analyze (the worker body)', () => {
  it('sealed photo: URL found and fingerprint distance 0', () => {
    const r = analyze(load('sealed.jpg')); const p = payloadFromUrl(r.url!)!;
    expect(checkSeal(p).keyIdHex).toBe(V.payloads[0].expectKeyId); expect(r.hamming).toBe(0); });
  it('chat-compressed photo still matches; the copied QR does not', () => {
    expect(analyze(load('sealed_1600_q70.jpg')).hamming).toBeLessThanOrEqual(8); expect(analyze(load('copied_qr.jpg')).hamming).toBeGreaterThan(16); });
  it('a picture with no code: no URL, no distance', () => expect(analyze(load('cropped_no_qr.jpg'))).toEqual({ url: null, hamming: null, texture: null, qrInPicture: false, geometry: null }));
  it('NO_FINGERPRINT seal (P26/P28): no distance, only the texture of the picture', () => {
    const dark = analyze(load('dark_sealed.jpg')), bright = analyze(load('bright_sealed.jpg'));
    const c7 = V.payloads.find((p: { name: string }) => p.name === 'v1_case7');
    expect(dark.url).toBe(c7.url); expect(bright.url).toBe(c7.url);
    expect(dark.hamming).toBeNull(); expect(bright.hamming).toBeNull();
    expect(dark.texture).toBeLessThanOrEqual(FLAT_MISMATCH_TEXTURE); expect(bright.texture).toBeGreaterThan(FLAT_MISMATCH_TEXTURE);
    expect(analyze(load('sealed.jpg')).texture).toBeNull();
  });
});
