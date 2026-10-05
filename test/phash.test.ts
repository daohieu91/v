import { describe, expect, it } from 'vitest';
import { TEXTURE_FLOOR } from '../src/config';
import { fingerprintRgba, phashRgba } from '../src/phash';
import { cells, flat, noise } from './helpers/gen';
/** A 32 × 32 grey image whose 1024 cells are exactly `v` (no halving, no mask): Step 7 sees `v` itself. */
const grey = (v: (i: number) => number) => { const o = new Uint8Array(1024 * 4);
  for (let i = 0; i < 1024; i++) { o[4 * i] = o[4 * i + 1] = o[4 * i + 2] = v(i); o[4 * i + 3] = 255; } return o; };
const NONE = [0, 0, 0, 0] as const;
describe('Step 7 texture (P26, PerceptualHash KDoc)', () => {
  it('is 1024·Σs² − (Σs)² over the 1024 cells, exact', () => {
    expect(fingerprintRgba(grey(i => (i % 2 ? 2 : 0)), 32, 32, NONE).texture).toBe(1024 * 2048 - 1024 * 1024);          // 1 048 576
    expect(fingerprintRgba(grey(i => (i < 3 ? 1 : 0)), 32, 32, NONE).texture).toBe(1024 * 3 - 9);                       // 3063
    // The largest possible value (a 0/255 checkerboard of cells) is still an exact integer: below 2³⁶, no BigInt needed.
    const max = fingerprintRgba(grey(i => (i % 2 ? 255 : 0)), 32, 32, NONE).texture;
    expect(max).toBe(1024 * 512 * 255 * 255 - (512 * 255) ** 2); expect(max).toBeLessThan(2 ** 36); expect(Number.isSafeInteger(max)).toBe(true);
  });
  it('is measured after the mask fill: a masked bright stamp adds nothing', () => {
    const im = grey(() => 0); for (let i = 26 * 32; i < 1024; i++) im[4 * i] = im[4 * i + 1] = im[4 * i + 2] = 255;   // bottom 6 rows white
    expect(fingerprintRgba(im, 32, 32, NONE).texture).toBeGreaterThan(0);
    expect(fingerprintRgba(im, 32, 32, [0, 207, 255, 255]).texture).toBe(0);      // rows 26..31 masked → filled with the outside mean 0
  });
  it('a flat colour, a fully masked image and a degenerate image have texture 0', () => {
    expect(fingerprintRgba(flat(300, 200, 0xff102030 | 0), 300, 200, NONE)).toEqual({ hash: 0n, texture: 0, flat: true });
    expect(fingerprintRgba(noise(64, 64, 7), 64, 64, [0, 0, 255, 255]).texture).toBe(0);
    expect(fingerprintRgba(noise(31, 64, 7), 31, 64, NONE)).toEqual({ hash: 0n, texture: 0, flat: true });
  });
  it('flat is strictly below the floor', () => {
    expect(fingerprintRgba(cells(640, 640, 511), 640, 640, NONE)).toMatchObject({ texture: TEXTURE_FLOOR - 1, flat: true });
    expect(fingerprintRgba(cells(640, 640, 512), 640, 640, NONE)).toMatchObject({ texture: TEXTURE_FLOOR, flat: false });
  });
  it('phashRgba is the hash of the same pass', () => {
    const im = noise(1500, 1100, 3); expect(phashRgba(im, 1500, 1100, [4, 202, 252, 255])).toBe(fingerprintRgba(im, 1500, 1100, [4, 202, 252, 255]).hash);
  });
});
