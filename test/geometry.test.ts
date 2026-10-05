import { readFileSync } from 'node:fs';
import sharp from 'sharp';
import { describe, expect, it } from 'vitest';
import { analyze, type Analysis } from '../src/analyze';
import { checkSeal } from '../src/crypto';
import { ASPECT_TOL, GEOMETRY_TOL, aspectOf, checkGeometry, model, qrLeftPx, qrResidual, qrSidePx } from '../src/geometry';
import { payloadFromUrl } from '../src/payload';
import { findSeal } from '../src/qr';
import { verdict } from '../src/verdict';
// P41 + P41b. sealed.jpg is the APP's own fixture (docs/verify/fixtures: StampLayout + QrRenderer, 2000 × 1500); flat_sealed.jpg is
// scripts/make-crop-fixtures.ts' low-texture photo (the ❌1d class: crops keep its fingerprint distance ≤ 14).
type Im = { data: Uint8ClampedArray; w: number; h: number };
const decode = async (b: Buffer | string): Promise<Im> => { const { data, info } = await sharp(b).rotate().ensureAlpha().raw().toBuffer({ resolveWithObject: true });
  return { data: new Uint8ClampedArray(data.buffer, data.byteOffset, data.length), w: info.width, h: info.height }; };
const jpegOf = (src: string, o: { crop?: { left: number; top: number; width: number; height: number }; resize?: number; q?: number }) => {
  let s = sharp(src); if (o.crop) s = s.extract(o.crop); if (o.resize) s = s.resize(o.resize); return s.jpeg({ quality: o.q ?? 92 }).toBuffer(); };
const pick = (r: Analysis) => { const p = payloadFromUrl(r.url!)!;
  return verdict({ payload: p, seal: checkSeal(p), hamming: r.hamming, texture: r.texture, level2: null, picture: { qr: r.qrInPicture, geometry: r.geometry } }); };
const FLAT = 'e2e/fixtures/flat_sealed.jpg', SEALED = 'e2e/fixtures/sealed.jpg';
const SIDES = ['top', 'bottom', 'left', 'right'] as const;
const cropBox = (W: number, H: number, side: typeof SIDES[number], pct: number) => { const dx = side === 'left' || side === 'right' ? Math.round((W * pct) / 100) : 0;
  const dy = side === 'top' || side === 'bottom' ? Math.round((H * pct) / 100) : 0; return { left: side === 'left' ? dx : 0, top: side === 'top' ? dy : 0, width: W - dx, height: H - dy }; };

describe('QR sizing and placement: a port of StampLayout.kt / QrRenderer.kt', () => {
  it('qrSidePx and the QR\'s left edge equal the app\'s Float arithmetic on 1 200+ sizes (scripts/QrSideTable.java, a literal Java transcription)', () => {
    const T = JSON.parse(readFileSync('test/fixtures/geometry/qrside-java.json', 'utf8')) as [number, number, number, number][];
    expect(T.length).toBeGreaterThan(1200);
    for (const [w, h, side, left] of T) { expect(qrSidePx(w, h), `${w}x${h}`).toBe(side); expect(qrLeftPx(w, side), `${w}x${h} left`).toBe(left); }
    // The app's own unit-test values (StampLayoutQrTest), P27/P27a.
    expect([qrSidePx(3000, 4000), qrSidePx(2448, 3264), qrSidePx(1080, 1440), qrSidePx(4000, 3000), qrSidePx(750, 563)]).toEqual([549, 427, 183, 610, 183]);
  });
  it('aspect = round(w / h × 10000), clamped to 1..65535 (SealFields.aspectOf)', () => {
    expect([aspectOf(4000, 3000), aspectOf(3000, 4000), aspectOf(1920, 1080), aspectOf(1, 1), aspectOf(7, 1), aspectOf(1, 20001), aspectOf(2, 3)])
      .toEqual([13333, 7500, 17778, 10000, 65535, 1, 6667]);
  });
  it('predicts where the app put the QR on its own fixture (finder centres within half a pixel)', async () => {
    const im = await decode(SEALED); const hit = findSeal(im)!; const p = payloadFromUrl(hit.url)!;
    const m = model(im.w, im.h, p.fields.frame[1])!; const c = m.cell;
    expect(Math.abs(hit.finders!.tl.x - (m.symX + 3.5 * c))).toBeLessThanOrEqual(0.5);
    expect(hit.finders!.tl.y).toBeGreaterThanOrEqual(m.symYlo + 3.5 * c - 0.5); expect(hit.finders!.tl.y).toBeLessThanOrEqual(m.symYhi + 3.5 * c + 0.5);
    expect(Math.abs(hit.finders!.tr.x - hit.finders!.tl.x - 46 * c)).toBeLessThanOrEqual(0.5);
    expect(p.fields.aspect).toBe(aspectOf(im.w, im.h));
    expect(qrResidual(hit.finders!, im.w, im.h, p.fields.frame[1], p.fields.aspect)).toBeLessThan(0.1);
  });
});

describe('crop detection (P41 / P41b): resized shares pass, crops never read green', () => {
  it('unedited and resized-only copies are unaffected: geometry ok, the verdict stays green', async () => {
    for (const src of [SEALED, FLAT]) for (const o of [{}, { resize: 1600, q: 75 }, { resize: 1280, q: 70 }, { resize: 1000, q: 65 }]) {
      const r = analyze(await decode(await jpegOf(src, o)));
      expect(r.geometry, `${src} ${JSON.stringify(o)}`).toBe('ok'); expect(pick(r).color, `${src} ${JSON.stringify(o)}`).toBe('green');
    }
  }, 60_000);
  it('3, 5 and 10 % off any one side: yellow "may have been cropped" (or no QR left: never green, with the link at most yellow)', async () => {
    const im0 = await decode(FLAT); const frag = analyze(im0).url!.split('#')[1]; const table: string[] = [];
    for (const pct of [3, 5, 10]) for (const side of SIDES) {
      const im = await decode(await jpegOf(FLAT, { crop: cropBox(im0.w, im0.h, side, pct) }));
      const bare = analyze(im), link = analyze(im, frag);
      table.push(`${side} ${pct}%: ${bare.qrInPicture ? `d=${bare.hamming} ${pick(bare).headline}` : `QR cut, link d=${link.hamming} ${pick(link).headline}`}`);
      if (bare.qrInPicture) {
        expect(bare.geometry, `${side} ${pct}%`).toBe('mismatch');
        expect([pick(bare).color, pick(bare).headline], `${side} ${pct}%`).toEqual(['yellow', 'verdict_maybe_cropped']);
        expect(pick(bare).checks.map(c => c.key)).toContain('check_geometry_mismatch');
        // Non-vacuous: the fingerprint alone would not have said red (and, in the match band, would have said green: the ❌1d bug).
        expect(bare.hamming!, `${side} ${pct}%`).toBeLessThanOrEqual(16);
        if (bare.hamming! <= 8) expect(pick({ ...bare, geometry: 'ok' }).color).toBe('green');
      } else {
        expect(bare.url, 'a cut QR leaves no code on the bare page').toBeNull();
        expect(link.qrInPicture).toBe(false); expect(pick(link).color, `${side} ${pct}% + link`).not.toBe('green');
      }
    }
    expect(table.filter(l => l.includes('verdict_maybe_cropped')).length, table.join('\n')).toBe(10);
  }, 120_000);
  it('the ❌1d case: 10 % off the top keeps a matching fingerprint, and is yellow, not green', async () => {
    const r = analyze(await decode('e2e/fixtures/flat_crop_top10.jpg'));
    expect(r.hamming).toBeLessThanOrEqual(8); expect(r.geometry).toBe('mismatch');
    expect(pick(r).headline).toBe('verdict_maybe_cropped'); expect(pick(r).checks.map(c => c.key)).not.toContain('proves_l1');
  });
  it('a crop proportional on both axes keeps the aspect, but the QR no longer fits: caught by the QR geometry alone', async () => {
    const im0 = await decode(FLAT);
    for (const pct of [5, 10]) {
      const dx = Math.round((im0.w * pct) / 100), dy = Math.round((im0.h * pct) / 100);
      const im = await decode(await jpegOf(FLAT, { crop: { left: dx, top: dy, width: im0.w - dx, height: im0.h - dy }, resize: 1600, q: 80 }));
      const hit = findSeal(im)!; const p = payloadFromUrl(hit.url)!;
      const g = checkGeometry(p.fields, hit.finders, im.w, im.h);
      expect(g.aspectDelta!, `${pct}%`).toBeLessThanOrEqual(ASPECT_TOL); expect(g.residual!, `${pct}%`).toBeGreaterThan(GEOMETRY_TOL); expect(g.kind).toBe('mismatch');
    }
  }, 60_000);
  it('the aspect alone catches a one-axis crop when the QR gives no geometry (finders unknown)', () => {
    const sealed = { frame: [4, 182, 251, 250], aspect: 13333 };
    expect(checkGeometry(sealed, null, 2000, 1500).kind).toBe('unknown');
    expect(checkGeometry(sealed, null, 1600, 1200).kind).toBe('unknown');
    for (const [w, h] of [[2000, 1455], [1940, 1500], [1600, 1176]]) expect(checkGeometry(sealed, null, w, h).kind, `${w}x${h}`).toBe('mismatch');
  });
  it('a tilted, skewed or rotated QR (a photo of a screen, a rotated copy) makes no geometry claim', () => {
    const f = { tl: { x: 100, y: 100 }, tr: { x: 330, y: 100 }, bl: { x: 100, y: 330 } };
    expect(qrResidual(f, 2000, 1500, 182, 13333)).not.toBeNull();
    expect(qrResidual({ ...f, tr: { x: 330, y: 130 } }, 2000, 1500, 182, 13333)).toBeNull();          // tilted ~7°
    expect(qrResidual({ ...f, bl: { x: 100, y: 380 } }, 2000, 1500, 182, 13333)).toBeNull();          // skewed: modules differ > 3 %
    expect(qrResidual({ tl: f.tr, tr: f.tl, bl: { x: 330, y: 330 } }, 2000, 1500, 182, 13333)).toBeNull();   // mirrored
  });
});
