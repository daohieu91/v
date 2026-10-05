import { describe, expect, it } from 'vitest';
import { bitmap, decodePlan, fitPow2, hasC2pa, imageDims, jpegSize, MAX_FILE_BYTES, TooLargeImage, UnsupportedImage } from '../src/image';
const jpg = (...segs: number[][]) => new Uint8Array([0xff, 0xd8, ...segs.flat(), 0xff, 0xda, 0, 2]);
const seg = (m: number, body: number[]) => [0xff, m, (body.length + 2) >> 8, (body.length + 2) & 255, ...body];
const ascii = (s: string) => [...s].map(c => c.charCodeAt(0));
describe('image helpers', () => {
  it('finds a JUMBF APP11 segment after other APP segments', () => {
    expect(hasC2pa(jpg(seg(0xe0, ascii('JFIF\0')), seg(0xeb, ascii('JP\0\0jumb'))))).toBe(true);
    expect(hasC2pa(jpg(seg(0xe0, ascii('JFIF\0')), seg(0xeb, ascii('XX'))))).toBe(false);
    expect(hasC2pa(jpg(seg(0xe0, ascii('JFIF\0'))))).toBe(false);
  });
  it('finds the C2PA uuid box in an MP4', () => {
    const box = (t: string, body: number[]) => { const n = 8 + body.length; return [n >>> 24, (n >> 16) & 255, (n >> 8) & 255, n & 255, ...ascii(t), ...body]; };
    const uuid = [0xd8, 0xfe, 0xc3, 0xd6, 0x1b, 0x0e, 0x48, 0x3c, 0x92, 0x97, 0x58, 0x28, 0x87, 0x7e, 0xc4, 0x81];
    expect(hasC2pa(new Uint8Array([...box('ftyp', ascii('isom0000')), ...box('uuid', [...uuid, 0, 0, 0, 0])]))).toBe(true);
    expect(hasC2pa(new Uint8Array([...box('ftyp', ascii('isom0000')), ...box('free', new Array(24).fill(0))]))).toBe(false);
  });
  it('never throws on garbage', () => { for (let n = 0; n < 64; n++) expect(typeof hasC2pa(new Uint8Array(n).fill(0xff))).toBe('boolean'); });
  it('bounds the decode with exact halvings so the fingerprint halving chain is kept (≤ 4096 px)', () => {
    expect(fitPow2(4000, 3000, 4096)).toEqual({ w: 4000, h: 3000 });
    expect(fitPow2(8000, 6000, 4096)).toEqual({ w: 4000, h: 3000 });
    expect(fitPow2(8165, 6123, 4096)).toEqual({ w: 4082, h: 3061 });
    expect(fitPow2(16384, 1000, 4096)).toEqual({ w: 4096, h: 250 });
  });
  it('caps files at 40 MB', () => expect(MAX_FILE_BYTES).toBe(40 * 1024 * 1024));
});
describe('jpegSize', () => {
  it('reads the SOF size after APP segments, and nothing from non-JPEG', () => {
    const sof = (m: number, w: number, h: number) => [0xff, m, 0, 17, 8, h >> 8, h & 255, w >> 8, w & 255, 3, ...new Array(9).fill(0)];
    const app = [0xff, 0xe1, 0, 6, 1, 2, 3, 4];
    expect(jpegSize(new Uint8Array([0xff, 0xd8, ...app, ...sof(0xc0, 8160, 6120)]))).toEqual({ w: 8160, h: 6120 });
    expect(jpegSize(new Uint8Array([0xff, 0xd8, ...app, ...sof(0xc2, 4000, 3000)]))).toEqual({ w: 4000, h: 3000 });
    expect(jpegSize(new Uint8Array([0xff, 0xd8, 0xff, 0xc4, 0, 4, 0, 0, ...sof(0xc0, 10, 20)]))).toEqual({ w: 10, h: 20 });   // DHT is not a SOF
    expect(jpegSize(new Uint8Array([0x89, 0x50, 0x4e, 0x47]))).toBeNull();
    expect(jpegSize(new Uint8Array([0xff, 0xd8, 0xff]))).toBeNull();
  });
});
const be32 = (v: number) => [v >>> 24, (v >> 16) & 255, (v >> 8) & 255, v & 255];
const le16 = (v: number) => [v & 255, v >> 8]; const le24 = (v: number) => [v & 255, (v >> 8) & 255, (v >> 16) & 255];
const ascii2 = (s: string) => [...s].map(c => c.charCodeAt(0));
/** A JPEG head: APP1 Exif (big-endian TIFF, IFD0 with one Orientation entry) then SOF0. */
export const exifJpeg = (w: number, h: number, o: number, le = false) => {
  const s16 = (v: number) => (le ? [v & 255, v >> 8] : [v >> 8, v & 255]);
  const s32 = (v: number) => (le ? [v & 255, (v >> 8) & 255, (v >> 16) & 255, v >>> 24] : be32(v));
  const tiff = [...ascii2(le ? 'II' : 'MM'), ...s16(42), ...s32(8), ...s16(1), ...s16(0x0112), ...s16(3), ...s32(1), ...s16(o), 0, 0, ...s32(0)];
  const body = [...ascii2('Exif\0\0'), ...tiff];
  return new Uint8Array([0xff, 0xd8, 0xff, 0xe1, (body.length + 2) >> 8, (body.length + 2) & 255, ...body,
    0xff, 0xc0, 0, 17, 8, h >> 8, h & 255, w >> 8, w & 255, 3, ...new Array(9).fill(0)]);
};
describe('imageDims + decodePlan (never a full-size decode of a huge picture)', () => {
  it('reads JPEG size and EXIF orientation (both byte orders)', () => {
    expect(imageDims(exifJpeg(8000, 6000, 6))).toEqual({ w: 8000, h: 6000, orientation: 6 });
    expect(imageDims(exifJpeg(4000, 3000, 3, true))).toEqual({ w: 4000, h: 3000, orientation: 3 });
  });
  it('reads PNG, GIF, BMP, WebP (VP8, VP8L, VP8X) and HEIF/AVIF (largest ispe)', () => {
    expect(imageDims(new Uint8Array([0x89, ...ascii2('PNG\r\n\x1a\n'), 0, 0, 0, 13, ...ascii2('IHDR'), ...be32(12000), ...be32(9000)])))
      .toEqual({ w: 12000, h: 9000, orientation: 1 });
    expect(imageDims(new Uint8Array([...ascii2('GIF89a'), ...le16(640), ...le16(480)]))).toEqual({ w: 640, h: 480, orientation: 1 });
    const bmp = new Uint8Array(26); bmp.set(ascii2('BM')); new DataView(bmp.buffer).setInt32(18, 5000, true); new DataView(bmp.buffer).setInt32(22, -4000, true);
    expect(imageDims(bmp)).toEqual({ w: 5000, h: 4000, orientation: 1 });
    const riff = (chunk: string, body: number[]) => new Uint8Array([...ascii2('RIFF'), 0, 0, 0, 0, ...ascii2('WEBP'), ...ascii2(chunk), ...body]);
    expect(imageDims(riff('VP8X', [0, 0, 0, 0, 0, 0, 0, 0, ...le24(8191), ...le24(6143)]))).toEqual({ w: 8192, h: 6144, orientation: 1 });
    const l = (4999) | (2999 << 14); expect(imageDims(riff('VP8L', [0, 0, 0, 0, 0x2f, l & 255, (l >> 8) & 255, (l >> 16) & 255, l >>> 24])))
      .toEqual({ w: 5000, h: 3000, orientation: 1 });
    expect(imageDims(riff('VP8 ', [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, ...le16(4000), ...le16(3000)]))).toEqual({ w: 4000, h: 3000, orientation: 1 });
    const ispe = (w: number, h: number) => [0, 0, 0, 20, ...ascii2('ispe'), 0, 0, 0, 0, ...be32(w), ...be32(h)];
    expect(imageDims(new Uint8Array([0, 0, 0, 16, ...ascii2('ftypheic'), 0, 0, 0, 0, ...ispe(512, 512), ...ispe(8064, 6048), ...ispe(320, 240)])))
      .toEqual({ w: 8064, h: 6048, orientation: 1 });
    expect(imageDims(new Uint8Array([1, 2, 3, 4, 5]))).toBeNull();
    expect(imageDims(new Uint8Array([...ascii2('II*\0'), 8, 0, 0, 0, 0, 0]))).toBeNull();                    // TIFF: not a supported photo format
  });
  it('plans: small → as is; large → the bounded size on the DISPLAYED axes; unknown → unsupported, never decoded', () => {
    expect(decodePlan({ w: 4000, h: 3000, orientation: 1 }, 5e6)).toEqual({ kind: 'plain' });
    expect(decodePlan({ w: 8000, h: 6000, orientation: 1 }, 2e7)).toEqual({ kind: 'resize', w: 4000, h: 3000 });
    expect(decodePlan({ w: 8000, h: 6000, orientation: 6 }, 2e7)).toEqual({ kind: 'resize', w: 3000, h: 4000 });   // 50 MP portrait
    expect(decodePlan({ w: 8000, h: 6000, orientation: 8 }, 2e7)).toEqual({ kind: 'resize', w: 3000, h: 4000 });
    expect(decodePlan({ w: 12000, h: 9000, orientation: 1 }, 1e6)).toEqual({ kind: 'resize', w: 3000, h: 2250 });   // tiny but huge PNG
    expect(decodePlan(null, 1e3)).toEqual({ kind: 'unsupported' });        // no size in the header: never decoded (decompression bomb)
    expect(decodePlan(null, 30e6)).toEqual({ kind: 'unsupported' });
  });
});
describe('bounded bitmap decode (fake createImageBitmap: engines differ in resize vs EXIF order)', () => {
  const run = async (fake: (o: ImageBitmapOptions | undefined) => { width: number; height: number }) => {
    const calls: (number[] | null)[] = []; let closed = 0;
    (globalThis as any).createImageBitmap = async (_f: Blob, o?: ImageBitmapOptions) => { calls.push(o?.resizeWidth ? [o.resizeWidth, o.resizeHeight!] : null);
      return { ...fake(o), close: () => { closed++; } }; };
    try { const s = await bitmap(new Blob(['x']), { kind: 'resize', w: 4000, h: 3000 }); return { s, calls, closed }; }
    catch (e) { return { e, calls, closed }; } finally { delete (globalThis as any).createImageBitmap; }
  };
  it('orient-then-resize engine: the first request is exact', async () => {
    const r = await run(o => ({ width: o!.resizeWidth!, height: o!.resizeHeight! }));
    expect(r.s && [r.s.w, r.s.h, r.s.via]).toEqual([4000, 3000, 'resize']); expect(r.calls).toEqual([[4000, 3000]]);
  });
  it('resize-then-orient engine: the swapped request is used, the distorted one is closed', async () => {
    const r = await run(o => ({ width: o!.resizeHeight!, height: o!.resizeWidth! }));
    expect(r.s && [r.s.w, r.s.h]).toEqual([4000, 3000]); expect(r.calls).toEqual([[4000, 3000], [3000, 4000]]); expect(r.closed).toBe(1);
  });
  it('an engine that ignores the resize hint is refused, never decoded at full size', async () => {
    const r = await run(() => ({ width: 8000, height: 6000 }));
    expect(r.e).toBeInstanceOf(TooLargeImage); expect(r.calls.every(c => c !== null)).toBe(true);
  });
  it('an unsupported plan never calls the decoder', async () => {
    let called = false; (globalThis as any).createImageBitmap = async () => { called = true; };
    await expect(bitmap(new Blob(['x']), { kind: 'unsupported' })).rejects.toBeInstanceOf(UnsupportedImage); expect(called).toBe(false);
    delete (globalThis as any).createImageBitmap;
  });
  it('a refuse plan never calls the decoder', async () => {
    let called = false; (globalThis as any).createImageBitmap = async () => { called = true; };
    await expect(bitmap(new Blob(['x']), { kind: 'refuse' })).rejects.toBeInstanceOf(TooLargeImage); expect(called).toBe(false);
    delete (globalThis as any).createImageBitmap;
  });
});
