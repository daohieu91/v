import { describe, expect, it } from 'vitest';
import { hasC2pa, fitPow2, jpegSize, MAX_FILE_BYTES } from '../src/image';
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
