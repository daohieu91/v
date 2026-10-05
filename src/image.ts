/** Files above this are refused with a friendly message: a 12–50 MP phone JPEG is 3–25 MB, and every decode is bounded by it. */
export const MAX_FILE_BYTES = 40 * 1024 * 1024;
/** Longest side handed to QR + fingerprint. A 12 MP photo (4000 × 3000) passes unscaled, so the fingerprint sees the app's own pixels. */
export const MAX_SIDE = 4096;
export type Rgba = { data: Uint8ClampedArray; w: number; h: number; via?: 'plain' | 'resize' };

/**
 * Size after the fewest exact halvings (W div 2ⁿ, H div 2ⁿ) that bring the longest side to ≤ max. Exact halvings keep the fingerprint's
 * own halving chain (PerceptualHash halves while the longest side is > 1024) on the same geometry as the app, which hashes at full size.
 */
export function fitPow2(w: number, h: number, max: number): { w: number; h: number } {
  let n = 0; while (Math.max(w >> n, h >> n) > max) n++;
  return { w: Math.max(1, w >> n), h: Math.max(1, h >> n) };
}

/** Above this many pixels a picture is never decoded at full size (a 4096 × 4096 bitmap is 64 MB). */
export const MAX_FULL_DECODE_PX = MAX_SIDE * MAX_SIDE;
/** A file whose size cannot be read from its header is decoded only when it is this small (then it cannot hide a huge bitmap cheaply). */
export const UNKNOWN_DIMS_MAX_BYTES = 6 * 1024 * 1024;
export class TooLargeImage extends Error { constructor() { super('too_large'); this.name = 'TooLargeImage'; } }

export type Dims = { w: number; h: number; orientation: number };
const u16 = (b: Uint8Array, i: number, le = false) => (le ? b[i] | (b[i + 1] << 8) : (b[i] << 8) | b[i + 1]);
const u32 = (b: Uint8Array, i: number, le = false) => (le ? (b[i] | (b[i + 1] << 8) | (b[i + 2] << 16)) + b[i + 3] * 2 ** 24 : b[i] * 2 ** 24 + ((b[i + 1] << 16) | (b[i + 2] << 8) | b[i + 3]));
const tag = (b: Uint8Array, i: number, t: string) => i + t.length <= b.length && [...t].every((c, k) => b[i + k] === c.charCodeAt(0));

/** EXIF orientation (1–8) from an APP1 "Exif" body starting at `i`; 1 when absent or malformed. */
function exifOrientation(b: Uint8Array, i: number, end: number): number {
  if (!tag(b, i, 'Exif\0\0')) return 1;
  const t = i + 6; if (t + 8 > end) return 1; const le = b[t] === 0x49;
  if (!(le ? tag(b, t, 'II') : tag(b, t, 'MM'))) return 1;
  const ifd = t + u32(b, t + 4, le); if (ifd + 2 > end) return 1;
  const n = u16(b, ifd, le);
  for (let k = 0; k < n; k++) { const e = ifd + 2 + 12 * k; if (e + 12 > end) return 1;
    if (u16(b, e, le) === 0x0112) { const o = u16(b, e + 8, le); return o >= 1 && o <= 8 ? o : 1; } }
  return 1;
}
/** Width, height (as stored) and EXIF orientation of a JPEG, or null. Never throws. */
export function jpegInfo(b: Uint8Array): Dims | null {
  if (b[0] !== 0xff || b[1] !== 0xd8) return null;
  let orientation = 1;
  for (let i = 2; i + 9 <= b.length && b[i] === 0xff;) { const m = b[i + 1], len = (b[i + 2] << 8) | b[i + 3];
    if (m === 0xe1 && orientation === 1) orientation = exifOrientation(b, i + 4, Math.min(b.length, i + 2 + len));
    if (m >= 0xc0 && m <= 0xcf && m !== 0xc4 && m !== 0xc8 && m !== 0xcc) return { h: (b[i + 5] << 8) | b[i + 6], w: (b[i + 7] << 8) | b[i + 8], orientation };
    if (m === 0xda || len < 2) return null; i += 2 + len; }
  return null;
}
export const jpegSize = (b: Uint8Array) => { const d = jpegInfo(b); return d ? { w: d.w, h: d.h } : null; };
/**
 * Pixel size from the header of a JPEG, PNG, WebP, GIF, BMP or HEIF/AVIF file (the largest `ispe`: tiles and thumbnails are smaller than
 * the primary image), or null when unknown. Never throws.
 */
export function imageDims(b: Uint8Array): Dims | null {
  try {
    const j = jpegInfo(b); if (j) return j;
    const d = (w: number, h: number): Dims | null => (w > 0 && h > 0 ? { w, h, orientation: 1 } : null);
    if (tag(b, 0, '\x89PNG') && tag(b, 12, 'IHDR')) return d(u32(b, 16), u32(b, 20));
    if (tag(b, 0, 'GIF8')) return d(u16(b, 6, true), u16(b, 8, true));
    if (tag(b, 0, 'BM') && b.length >= 26) return d(u32(b, 18, true), Math.abs(new DataView(b.buffer, b.byteOffset).getInt32(22, true)));
    if (tag(b, 0, 'RIFF') && tag(b, 8, 'WEBP')) {
      if (tag(b, 12, 'VP8X')) return d(1 + (b[24] | (b[25] << 8) | (b[26] << 16)), 1 + (b[27] | (b[28] << 8) | (b[29] << 16)));
      if (tag(b, 12, 'VP8L')) { const v = u32(b, 21, true); return d(1 + (v & 0x3fff), 1 + ((v >>> 14) & 0x3fff)); }
      if (tag(b, 12, 'VP8 ')) return d(u16(b, 26, true) & 0x3fff, u16(b, 28, true) & 0x3fff);
      return null;
    }
    if (tag(b, 4, 'ftyp')) { let best: Dims | null = null;
      for (let i = 0; i + 20 <= b.length; i++) if (b[i] === 0x69 && tag(b, i, 'ispe')) { const w = u32(b, i + 8), h = u32(b, i + 12);
        if (w > 0 && h > 0 && (!best || w * h > best.w * best.h)) best = { w, h, orientation: 1 }; }
      return best; }
    return null;
  } catch { return null; }
}

export type Plan = { kind: 'plain' } | { kind: 'resize'; w: number; h: number } | { kind: 'refuse' };
/**
 * How to decode, from the header alone (pure): small enough → as is; larger → ask the browser for the bounded size directly (the
 * target is computed on the DISPLAYED axes: EXIF orientations 5–8 swap width and height); size unknown → only a small file.
 */
export function decodePlan(dims: Dims | null, bytes: number): Plan {
  if (!dims) return bytes <= UNKNOWN_DIMS_MAX_BYTES ? { kind: 'plain' } : { kind: 'refuse' };
  const swap = dims.orientation >= 5; const ow = swap ? dims.h : dims.w, oh = swap ? dims.w : dims.h;
  const t = fitPow2(ow, oh, MAX_SIDE);
  if (t.w === ow && t.h === oh && ow * oh <= MAX_FULL_DECODE_PX) return { kind: 'plain' };
  return { kind: 'resize', w: t.w, h: t.h };
}

type Source = { src: CanvasImageSource; w: number; h: number; close: () => void; via: 'plain' | 'resize' };
/**
 * Decodes per the plan. A resize asks for the displayed target first, then the swapped request (an engine that resizes before applying
 * EXIF orientation); the result is accepted only at exactly the target size, never distorted, and NEVER falls back to a full decode.
 */
export async function bitmap(f: Blob, plan: Plan): Promise<Source | null> {
  if (plan.kind === 'refuse') throw new TooLargeImage();
  if (typeof createImageBitmap !== 'function') { if (plan.kind === 'resize') throw new TooLargeImage(); return null; }
  const wrap = (b: ImageBitmap, via: Source['via']): Source => ({ src: b, w: b.width, h: b.height, close: () => b.close(), via });
  if (plan.kind === 'resize') {
    for (const [rw, rh] of [[plan.w, plan.h], [plan.h, plan.w]]) {
      try { const b = await createImageBitmap(f, { imageOrientation: 'from-image', resizeWidth: rw, resizeHeight: rh, resizeQuality: 'high' });
        if (b.width === plan.w && b.height === plan.h) return wrap(b, 'resize'); b.close(); }
      catch { /* the engine rejects resize options or this request: try the other, then refuse */ }
    }
    throw new TooLargeImage();
  }
  for (const opt of [{ imageOrientation: 'from-image' } as ImageBitmapOptions, undefined]) {
    try { return wrap(await (opt ? createImageBitmap(f, opt) : createImageBitmap(f)), 'plain'); }
    catch { /* an older engine rejects the option, or cannot decode a Blob: try the next way */ }
  }
  return null;
}
const planOf = async (f: Blob) => decodePlan(imageDims(new Uint8Array(await f.slice(0, 512 * 1024).arrayBuffer())), f.size);
async function decode(f: Blob): Promise<Source> {
  const plan = await planOf(f);
  const b = await bitmap(f, plan); if (b) return b;
  const url = URL.createObjectURL(f);                                       // only for a 'plain' plan (bounded by the header check)
  try { const img = new Image(); img.src = url; await img.decode(); return { src: img, w: img.naturalWidth, h: img.naturalHeight, close: () => { img.src = ''; }, via: 'plain' }; }
  finally { URL.revokeObjectURL(url); }
}
type Canvas2D = { width: number; height: number; getContext(t: '2d', o?: CanvasRenderingContext2DSettings): unknown };
function draw(s: Source, maxSide: number, make: (w: number, h: number) => Canvas2D): Rgba {
  const { w, h } = fitPow2(s.w, s.h, maxSide); const c = make(w, h);
  try {
    const g = c.getContext('2d', { willReadFrequently: true }) as CanvasRenderingContext2D | null; if (!g) throw new Error('canvas');
    g.imageSmoothingEnabled = true; g.imageSmoothingQuality = 'high'; g.drawImage(s.src, 0, 0, w, h);
    s.close();
    return { data: g.getImageData(0, 0, w, h).data, w, h, via: s.via };
  } finally { s.close(); c.width = 0; c.height = 0; }                     // release the canvas backing store now, not at GC
}

/** Decodes with the browser (EXIF orientation applied), bounded by the header plan, then ≤ maxSide by exact halvings. */
export async function fileToRgba(f: Blob, maxSide: number = MAX_SIDE): Promise<Rgba> {
  const s = await decode(f);
  return draw(s, maxSide, (w, h) => { const c = document.createElement('canvas'); c.width = w; c.height = h; return c; });
}
/** The same decode inside a Worker (OffscreenCanvas), so a 12 MP photo costs the page's main thread nothing; null where unsupported. */
export async function fileToRgbaOffscreen(f: Blob, maxSide: number = MAX_SIDE): Promise<Rgba | null> {
  if (typeof OffscreenCanvas !== 'function') return null;
  try { if (!new OffscreenCanvas(1, 1).getContext('2d')) return null; } catch { return null; }
  const s = await bitmap(f, await planOf(f)); if (!s) return null;
  return draw(s, maxSide, (w, h) => new OffscreenCanvas(w, h) as unknown as Canvas2D);
}

/** JPEG APP11 JUMBF ("JP" + "jumb") or the MP4 C2PA uuid box: cheap enough to run on every pick, so level 2 loads only when useful. Never throws. */
export function hasC2pa(b: Uint8Array): boolean {
  const s = (i: number, t: string) => i + t.length <= b.length && [...t].every((ch, k) => b[i + k] === ch.charCodeAt(0));
  if (b[0] === 0xff && b[1] === 0xd8) {
    let i = 2;
    while (i + 4 <= b.length && b[i] === 0xff) { const m = b[i + 1], len = (b[i + 2] << 8) | b[i + 3];
      if (m === 0xeb && s(i + 4, 'JP')) return true; if (m === 0xda || len < 2) break; i += 2 + len; }
    return false;
  }
  const uuid = [0xd8, 0xfe, 0xc3, 0xd6, 0x1b, 0x0e, 0x48, 0x3c, 0x92, 0x97, 0x58, 0x28, 0x87, 0x7e, 0xc4, 0x81];
  for (let i = 0; i + 24 <= b.length;) { const size = b[i] * 2 ** 24 + (b[i + 1] << 16) + (b[i + 2] << 8) + b[i + 3];
    if (s(i + 4, 'uuid') && uuid.every((x, k) => b[i + 8 + k] === x)) return true; if (size < 8) break; i += size; }
  return false;
}

/** hasC2pa on a File without reading it all: the JPEG head (APP segments come first), or the MP4 top-level box headers only. */
export async function sniffC2pa(f: Blob): Promise<boolean> {
  const at = async (o: number, n: number) => new Uint8Array(await f.slice(o, Math.min(f.size, o + n)).arrayBuffer());
  const head = await at(0, 4 * 1024 * 1024);
  if (head[0] === 0xff && head[1] === 0xd8) return hasC2pa(head);
  for (let o = 0, k = 0; o + 24 <= f.size && k < 256; k++) {
    const h = await at(o, 32); const v = new DataView(h.buffer, h.byteOffset, h.byteLength);
    let size = v.getUint32(0); const hdr = size === 1 ? 16 : 8;
    if (size === 1) size = v.getUint32(8) * 2 ** 32 + v.getUint32(12); else if (size === 0) size = f.size - o;
    if (hasC2pa(hdr === 8 ? h.subarray(0, 24) : new Uint8Array([0, 0, 0, 24, ...h.subarray(4, 8), ...h.subarray(16, 32)]))) return true;
    if (size < hdr) return false; o += size;
  }
  return false;
}
