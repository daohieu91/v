/** Files above this are refused with a friendly message: a 12–50 MP phone JPEG is 3–25 MB, and every decode is bounded by it. */
export const MAX_FILE_BYTES = 40 * 1024 * 1024;
/** Longest side handed to QR + fingerprint. A 12 MP photo (4000 × 3000) passes unscaled, so the fingerprint sees the app's own pixels. */
export const MAX_SIDE = 4096;
export type Rgba = { data: Uint8ClampedArray; w: number; h: number };

/**
 * Size after the fewest exact halvings (W div 2ⁿ, H div 2ⁿ) that bring the longest side to ≤ max. Exact halvings keep the fingerprint's
 * own halving chain (PerceptualHash halves while the longest side is > 1024) on the same geometry as the app, which hashes at full size.
 */
export function fitPow2(w: number, h: number, max: number): { w: number; h: number } {
  let n = 0; while (Math.max(w >> n, h >> n) > max) n++;
  return { w: Math.max(1, w >> n), h: Math.max(1, h >> n) };
}

type Source = { src: CanvasImageSource; w: number; h: number; close: () => void };
/** Width and height from a JPEG's SOF marker, or null. Lets a large photo be decoded straight at its bounded size. Never throws. */
export function jpegSize(b: Uint8Array): { w: number; h: number } | null {
  if (b[0] !== 0xff || b[1] !== 0xd8) return null;
  for (let i = 2; i + 9 <= b.length && b[i] === 0xff;) { const m = b[i + 1], len = (b[i + 2] << 8) | b[i + 3];
    if (m >= 0xc0 && m <= 0xcf && m !== 0xc4 && m !== 0xc8 && m !== 0xcc) return { h: (b[i + 5] << 8) | b[i + 6], w: (b[i + 7] << 8) | b[i + 8] };
    if (m === 0xda || len < 2) return null; i += 2 + len; }
  return null;
}
/**
 * Above 4096 px the browser is asked to decode at the bounded size (resizeWidth/Height), so a 50 MP photo never becomes a 200 MB bitmap.
 * If the result is not exactly that size (an EXIF-rotated photo swaps the axes; an engine ignores the hint), it falls back to a plain decode.
 */
async function bitmap(f: Blob): Promise<Source | null> {
  if (typeof createImageBitmap !== 'function') return null;
  const sz = jpegSize(new Uint8Array(await f.slice(0, 256 * 1024).arrayBuffer()));
  const fit = sz ? fitPow2(sz.w, sz.h, MAX_SIDE) : null;
  const opts: (ImageBitmapOptions | undefined)[] = [{ imageOrientation: 'from-image' }, undefined];
  if (sz && fit && fit.w !== sz.w) opts.unshift({ imageOrientation: 'from-image', resizeWidth: fit.w, resizeHeight: fit.h, resizeQuality: 'high' });
  for (const opt of opts) {
    try { const b = await (opt ? createImageBitmap(f, opt) : createImageBitmap(f));
      if (opt?.resizeWidth && (b.width !== fit!.w || b.height !== fit!.h)) { b.close(); continue; }
      return { src: b, w: opt?.resizeWidth ? sz!.w : b.width, h: opt?.resizeHeight ? sz!.h : b.height, close: () => b.close() }; }
    catch { /* an older engine rejects the option, or cannot decode a Blob: try the next way */ }
  }
  return null;
}
async function decode(f: Blob): Promise<Source> {
  const b = await bitmap(f); if (b) return b;
  const url = URL.createObjectURL(f);
  try { const img = new Image(); img.src = url; await img.decode(); return { src: img, w: img.naturalWidth, h: img.naturalHeight, close: () => { img.src = ''; } }; }
  finally { URL.revokeObjectURL(url); }
}
type Canvas2D = { width: number; height: number; getContext(t: '2d', o?: CanvasRenderingContext2DSettings): unknown };
function draw(s: Source, maxSide: number, make: (w: number, h: number) => Canvas2D): Rgba {
  const { w, h } = fitPow2(s.w, s.h, maxSide); const c = make(w, h);
  try {
    const g = c.getContext('2d', { willReadFrequently: true }) as CanvasRenderingContext2D | null; if (!g) throw new Error('canvas');
    g.imageSmoothingEnabled = true; g.imageSmoothingQuality = 'high'; g.drawImage(s.src, 0, 0, w, h);
    s.close();
    return { data: g.getImageData(0, 0, w, h).data, w, h };
  } finally { s.close(); c.width = 0; c.height = 0; }                     // release the canvas backing store now, not at GC
}

/** Decodes with the browser (EXIF orientation applied) and scales so the longest side ≤ maxSide, by exact halvings. The bitmap is closed at once. */
export async function fileToRgba(f: Blob, maxSide: number = MAX_SIDE): Promise<Rgba> {
  const s = await decode(f);
  return draw(s, maxSide, (w, h) => { const c = document.createElement('canvas'); c.width = w; c.height = h; return c; });
}
/** The same decode inside a Worker (OffscreenCanvas), so a 12 MP photo costs the page's main thread nothing; null where unsupported. */
export async function fileToRgbaOffscreen(f: Blob, maxSide: number = MAX_SIDE): Promise<Rgba | null> {
  if (typeof OffscreenCanvas !== 'function') return null;
  try { if (!new OffscreenCanvas(1, 1).getContext('2d')) return null; } catch { return null; }
  const s = await bitmap(f); if (!s) return null;
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
