// Test-only PNG decoder (node:zlib), independent of the app's javax.imageio and the Python tools' Pillow: 8-bit RGB / RGBA,
// non-interlaced, all five filter types. Output is RGBA with alpha 255 for RGB input (the vectors' rgbaSha256 convention).
import { inflateSync } from 'node:zlib';

export interface Png { w: number; h: number; rgba: Uint8Array; chunks: string[] }

export function decodePng(buf: Uint8Array): Png {
  const sig = [137, 80, 78, 71, 13, 10, 26, 10];
  if (!sig.every((b, i) => buf[i] === b)) throw new Error('not a PNG');
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  let o = 8; let w = 0, h = 0, depth = 0, ctype = 0, interlace = 0; const idat: Uint8Array[] = []; const chunks: string[] = [];
  while (o < buf.length) {
    const len = dv.getUint32(o); const type = String.fromCharCode(...buf.subarray(o + 4, o + 8)); const data = buf.subarray(o + 8, o + 8 + len);
    chunks.push(type);
    if (type === 'IHDR') { w = dv.getUint32(o + 8); h = dv.getUint32(o + 12); depth = data[8]; ctype = data[9]; interlace = data[12]; }
    else if (type === 'IDAT') idat.push(data);
    else if (type === 'IEND') break;
    o += 12 + len;
  }
  if (depth !== 8 || (ctype !== 2 && ctype !== 6) || interlace !== 0) throw new Error(`unsupported PNG ${depth}/${ctype}/${interlace}`);
  const bpp = ctype === 2 ? 3 : 4; const stride = w * bpp;
  const raw = inflateSync(Buffer.concat(idat));
  if (raw.length !== h * (stride + 1)) throw new Error('bad IDAT size');
  const cur = new Uint8Array(stride); const prev = new Uint8Array(stride); const rgba = new Uint8Array(w * h * 4);
  for (let y = 0; y < h; y++) {
    const f = raw[y * (stride + 1)]; const line = raw.subarray(y * (stride + 1) + 1, (y + 1) * (stride + 1));
    for (let i = 0; i < stride; i++) {
      const a = i >= bpp ? cur[i - bpp] : 0; const b = prev[i]; const c = i >= bpp ? prev[i - bpp] : 0; const x = line[i];
      let v: number;
      switch (f) {
        case 0: v = x; break;
        case 1: v = x + a; break;
        case 2: v = x + b; break;
        case 3: v = x + ((a + b) >> 1); break;
        case 4: { const p = a + b - c; const pa = Math.abs(p - a), pb = Math.abs(p - b), pc = Math.abs(p - c);
          v = x + (pa <= pb && pa <= pc ? a : pb <= pc ? b : c); break; }
        default: throw new Error('bad filter ' + f);
      }
      cur[i] = v & 255;
    }
    for (let x = 0; x < w; x++) {
      const d = (y * w + x) * 4; const s = x * bpp;
      rgba[d] = cur[s]; rgba[d + 1] = cur[s + 1]; rgba[d + 2] = cur[s + 2]; rgba[d + 3] = bpp === 4 ? cur[s + 3] : 255;
    }
    prev.set(cur);
  }
  return { w, h, rgba, chunks };
}
