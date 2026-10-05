// The page's decode path, in node, for scripts/verify-file.ts (Task 10C web follow-up).
//
// Why not jpeg-js: it reads up to +4..6 bits higher than every browser on the same file (Task 10B, measured again here: untouched M20
// p04 → 8 vs 2 in Chromium, Firefox and WebKit). Three causes, all in its decoder: the YCbCr → RGB result is truncated into a
// Uint8Array instead of rounded (mean luma −0.5), the chroma planes are upsampled by pixel replication instead of libjpeg's "fancy"
// triangle filter, and its IDCT keeps 12 fractional bits instead of libjpeg's 13 (±1 on ~5 % of the luma samples). Chromium and
// Firefox decode with libjpeg-turbo (ISLOW IDCT, fancy upsampling); sharp's libvips decodes with the same library and settings, and
// its RGBA is byte-identical to theirs (measured on the 10B corpus; test/decode-node.test.ts pins it on a fixture).
//
// The size plan is the page's own (src/image.ts decodePlan): ≤ 4096 px is decoded as is, with EXIF orientation applied; a larger
// picture is resized to the same bounded target the page asks createImageBitmap for. That resize is NOT bit-exact with any browser,
// because the browsers disagree with each other there (Chromium vs Firefox vs WebKit ≈ 0.3 mean abs per channel); Lanczos-3 is the
// closest to Firefox and lands on the same distance as all three on the measured photos.
//
// Colour: a browser draws an sRGB-tagged (or untagged) picture onto its sRGB canvas unchanged, but libvips would run an sRGB → sRGB
// lcms transform that moves pixels by ±1 (seen on e2e/fixtures/sealed_1600_q70.jpg, which carries Google's sRGB profile). So such a
// profile is ignored; any other profile (Display P3, Adobe RGB…) is converted to sRGB, as the browsers do (not bit-exact with them).
import sharp from 'sharp';
import { decodePlan, imageDims, TooLargeImage, UnsupportedImage, type Rgba } from '../src/image';

/** The ICC profile's description (v2 'desc' or v4 'mluc'), or null. Never throws. */
export function iccDescription(icc: Uint8Array | undefined): string | null {
  try {
    if (!icc || icc.length < 132) return null; const v = new DataView(icc.buffer, icc.byteOffset, icc.byteLength);
    for (let k = 0, n = v.getUint32(128); k < n && 144 + 12 * k <= icc.length; k++) {
      const e = 132 + 12 * k; if (v.getUint32(e) !== 0x64657363) continue;               // 'desc'
      const o = v.getUint32(e + 4); const type = String.fromCharCode(...icc.subarray(o, o + 4));
      if (type === 'desc') return String.fromCharCode(...icc.subarray(o + 12, o + 12 + Math.max(0, v.getUint32(o + 8) - 1)));
      if (type === 'mluc' && v.getUint32(o + 8) > 0) { const len = v.getUint32(o + 20), at = o + v.getUint32(o + 24); let s = '';
        for (let i = 0; i + 1 < len; i += 2) s += String.fromCharCode(v.getUint16(at + i)); return s; }
      return null;
    }
    return null;
  } catch { return null; }
}

export async function decodeLikeThePage(bytes: Uint8Array): Promise<Rgba> {
  const plan = decodePlan(imageDims(bytes.subarray(0, 512 * 1024)), bytes.length);
  if (plan.kind === 'unsupported') throw new UnsupportedImage();
  if (plan.kind === 'refuse') throw new TooLargeImage();
  const icc = (await sharp(bytes).metadata()).icc; const desc = iccDescription(icc);
  const ignoreIcc = !icc || (desc !== null && /^srgb\b/i.test(desc.trim()));
  let img = sharp(bytes, { limitInputPixels: false, failOn: 'error', ignoreIcc }).rotate().toColourspace('srgb');   // EXIF orientation (as from-image); 8-bit sRGB, grey → RGB
  if (plan.kind === 'resize') img = img.resize(plan.w, plan.h, { fit: 'fill', kernel: 'lanczos3' });
  const { data, info } = await img.ensureAlpha(1).raw().toBuffer({ resolveWithObject: true });
  if (info.channels !== 4) throw new UnsupportedImage();
  if (plan.kind === 'resize' && (info.width !== plan.w || info.height !== plan.h)) throw new TooLargeImage();
  return { data: new Uint8ClampedArray(data.buffer, data.byteOffset, data.byteLength), w: info.width, h: info.height, via: plan.kind };
}
