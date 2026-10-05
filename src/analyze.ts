import { URL_PREFIX } from './config';
import { payloadFromUrl } from './payload';
import { fingerprintRgba, hamming } from './phash';
import { findSealUrl, type Img } from './qr';
/** `hamming`: distance to the sealed hash; `texture`: Step 7 of this picture, only for a NO_FINGERPRINT seal (which has no hash, P28). */
export interface Analysis { url: string | null; hamming: number | null; texture: number | null }
/**
 * The heavy part of a pick (runs in the Web Worker): find the QR, then the fingerprint distance of this picture to the sealed one.
 * `fallbackFragment` (the page's #fragment, when the QR was scanned with a camera) is used when the picture's own QR is unreadable.
 * The fingerprint gets the decoded pixels at full size (≤ 4096 px): its own integer halvings then match the app's (P19, F-M9).
 * It returns no verdict: the colour is decided on the page from checkSeal alone. A NO_FINGERPRINT seal (P26) gets no distance, only the
 * texture of this picture (P28).
 */
export function analyze(im: Img, fallbackFragment: string | null = null): Analysis {
  const url = findSealUrl(im) ?? (fallbackFragment ? URL_PREFIX + fallbackFragment : null);
  if (!url) return { url: null, hamming: null, texture: null };
  const p = payloadFromUrl(url);
  if (!p) return { url, hamming: null, texture: null };
  const fp = fingerprintRgba(im.data, im.w, im.h, p.fields.frame);
  return p.fields.noFingerprint ? { url, hamming: null, texture: fp.texture } : { url, hamming: hamming(fp.hash, p.fields.phash), texture: null };
}
