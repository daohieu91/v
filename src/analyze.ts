import { URL_PREFIX } from './config';
import { checkGeometry } from './geometry';
import { payloadFromUrl } from './payload';
import { fingerprintRgba, hamming } from './phash';
import { findSeal, type Img } from './qr';
export type Geometry = 'ok' | 'mismatch' | 'unknown';
/**
 * `hamming`: distance to the sealed hash; `texture`: Step 7 of this picture, only for a NO_FINGERPRINT seal (which has no hash, P28).
 * `qrInPicture`: the seal came from this picture's own QR (false: from the page's link only, I4). `geometry` (P41/P41b): this picture's
 * aspect and QR placement against the signed aspect and frame; null when no seal was decoded.
 */
export interface Analysis { url: string | null; hamming: number | null; texture: number | null; qrInPicture: boolean; geometry: Geometry | null }
/**
 * The heavy part of a pick (runs in the Web Worker): find the QR, then the fingerprint distance of this picture to the sealed one.
 * `fallbackFragment` (the page's #fragment, when the QR was scanned with a camera) is used when the picture's own QR is unreadable;
 * `qrInPicture` then says so, and the page never shows green for it.
 * The fingerprint gets the decoded pixels at full size (≤ 4096 px): its own integer halvings then match the app's (P19, F-M9).
 * It returns no verdict: the colour is decided on the page from checkSeal alone. A NO_FINGERPRINT seal (P26) gets no distance, only the
 * texture of this picture (P28).
 */
export function analyze(im: Img, fallbackFragment: string | null = null): Analysis {
  const hit = findSeal(im);
  const url = hit?.url ?? (fallbackFragment ? URL_PREFIX + fallbackFragment : null);
  const qrInPicture = !!hit;
  if (!url) return { url: null, hamming: null, texture: null, qrInPicture, geometry: null };
  const p = payloadFromUrl(url);
  if (!p) return { url, hamming: null, texture: null, qrInPicture, geometry: null };
  const geometry = checkGeometry(p.fields, hit?.finders ?? null, im.w, im.h).kind;
  const fp = fingerprintRgba(im.data, im.w, im.h, p.fields.frame);
  return p.fields.noFingerprint ? { url, hamming: null, texture: fp.texture, qrInPicture, geometry }
    : { url, hamming: hamming(fp.hash, p.fields.phash), texture: null, qrInPicture, geometry };
}
