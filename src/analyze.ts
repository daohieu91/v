import { URL_PREFIX } from './config';
import { payloadFromUrl } from './payload';
import { hamming, phashRgba } from './phash';
import { findSealUrl, type Img } from './qr';
export interface Analysis { url: string | null; hamming: number | null }
/**
 * The heavy part of a pick (runs in the Web Worker): find the QR, then the fingerprint distance of this picture to the sealed one.
 * `fallbackFragment` (the page's #fragment, when the QR was scanned with a camera) is used when the picture's own QR is unreadable.
 * The fingerprint gets the decoded pixels at full size (≤ 4096 px): its own integer halvings then match the app's (P19, F-M9).
 * It returns no verdict: the colour is decided on the page from checkSeal alone.
 */
export function analyze(im: Img, fallbackFragment: string | null = null): Analysis {
  const url = findSealUrl(im) ?? (fallbackFragment ? URL_PREFIX + fallbackFragment : null);
  if (!url) return { url: null, hamming: null };
  const p = payloadFromUrl(url);
  return { url, hamming: p ? hamming(phashRgba(im.data, im.w, im.h, p.fields.frame), p.fields.phash) : null };
}
