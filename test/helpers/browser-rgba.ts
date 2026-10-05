/**
 * SHA-256 of the RGBA that Chromium AND Firefox produce for these fixtures (createImageBitmap + canvas, the page's path). The same pins
 * are re-measured in real browsers by e2e/level1.spec.ts, so they are not just whatever node produced. jpeg-js (the old verify-file
 * decoder) gives different pixels on both, and up to +10 bits of distance on the Task 10B corpus.
 */
export const BROWSER_RGBA: Record<string, string> = {
  'sealed_1600_q70.jpg': '7f4ebe2cc1ca69b0bcc65cb4771e6523b29f3a255d3bc2bc5136d844afbb357e',   // carries an sRGB ICC profile
  'dark_sealed.jpg': '692bf19dac7043bb9b73f385985a9af1209eb39a9fa3fead67d68864984c03ee',
};
