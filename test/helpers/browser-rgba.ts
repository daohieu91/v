/**
 * SHA-256 of the RGBA that Chromium AND Firefox produce for these fixtures (createImageBitmap + canvas, the page's path). The same pins
 * are re-measured in real browsers by e2e/level1.spec.ts, so they are not just whatever node produced. jpeg-js (the old verify-file
 * decoder) gives different pixels on both, and up to +10 bits of distance on the Task 10B corpus.
 */
export const BROWSER_RGBA: Record<string, string> = {
  'sealed_1600_q70.jpg': 'c2f322de4ab0a613c56d6aa4b771ef7006dda6db8d242bb1b9990258c5acf53c',   // carries an sRGB ICC profile
  'dark_sealed.jpg': '688b8ff4d514ffc6ddb4706f2f8b22cb03dd41189616f8910877234b625d99fb',
};
