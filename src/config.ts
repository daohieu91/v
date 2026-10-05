/** Permanent (spec §2.2): every printed QR points here. Identical to the app's VerifyConfig.VERIFY_URL_PREFIX (the vectors test enforces it). */
export const URL_PREFIX = 'https://daohieu91.github.io/v/#';
/**
 * Hamming bands: match ≤ 8, maybe ≤ 16, changed above. Identical to VerifyConfig.PHASH_MATCH_MAX / PHASH_MAYBE_MAX
 * (ruling P21, confirmed on real M20 photos in Task 10B; the vectors test enforces equality with the app).
 */
export const THRESHOLDS = [8, 16] as const;
/**
 * PROVISIONAL (ruling P28): PerceptualHash Step 7 floor, 2¹⁸ (a cell standard deviation of 0.5 luma). Below it the app seals with
 * NO_FINGERPRINT and phash 0 (P26). Calibrated in Task 10C on one phone (Galaxy M20) only; the vectors test enforces equality with the app.
 */
export const TEXTURE_FLOOR = 262144;
/**
 * P28: a NO_FINGERPRINT seal was made for a dark/flat photo. A received picture whose texture is above 8 × TEXTURE_FLOOR (2 097 152)
 * cannot be that photo, so the page shows red; at or below it the photo is "too dark/flat to compare" (yellow). Never a hash compare.
 */
export const FLAT_MISMATCH_TEXTURE = 8 * TEXTURE_FLOOR;
export const PACKAGE_NAME = 'com.essenty.camerastamp';
/**
 * SHA-256 of the APK signing certificate(s) accepted as "the real app" in level 2.
 * DEV entries are the debug key used by releaseSmoke builds (acceptance on the M20); Part 4 replaces them with the Play
 * App Signing certificate digest from Play Console before launch (Task 23 records this as an open item).
 */
export const SIGNING_DIGESTS: readonly { hex: string; dev: boolean }[] = [];
// P36: the debug key's digest (6dcef549…7602, releaseSmoke builds) is NOT deployed: a debug-signed file reads "app signature not yet
// registered". Tests inject digests. Part 4 adds the Play App Signing digest here as { hex, dev: false }.
/** Videos are checked by level 2 only (C2PA, read by slices): a 30 s FHD clip from the app is ~50–60 MB (12S-c). Photos keep image.ts's 40 MB. */
export const MAX_VIDEO_BYTES = 100 * 1024 * 1024;
export const PLAY_URL = 'https://play.google.com/store/apps/details?id=com.essenty.camerastamp&referrer=utm_source%3Dverify';
