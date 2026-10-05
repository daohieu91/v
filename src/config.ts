/** Permanent (spec §2.2): every printed QR points here. Identical to the app's VerifyConfig.VERIFY_URL_PREFIX (the vectors test enforces it). */
export const URL_PREFIX = 'https://daohieu91.github.io/v/#';
/**
 * Hamming bands: match ≤ 8, maybe ≤ 16, changed above. Identical to VerifyConfig.PHASH_MATCH_MAX / PHASH_MAYBE_MAX
 * (ruling P21, provisional until Task 10B; the vectors test enforces equality with the app).
 */
export const THRESHOLDS = [8, 16] as const;
export const PACKAGE_NAME = 'com.essenty.camerastamp';
/**
 * SHA-256 of the APK signing certificate(s) accepted as "the real app" in level 2.
 * DEV entries are the debug key used by releaseSmoke builds (acceptance on the M20); Part 4 replaces them with the Play
 * App Signing certificate digest from Play Console before launch (Task 23 records this as an open item).
 */
export const SIGNING_DIGESTS: readonly { hex: string; dev: boolean }[] = [
  { hex: '6dcef54931f170eff8e8d53bd77e62ec66c078479a6141411d08b00287077602', dev: true },
];
export const PLAY_URL = 'https://play.google.com/store/apps/details?id=com.essenty.camerastamp&referrer=utm_source%3Dverify';
