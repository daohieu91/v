import { FLAT_MISMATCH_TEXTURE, THRESHOLDS } from './config';
import type { SealPayload } from './payload';
export type Color = 'green' | 'yellow' | 'red';
export interface Check { key: string; status: 'pass' | 'warn' | 'fail' | 'info'; params?: Record<string, string | number> }
/** `sub`: a line under the band (M9: on a level-1-only green, whose key it was and that app and phone are not confirmed). */
export interface Verdict { color: Color; headline: string; checks: Check[]; sub?: Check }
/**
 * What the picked PICTURE said about itself (a photo pick only; null for a link alone or a video). `qr`: the seal came from the
 * picture's own QR, not the link (I4). `geometry`: P41/P41b, its aspect and QR placement against the signed ones.
 */
export interface Picture { qr: boolean; geometry: 'ok' | 'mismatch' | 'unknown' | null }
/**
 * Level 2 (the original file). `bound`: the C2PA signer key is the seal payload's key, so the file-level hard binding stands for THIS
 * seal's content (P30); the page sets it false when the picture's own QR seal is not the seal in the file (identity, P18 a).
 */
export interface L2Summary { kind: 'none' | 'invalid' | 'ok'; lines: Check[]; realDevice: boolean; bound: boolean }
/** Level-2 findings that make the file itself untrustworthy: a revoked certificate, a signer that is not the seal's/attested key, a QR of another key. */
const L2_RED = new Set(['l2_revoked', 'l2_binding_bad', 'l2_qr_other_key']);
const UNCERTIFIED = new Set(['l2_chain_bad', 'l2_no_seal']);
const DEVICE_YELLOW = new Set(['l2_boot_bad', 'l2_locked_bad', 'l2_boot_unknown']);

/**
 * Spec §6 / §7.3, honest: one line per check, nothing merged or overstated. The seal holds ONLY when checkSeal says so (`seal.ok`):
 * a recovered key alone proves nothing, since an edited payload still recovers *a* key. A level-1 green means "this picture and these
 * details are unchanged since key <id> sealed them", never "taken by the app": that needs the original file (level 2).
 *
 * NO_FINGERPRINT seals (P26, P28) carry no hash, so `hamming` is ignored for them and never makes green or red. Their picture check is the
 * received picture's Step 7 `texture`: above 8 × TEXTURE_FLOOR it cannot be the dark/flat photo that was sealed (red); at or below it
 * the photo is "too dark or flat to compare" (yellow, and never proves_l1). `texture` null = no picture compared.
 */
export function verdict(i: { payload: SealPayload | null; seal: { ok: boolean; keyIdHex: string | null } | null; hamming: number | null;
  texture: number | null; level2: L2Summary | null; picture?: Picture | null }): Verdict {
  if (!i.payload || !i.seal || i.seal.ok !== true || !i.seal.keyIdHex)   // a broken original file (e.g. a tampered video) says why
    return { color: 'red', headline: 'verdict_red', checks: i.level2?.kind === 'invalid' ? [...i.level2.lines] : [{ key: 'check_seal_bad', status: 'fail' }] };
  const f = i.payload.fields; const [a, b] = THRESHOLDS; const id = i.seal.keyIdHex;
  const checks: Check[] = [{ key: 'check_seal_ok', status: 'pass', params: { id } }];
  const flagged = f.noFingerprint === true;
  const hamming = flagged ? null : i.hamming;                             // P28: never a hash compare for a NO_FINGERPRINT seal
  const texture = flagged ? i.texture : null;
  const flatMismatch = texture !== null && texture > FLAT_MISMATCH_TEXTURE;
  // F-M13: a valid original file binds the content itself. P30: that holds for a NO_FINGERPRINT seal too — the C2PA hard binding over the
  // exact bytes proves more than any pHash, so a flagged seal whose original file passes level 2 is green (worded check_content_c2pa,
  // "the original file's content is unchanged"); P28's texture yellow is a level-1 (pixel) answer only. A picture with detail still reads
  // red: it cannot be the dark/flat photo that was sealed, whatever level 2 says.
  const c2paContent = i.level2?.kind === 'ok' && i.level2.bound === true && hamming === null && (flagged ? !flatMismatch : texture === null);
  // The original file's hard binding stands for THIS seal's exact bytes (P30): the only case where "unchanged" may be said (P44).
  const exact = i.level2?.kind === 'ok' && i.level2.bound === true && !flatMismatch;
  // I4 / P41b: a picked photo whose own QR was not read can never be green (whatever the link or the file says), at most yellow.
  const noQr = !!i.picture && !i.picture.qr;
  // P41 / P41b: the picture's shape or QR placement does not fit the seal → it may have been cropped (yellow, never red). Skipped when
  // the original file proves the exact bytes.
  const cropped = !!i.picture && i.picture.geometry === 'mismatch' && !exact;
  // P45: the picture's own QR was read but its geometry could not be checked (tilted over ~2°, skewed, or no finder centres): a crop
  // cannot be ruled out, so never green (yellow at most, the most specific yellow keeps the headline). Skipped for the exact bytes.
  const unframed = !!i.picture && i.picture.qr && i.picture.geometry === 'unknown' && !exact;
  if (c2paContent) checks.push({ key: 'check_content_c2pa', status: 'pass' });
  else if (flagged && texture !== null) checks.push(flatMismatch ? { key: 'check_flat_mismatch', status: 'fail' } : { key: 'check_too_flat', status: 'warn' });
  else if (hamming === null) checks.push({ key: 'check_not_compared', status: 'info' });
  else if (hamming <= a) checks.push({ key: 'check_image_match', status: 'pass', params: { d: hamming } });
  else if (hamming <= b) checks.push({ key: 'check_image_maybe', status: 'warn', params: { d: hamming } });
  else checks.push({ key: 'check_image_mismatch', status: 'fail', params: { d: hamming } });
  if (noQr) checks.push({ key: 'check_code_not_in_photo', status: 'warn' });
  if (cropped) checks.push({ key: 'check_geometry_mismatch', status: 'warn' });
  if (unframed) checks.push({ key: 'check_geometry_unknown', status: 'warn' });
  const warns: Check[] = [];
  if (!f.autoTime) warns.push({ key: 'warn_auto_time', status: 'warn' });
  if (f.clockSkewSeconds !== null && Math.abs(f.clockSkewSeconds) > 120) warns.push({ key: 'warn_clock_skew', status: 'warn', params: { n: Math.round(Math.abs(f.clockSkewSeconds) / 60) } });
  if (f.softwareKey) warns.push({ key: 'warn_software_key', status: 'warn' });
  checks.push(...warns);
  if (f.clockSkewSeconds !== null && Math.abs(f.clockSkewSeconds) <= 120 && f.autoTime) checks.push({ key: 'gps_match', status: 'pass', params: { n: Math.abs(f.clockSkewSeconds) } });
  // P42: the seal deliberately carries no coordinates when the stamp did not show them: never say "no location" then.
  if (!f.location) checks.push(f.locationWithheld ? { key: 'info_location_withheld', status: 'info' } : { key: 'info_no_location', status: 'info' });
  else { if (f.location.approximate) checks.push({ key: 'info_approx', status: 'info', params: { km: (f.location.accuracyM / 1000).toFixed(1) } });
         if (f.location.stale) checks.push({ key: 'info_stale', status: 'info', params: { n: Math.round((f.location.ageTens * 10) / 60) } }); }
  checks.push(...(i.level2 ? i.level2.lines : [{ key: 'device_unknown', status: 'info' as const }]));
  const color = ((): [Color, string] => {
    if (hamming !== null && hamming > b) return ['red', 'verdict_red'];
    // M13: an editor re-saved the original but kept its C2PA data. The file is no longer the original, but the picture (its own QR) still
    // matches its seal: yellow, never green. Anything less (no QR in the picture, a crop, a distance above the match band) stays red.
    if (i.level2?.kind === 'invalid') return hamming !== null && hamming <= a && i.picture?.qr === true && !cropped ? ['yellow', 'verdict_l2_resaved'] : ['red', 'verdict_red'];
    if (i.level2?.lines.some(c => L2_RED.has(c.key))) return ['red', 'verdict_l2_bad'];
    // A Google-certified key of ANOTHER app sealed a file that claims to be ours (P35 round 2).
    if (i.level2?.lines.some(c => c.key === 'l2_chain_ok') && i.level2.lines.some(c => c.key === 'l2_app_bad')) return ['red', 'verdict_l2_bad'];
    if (flatMismatch) return ['red', 'verdict_flat_mismatch'];
    if (texture !== null && !c2paContent) return ['yellow', 'verdict_too_flat'];
    if (hamming === null && !c2paContent && !noQr) return ['yellow', 'verdict_info_not_compared'];
    if (noQr) return ['yellow', 'verdict_code_not_in_photo'];
    if (cropped) return ['yellow', 'verdict_maybe_cropped'];
    if (hamming !== null && hamming > a) return ['yellow', 'verdict_maybe_edited'];
    if (warns.length) return ['yellow', warns[0].key];
    // P11: the original file's attestation says software key (Android 7–8, emulators), even if the payload's flag did not.
    if (i.level2?.lines.some(c => c.key === 'l2_level_sw')) return ['yellow', 'warn_software_key'];
    // P35: an original whose key is not certified by Google (no attestation, a stripped or foreign chain, no seal) is the same tier as a
    // software key: removing evidence from a file must never make the verdict better than keeping it.
    if (i.level2?.kind === 'ok' && i.level2.lines.some(c => UNCERTIFIED.has(c.key))) return ['yellow', 'verdict_uncertified'];
    // A certified key on a phone whose boot is not verified, whose bootloader is unlocked, or whose boot state is not attested: same tier.
    const device = i.level2?.kind === 'ok' ? i.level2.lines.find(c => DEVICE_YELLOW.has(c.key)) : undefined;
    if (device) return ['yellow', device.key];
    if (unframed) return ['yellow', 'verdict_geometry_unknown'];
    // P44: level 1 (a 64-bit perceptual hash) says "matches what was sealed"; "unchanged" only for the exact bytes of a bound original.
    return ['green', exact ? 'verdict_green_exact' : 'verdict_green'];
  })();
  // P25/P44: what level 1 proves is said ONLY when it is what the page found: on green, never on red or yellow.
  if (color[0] === 'green') checks.push({ key: 'proves_l1', status: 'info', params: { id } });
  if (color[0] === 'green' && !exact) checks.push({ key: 'proves_small_edits', status: 'info' });
  // Only when no original file was checked: once one was, its own lines say what is (not) confirmed about the device.
  if (!i.level2 || i.level2.kind === 'none') checks.push({ key: 'proves_not_device', status: 'info' });
  checks.push({ key: 'proves_screen', status: 'info' });
  // M9: a level-1 green from a self-made key looks like one from the app: say on the band itself whose key it is, and what is not confirmed.
  const sub: Check | undefined = color[0] === 'green' && (!i.level2 || i.level2.kind === 'none') ? { key: 'verdict_green_sub', status: 'info', params: { id } } : undefined;
  return sub ? { color: color[0], headline: color[1], checks, sub } : { color: color[0], headline: color[1], checks };
}
