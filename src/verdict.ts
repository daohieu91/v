import { FLAT_MISMATCH_TEXTURE, THRESHOLDS } from './config';
import type { SealPayload } from './payload';
export type Color = 'green' | 'yellow' | 'red';
export interface Check { key: string; status: 'pass' | 'warn' | 'fail' | 'info'; params?: Record<string, string | number> }
export interface Verdict { color: Color; headline: string; checks: Check[] }
/**
 * Level 2 (the original file). `bound`: the C2PA signer key is the seal payload's key, so the file-level hard binding stands for THIS
 * seal's content (P30); the page sets it false when the picture's own QR seal is not the seal in the file (identity, P18 a).
 */
export interface L2Summary { kind: 'none' | 'invalid' | 'ok'; lines: Check[]; realDevice: boolean; bound: boolean }
/** Level-2 findings that make the file itself untrustworthy: a revoked certificate, a signer that is not the seal's/attested key, a QR of another key. */
const L2_RED = new Set(['l2_revoked', 'l2_binding_bad', 'l2_qr_other_key']);

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
  texture: number | null; level2: L2Summary | null }): Verdict {
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
  if (c2paContent) checks.push({ key: 'check_content_c2pa', status: 'pass' });
  else if (flagged && texture !== null) checks.push(flatMismatch ? { key: 'check_flat_mismatch', status: 'fail' } : { key: 'check_too_flat', status: 'warn' });
  else if (hamming === null) checks.push({ key: 'check_not_compared', status: 'info' });
  else if (hamming <= a) checks.push({ key: 'check_image_match', status: 'pass', params: { d: hamming } });
  else if (hamming <= b) checks.push({ key: 'check_image_maybe', status: 'warn', params: { d: hamming } });
  else checks.push({ key: 'check_image_mismatch', status: 'fail', params: { d: hamming } });
  const warns: Check[] = [];
  if (!f.autoTime) warns.push({ key: 'warn_auto_time', status: 'warn' });
  if (f.clockSkewSeconds !== null && Math.abs(f.clockSkewSeconds) > 120) warns.push({ key: 'warn_clock_skew', status: 'warn', params: { n: Math.round(Math.abs(f.clockSkewSeconds) / 60) } });
  if (f.softwareKey) warns.push({ key: 'warn_software_key', status: 'warn' });
  checks.push(...warns);
  if (f.clockSkewSeconds !== null && Math.abs(f.clockSkewSeconds) <= 120 && f.autoTime) checks.push({ key: 'gps_match', status: 'pass', params: { n: Math.abs(f.clockSkewSeconds) } });
  if (!f.location) checks.push({ key: 'info_no_location', status: 'info' });
  else { if (f.location.approximate) checks.push({ key: 'info_approx', status: 'info', params: { km: (f.location.accuracyM / 1000).toFixed(1) } });
         if (f.location.stale) checks.push({ key: 'info_stale', status: 'info', params: { n: Math.round((f.location.ageTens * 10) / 60) } }); }
  checks.push(...(i.level2 ? i.level2.lines : [{ key: 'device_unknown', status: 'info' as const }]));
  const color = ((): [Color, string] => {
    if (i.level2?.kind === 'invalid' || (hamming !== null && hamming > b)) return ['red', 'verdict_red'];
    if (i.level2?.lines.some(c => L2_RED.has(c.key))) return ['red', 'verdict_l2_bad'];
    if (flatMismatch) return ['red', 'verdict_flat_mismatch'];
    if (texture !== null && !c2paContent) return ['yellow', 'verdict_too_flat'];
    if (hamming === null && !c2paContent) return ['yellow', 'verdict_info_not_compared'];
    if (hamming !== null && hamming > a) return ['yellow', 'verdict_maybe_edited'];
    if (warns.length) return ['yellow', warns[0].key];
    // P11: the original file's attestation says software key (Android 7–8, emulators), even if the payload's flag did not.
    if (i.level2?.lines.some(c => c.key === 'l2_level_sw')) return ['yellow', 'warn_software_key'];
    return ['green', 'verdict_green'];
  })();
  // P25: "unchanged since sealed by key X" is said ONLY when it is what the page found: on green, never on red or yellow.
  if (color[0] === 'green') checks.push({ key: 'proves_l1', status: 'info', params: { id } });
  if (!i.level2?.realDevice) checks.push({ key: 'proves_not_device', status: 'info' });
  checks.push({ key: 'proves_screen', status: 'info' });
  return { color: color[0], headline: color[1], checks };
}
