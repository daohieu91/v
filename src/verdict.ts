import { THRESHOLDS } from './config';
import type { SealPayload } from './payload';
export type Color = 'green' | 'yellow' | 'red';
export interface Check { key: string; status: 'pass' | 'warn' | 'fail' | 'info'; params?: Record<string, string | number> }
export interface Verdict { color: Color; headline: string; checks: Check[] }
export interface L2Summary { kind: 'none' | 'invalid' | 'ok'; lines: Check[]; realDevice: boolean }

/**
 * Spec §6 / §7.3, honest: one line per check, nothing merged or overstated. The seal holds ONLY when checkSeal says so (`seal.ok`):
 * a recovered key alone proves nothing, since an edited payload still recovers *a* key. A level-1 green means "this picture and these
 * details are unchanged since key <id> sealed them", never "taken by the app": that needs the original file (level 2).
 */
export function verdict(i: { payload: SealPayload | null; seal: { ok: boolean; keyIdHex: string | null } | null; hamming: number | null; level2: L2Summary | null }): Verdict {
  if (!i.payload || !i.seal || i.seal.ok !== true || !i.seal.keyIdHex) return { color: 'red', headline: 'verdict_red', checks: [{ key: 'check_seal_bad', status: 'fail' }] };
  const f = i.payload.fields; const [a, b] = THRESHOLDS; const id = i.seal.keyIdHex;
  const checks: Check[] = [{ key: 'check_seal_ok', status: 'pass', params: { id } }];
  const c2paContent = i.hamming === null && i.level2?.kind === 'ok';       // F-M13: a valid original file binds the content itself
  if (c2paContent) checks.push({ key: 'check_content_c2pa', status: 'pass' });
  else if (i.hamming === null) checks.push({ key: 'check_not_compared', status: 'info' });
  else if (i.hamming <= a) checks.push({ key: 'check_image_match', status: 'pass', params: { d: i.hamming } });
  else if (i.hamming <= b) checks.push({ key: 'check_image_maybe', status: 'warn', params: { d: i.hamming } });
  else checks.push({ key: 'check_image_mismatch', status: 'fail', params: { d: i.hamming } });
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
  checks.push({ key: 'proves_l1', status: 'info', params: { id } });
  if (!i.level2?.realDevice) checks.push({ key: 'proves_not_device', status: 'info' });
  checks.push({ key: 'proves_screen', status: 'info' });
  const fail = i.level2?.kind === 'invalid' || (i.hamming !== null && i.hamming > b);
  if (fail) return { color: 'red', headline: 'verdict_red', checks };
  if (i.hamming === null && !c2paContent) return { color: 'yellow', headline: 'verdict_info_not_compared', checks };
  if (i.hamming !== null && i.hamming > a) return { color: 'yellow', headline: 'verdict_maybe_edited', checks };
  if (warns.length) return { color: 'yellow', headline: warns[0].key, checks };
  return { color: 'green', headline: 'verdict_green', checks };
}
