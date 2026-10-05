import { describe, expect, it } from 'vitest';
import { FLAT_MISMATCH_TEXTURE, TEXTURE_FLOOR } from '../src/config';
import { verdict } from '../src/verdict';
import type { SealPayload } from '../src/payload';
const base = (o: Partial<SealPayload['fields']> = {}): SealPayload => ({ recoveryBit: 0, signature: new Uint8Array(64), signed: new Uint8Array(41),
  fields: { version: 1, epochSeconds: 1759407420, tzOffsetMinutes: 540, location: { latE5: 3012345, lngE5: 14054321, accuracyM: 6, ageTens: 0, approximate: false, stale: false },
    autoTime: true, clockSkewSeconds: 2, softwareKey: false, phash: 0n, frame: [4, 202, 252, 255], keyTag: 1, noFingerprint: false, aspect: 13333, locationWithheld: false, ...o } });
const ok = { ok: true, keyIdHex: '0011223344556677' };
const v = (p: SealPayload | null, h: number | null, seal: { ok: boolean; keyIdHex: string | null } = ok) => verdict({ payload: p, seal, hamming: h, texture: null, level2: null });
describe('verdict', () => {
  it('green when sealed, matching and clean', () => { const r = v(base(), 3); expect(r.color).toBe('green'); expect(r.headline).toBe('verdict_green');
    expect(r.checks.find(c => c.key === 'gps_match')?.params).toEqual({ n: 2 }); expect(r.checks.some(c => c.key === 'device_unknown')).toBe(true); });
  it('shows the full 8-byte key id, never only the 4-byte tag (P18 e)', () =>
    expect(v(base(), 3).checks.find(c => c.key === 'check_seal_ok')?.params).toEqual({ id: '0011223344556677' }));
  it('yellow before an image is compared', () => expect(v(base(), null).headline).toBe('verdict_info_not_compared'));
  it('yellow when lightly edited', () => expect(v(base(), 15).headline).toBe('verdict_maybe_edited'));
  it('the bands are inclusive at 8 and 16', () => { expect(v(base(), 8).color).toBe('green'); expect(v(base(), 9).color).toBe('yellow');
    expect(v(base(), 16).color).toBe('yellow'); expect(v(base(), 17).color).toBe('red'); });
  it('red when the image differs', () => expect(v(base(), 21).color).toBe('red'));
  it('red when the seal does not hold', () => expect(v(base(), 0, { ok: false, keyIdHex: null }).color).toBe('red'));
  it('the colour comes from the seal check alone, never from a recovered key', () =>
    expect(v(base(), 0, { ok: false, keyIdHex: 'ffeeddccbbaa9988' }).color).toBe('red'));
  it('red without a payload', () => expect(v(null, null, { ok: false, keyIdHex: null }).color).toBe('red'));
  it('auto time off is a yellow warning', () => expect(v(base({ autoTime: false }), 2).headline).toBe('warn_auto_time'));
  it('clock skew over 2 minutes is a yellow warning in minutes', () => { const r = v(base({ clockSkewSeconds: -400 }), 2);
    expect(r.headline).toBe('warn_clock_skew'); expect(r.checks.find(c => c.key === 'warn_clock_skew')?.params).toEqual({ n: 7 }); });
  it('120 s of skew is still green', () => expect(v(base({ clockSkewSeconds: 120 }), 2).color).toBe('green'));
  it('software key is a yellow warning', () => expect(v(base({ softwareKey: true }), 2).headline).toBe('warn_software_key'));
  it('no location is information only', () => { const r = v(base({ location: null, clockSkewSeconds: null }), 2);
    expect(r.color).toBe('green'); expect(r.checks.some(c => c.key === 'info_no_location')).toBe(true); });
  it('approximate and stale location are information with numbers', () => {
    const r = v(base({ location: { latE5: 1, lngE5: 1, accuracyM: 3200, ageTens: 30, approximate: true, stale: true } }), 2);
    expect(r.color).toBe('green');
    expect(r.checks.find(c => c.key === 'info_approx')?.params).toEqual({ km: '3.2' });
    expect(r.checks.find(c => c.key === 'info_stale')?.params).toEqual({ n: 5 });
  });
  it('a broken original file is red even if the picture matches', () =>
    expect(verdict({ payload: base(), seal: ok, hamming: 1, texture: null, level2: { kind: 'invalid', lines: [], realDevice: false, bound: false } }).color).toBe('red'));
  it('a valid original file proves the content when no picture was compared (F-M13: video)', () => {
    const r = verdict({ payload: base(), seal: ok, hamming: null, texture: null, level2: { kind: 'ok', lines: [], realDevice: true, bound: true } });
    expect(r.color).toBe('green'); expect(r.checks.some(c => c.key === 'check_content_c2pa' && c.status === 'pass')).toBe(true);
    expect(verdict({ payload: base({ softwareKey: true }), seal: ok, hamming: null, texture: null, level2: { kind: 'ok', lines: [], realDevice: false, bound: true } }).headline).toBe('warn_software_key');
  });
  it('a level-1 green says what it proves and what it does not', () => { const k = v(base(), 0).checks.map(c => c.key);
    expect(k).toContain('proves_l1'); expect(k).toContain('proves_not_device'); });
  it('"unchanged since sealed" (proves_l1) appears ONLY on green (P25)', () => {
    const has = (r: ReturnType<typeof v>) => r.checks.some(c => c.key === 'proves_l1');
    expect(has(v(base(), 21)), 'red: picture differs').toBe(false);
    expect(has(v(base(), 0, { ok: false, keyIdHex: null })), 'red: seal broken').toBe(false);
    expect(has(verdict({ payload: base(), seal: ok, hamming: 1, texture: null, level2: { kind: 'invalid', lines: [], realDevice: false, bound: false } })), 'red: original file broken').toBe(false);
    expect(has(v(base(), 12)), 'yellow: maybe edited').toBe(false);
    expect(has(v(base(), null)), 'yellow: not compared').toBe(false);
    expect(has(v(base({ autoTime: false }), 2)), 'yellow: warning').toBe(false);
    expect(has(v(base(), 8)), 'green').toBe(true);
  });
  // P26 + P28: a NO_FINGERPRINT seal is never judged by a hash. Its colour comes from the received picture's Step 7 texture alone.
  describe('NO_FINGERPRINT seals', () => {
    const nf = () => base({ noFingerprint: true, phash: 0n });
    const t = (texture: number | null, hamming: number | null = null, p = nf()) => verdict({ payload: p, seal: ok, hamming, texture, level2: null });
    const keys = (r: ReturnType<typeof t>) => r.checks.map(c => c.key);
    it('no photo picked: yellow "Seal is valid — photo not compared yet"', () => {
      const r = t(null); expect([r.color, r.headline]).toEqual(['yellow', 'verdict_info_not_compared']); expect(keys(r)).toContain('check_not_compared');
      expect(keys(r)).not.toContain('proves_l1');
    });
    it('a dark/flat photo (texture ≤ 8 × floor): yellow "too dark or flat to compare", no hash compare and no proves_l1', () => {
      for (const x of [0, TEXTURE_FLOOR - 1, TEXTURE_FLOOR, FLAT_MISMATCH_TEXTURE]) { const r = t(x);
        expect([r.color, r.headline], String(x)).toEqual(['yellow', 'verdict_too_flat']);
        expect(r.checks.find(c => c.key === 'check_too_flat')?.status).toBe('warn');
        expect(keys(r).filter(k => k.startsWith('check_image') || k === 'proves_l1'), String(x)).toEqual([]); }
      expect(FLAT_MISMATCH_TEXTURE).toBe(2_097_152);
    });
    it('a photo with detail (texture > 8 × floor): red "the seal belongs to a different photo"', () => {
      for (const x of [FLAT_MISMATCH_TEXTURE + 1, 470_000_000]) { const r = t(x);
        expect([r.color, r.headline], String(x)).toEqual(['red', 'verdict_flat_mismatch']);
        expect(r.checks.find(c => c.key === 'check_flat_mismatch')?.status).toBe('fail'); expect(keys(r)).not.toContain('proves_l1'); }
    });
    it('never green or red from a hash, whatever distance reaches it', () => {
      expect(t(null, 0).color).toBe('yellow'); expect(t(null, 40).color).toBe('yellow'); expect(t(10, 0).headline).toBe('verdict_too_flat');
      expect(keys(t(10, 40)).some(k => k.startsWith('check_image'))).toBe(false);
    });
    it('the seal still has to hold, and the usual warnings still show', () => {
      expect(verdict({ payload: nf(), seal: { ok: false, keyIdHex: null }, hamming: null, texture: 0, level2: null }).color).toBe('red');
      expect(keys(t(10, null, base({ noFingerprint: true, phash: 0n, softwareKey: true })))).toContain('warn_software_key');
    });
    // P30: a valid original file (level 2, C2PA hard binding over the exact bytes) proves the content itself, more than any pHash could:
    // a NO_FINGERPRINT seal may then be green, worded as the level-2 "file unchanged since sealed". Without level 2 it stays yellow.
    const L2OK = { kind: 'ok' as const, lines: [], realDevice: true, bound: true };
    it('P30: a flagged seal whose original file passes level 2 is green, with the level-2 wording', () => {
      for (const texture of [null, 0, TEXTURE_FLOOR - 1]) {
        const r = verdict({ payload: nf(), seal: ok, hamming: null, texture, level2: L2OK });
        expect([r.color, r.headline], String(texture)).toEqual(['green', 'verdict_green_exact']);   // P44: the exact bytes
        expect(r.checks.find(c => c.key === 'check_content_c2pa')?.status, String(texture)).toBe('pass');
        expect(keys(r).filter(k => k === 'check_too_flat' || k === 'check_not_compared' || k.startsWith('check_image'))).toEqual([]);
      }
    });
    it('P30: the same flagged seal without level 2 stays yellow; a level-2 pass never hides a picture with detail', () => {
      expect(verdict({ payload: nf(), seal: ok, hamming: null, texture: null, level2: null }).color).toBe('yellow');
      expect(verdict({ payload: nf(), seal: ok, hamming: null, texture: 0, level2: null }).headline).toBe('verdict_too_flat');
      expect(verdict({ payload: nf(), seal: ok, hamming: null, texture: null, level2: { kind: 'none', lines: [], realDevice: false, bound: false } }).color).toBe('yellow');
      const detail = verdict({ payload: nf(), seal: ok, hamming: null, texture: FLAT_MISMATCH_TEXTURE + 1, level2: L2OK });
      expect([detail.color, detail.headline]).toEqual(['red', 'verdict_flat_mismatch']);
      expect(keys(detail)).toContain('check_flat_mismatch'); expect(keys(detail)).not.toContain('check_content_c2pa');
    });
    it('without the flag the texture is ignored and the hash decides', () => {
      expect(verdict({ payload: base(), seal: ok, hamming: 3, texture: FLAT_MISMATCH_TEXTURE * 100, level2: null }).color).toBe('green');
      expect(verdict({ payload: base(), seal: ok, hamming: 3, texture: 0, level2: null }).color).toBe('green');
    });
  });
});

// Task 22: what level 2 adds to the colour. Lines come from src/l2/device.ts; the verdict only reads their keys.
describe('verdict with level 2', () => {
  const L = (lines: string[], o: Partial<{ kind: 'ok' | 'none' | 'invalid'; realDevice: boolean; bound: boolean }> = {}) =>
    ({ kind: 'ok' as const, realDevice: false, bound: true, ...o, lines: lines.map(key => ({ key, status: 'info' as const })) });
  const r = (lines: string[], o = {}, h: number | null = 2) => verdict({ payload: base(), seal: ok, hamming: h, texture: null, level2: L(lines, o) });
  it('a revoked certificate, an unbound signer or a QR of another key is red "the original file\'s seal can\'t be trusted"', () => {
    for (const k of ['l2_revoked', 'l2_binding_bad', 'l2_qr_other_key']) { const v1 = r(['l2_signature_ok', k]);
      expect([v1.color, v1.headline], k).toEqual(['red', 'verdict_l2_bad']); expect(v1.checks.some(c => c.key === 'proves_l1'), k).toBe(false); }
  });
  it('round 2: a certified key of ANOTHER app (l2_app_bad) is red', () => {
    const v1 = r(['l2_signature_ok', 'l2_chain_ok', 'l2_app_bad', 'l2_level_hw', 'l2_boot_ok', 'l2_locked_ok']);
    expect([v1.color, v1.headline]).toEqual(['red', 'verdict_l2_bad']); expect(v1.checks.some(c => c.key === 'proves_l1')).toBe(false);
  });
  it.each(['l2_boot_bad', 'l2_locked_bad', 'l2_boot_unknown'])('round 2: a certified key with %s is yellow, headed by that line, never green', k => {
    const v1 = r(['l2_signature_ok', 'l2_chain_ok', 'l2_app_unregistered', 'l2_level_hw', k]);
    expect([v1.color, v1.headline]).toEqual(['yellow', k]); expect(v1.checks.some(c => c.key === 'proves_l1')).toBe(false);
  });
  it('a software attestation (P11: Android 7–8, emulators) turns a green yellow "software key — lower trust"', () => {
    const v1 = r(['l2_signature_ok', 'l2_level_sw']); expect([v1.color, v1.headline]).toEqual(['yellow', 'warn_software_key']);
    expect(r(['l2_signature_ok', 'l2_level_hw']).color).toBe('green');
  });
  it('a test build or an unregistered app signature on a certified key are lines, not colours', () => {
    for (const k of ['l2_app_dev', 'l2_app_unregistered', 'l2_app_unknown']) expect(r(['l2_signature_ok', 'l2_chain_ok', k]).color, k).toBe('green');
  });
  it('P35: a key not certified by Google (no or stripped attestation, no seal in the file) is yellow "Key not certified — lower trust", never green', () => {
    for (const k of ['l2_chain_bad', 'l2_no_seal']) { const v1 = r(['l2_signature_ok', k]); expect([v1.color, v1.headline], k).toEqual(['yellow', 'verdict_uncertified']);
      expect(v1.checks.some(c => c.key === 'proves_l1'), k).toBe(false); }
    // stripping evidence never improves the verdict: an uncertified file is never better than a software-attested one
    expect(r(['l2_signature_ok', 'l2_chain_bad']).color).toBe(r(['l2_signature_ok', 'l2_chain_bad', 'l2_level_sw']).color);
    const video = verdict({ payload: base(), seal: ok, hamming: null, texture: null, level2: L(['l2_chain_bad']) }); expect(video.color).toBe('yellow');
  });
  it('P30/F-M13 needs the file to be bound to THIS seal: an unbound file never stands in for the content', () => {
    const v1 = verdict({ payload: base(), seal: ok, hamming: null, texture: null, level2: L([], { bound: false }) });
    expect([v1.color, v1.headline]).toEqual(['yellow', 'verdict_info_not_compared']); expect(v1.checks.some(c => c.key === 'check_content_c2pa')).toBe(false);
    expect(verdict({ payload: base(), seal: ok, hamming: null, texture: null, level2: L([]) }).color).toBe('green');
  });
  it('"sealed by a key in a real device" keeps proves_screen; proves_not_device only when no original file was checked', () => {
    const real = r(['l2_real_device'], { realDevice: true }).checks.map(c => c.key);
    expect(real).toContain('proves_screen'); expect(real).not.toContain('proves_not_device');
    expect(r(['l2_chain_bad']).checks.map(c => c.key), 'an original was checked: its lines say it').not.toContain('proves_not_device');
    expect(r(['l2_error'], { kind: 'none', bound: false }).checks.map(c => c.key), 'original not readable').toContain('proves_not_device');
    expect(v(base(), 2).checks.map(c => c.key), 'no original').toContain('proves_not_device');
  });
  it('a broken original file without a readable seal (a tampered video) is red and says why', () => {
    const v1 = verdict({ payload: null, seal: null, hamming: null, texture: null, level2: L(['l2_invalid'], { kind: 'invalid', bound: false }) });
    expect(v1.color).toBe('red'); expect(v1.checks.map(c => c.key)).toEqual(['l2_invalid']);
  });
});

// Final fix wave B: P42, P44, I4, P41/P41b, M9, M13.
describe('verdict, final fix wave', () => {
  const pic = (qr: boolean, geometry: 'ok' | 'mismatch' | 'unknown' | null = 'ok') => ({ qr, geometry });
  const V = (o: Partial<Parameters<typeof verdict>[0]>) => verdict({ payload: base(), seal: ok, hamming: 2, texture: null, level2: null, picture: pic(true), ...o });
  const keys = (r: ReturnType<typeof verdict>) => r.checks.map(c => c.key);
  const BOUND = { kind: 'ok' as const, lines: [{ key: 'l2_signature_ok', status: 'pass' as const }], realDevice: false, bound: true };
  it('P42: a withheld location says "not included in this seal", never "no location"', () => {
    const w = V({ payload: base({ location: null, locationWithheld: true }) });
    expect(keys(w)).toContain('info_location_withheld'); expect(keys(w)).not.toContain('info_no_location'); expect(w.color).toBe('green');
    expect(keys(V({ payload: base({ location: null }) }))).toContain('info_no_location');
  });
  it('P44: a level-1 green "matches what was sealed", says tiny edits may not show, and names the key under the band (M9)', () => {
    const g = V({});
    expect([g.color, g.headline]).toEqual(['green', 'verdict_green']);
    expect(keys(g)).toEqual(expect.arrayContaining(['proves_l1', 'proves_small_edits']));
    expect(g.sub).toEqual({ key: 'verdict_green_sub', status: 'info', params: { id: ok.keyIdHex } });
    for (const y of [V({ hamming: 12 }), V({ hamming: 30 })]) { expect(y.sub).toBeUndefined(); expect(keys(y)).not.toContain('proves_small_edits'); }
  });
  it('P44: only a bound original (the exact bytes) is "unchanged"; then no small-edits caveat and no level-1-only subtitle', () => {
    const e = V({ level2: BOUND });
    expect([e.color, e.headline]).toEqual(['green', 'verdict_green_exact']); expect(keys(e)).not.toContain('proves_small_edits'); expect(e.sub).toBeUndefined();
    expect(V({ level2: { ...BOUND, bound: false } }).headline).toBe('verdict_green');
  });
  it('I4 / P41b: a photo whose own QR was not read is never green, at most yellow; a mismatch stays red', () => {
    for (const h of [0, 8]) { const r = V({ hamming: h, picture: pic(false, 'unknown') });
      expect([r.color, r.headline], String(h)).toEqual(['yellow', 'verdict_code_not_in_photo']); expect(keys(r)).toContain('check_code_not_in_photo');
      expect(keys(r)).not.toContain('proves_l1'); }
    expect(V({ hamming: 20, picture: pic(false) }).color).toBe('red');
    // Even with a bound original whose content level 2 proves (P30), a picked photo without its QR is not green.
    expect(V({ hamming: null, level2: BOUND, picture: pic(false, null) }).color).toBe('yellow');
    // A link alone (no picture) and a video (no QR at all) are unaffected.
    expect(V({ hamming: null, picture: null }).headline).toBe('verdict_info_not_compared');
  });
  it('P41: a geometry mismatch is yellow "may have been cropped", never green and never red by itself; the exact bytes skip it', () => {
    const c = V({ picture: pic(true, 'mismatch') });
    expect([c.color, c.headline]).toEqual(['yellow', 'verdict_maybe_cropped']); expect(keys(c)).toContain('check_geometry_mismatch'); expect(keys(c)).not.toContain('proves_l1');
    expect(V({ hamming: 20, picture: pic(true, 'mismatch') }).color).toBe('red');
    for (const g of ['ok', 'unknown'] as const) expect(V({ picture: pic(true, g) }).color, g).toBe('green');
    expect(V({ level2: BOUND, picture: pic(true, 'mismatch') }).headline).toBe('verdict_green_exact');
  });
  it('M13: an original re-saved with its C2PA data kept, whose own QR picture still matches: yellow, not red; anything less stays red', () => {
    const INV = { kind: 'invalid' as const, lines: [{ key: 'l2_invalid', status: 'fail' as const }], realDevice: false, bound: false };
    const r = V({ level2: INV }); expect([r.color, r.headline]).toEqual(['yellow', 'verdict_l2_resaved']); expect(keys(r)).toContain('l2_invalid');
    expect(V({ level2: INV, hamming: 9 }).color).toBe('red');
    expect(V({ level2: INV, picture: pic(false) }).color).toBe('red');
    expect(V({ level2: INV, picture: pic(true, 'mismatch') }).color).toBe('red');
    expect(V({ level2: INV, picture: null }).color).toBe('red');
  });
});
