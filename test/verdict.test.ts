import { describe, expect, it } from 'vitest';
import { FLAT_MISMATCH_TEXTURE, TEXTURE_FLOOR } from '../src/config';
import { verdict } from '../src/verdict';
import type { SealPayload } from '../src/payload';
const base = (o: Partial<SealPayload['fields']> = {}): SealPayload => ({ recoveryBit: 0, signature: new Uint8Array(64), signed: new Uint8Array(39),
  fields: { version: 1, epochSeconds: 1759407420, tzOffsetMinutes: 540, location: { latE5: 3012345, lngE5: 14054321, accuracyM: 6, ageTens: 0, approximate: false, stale: false },
    autoTime: true, clockSkewSeconds: 2, softwareKey: false, phash: 0n, frame: [4, 202, 252, 255], keyTag: 1, noFingerprint: false, ...o } });
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
    expect(verdict({ payload: base(), seal: ok, hamming: 1, texture: null, level2: { kind: 'invalid', lines: [], realDevice: false } }).color).toBe('red'));
  it('a valid original file proves the content when no picture was compared (F-M13: video)', () => {
    const r = verdict({ payload: base(), seal: ok, hamming: null, texture: null, level2: { kind: 'ok', lines: [], realDevice: true } });
    expect(r.color).toBe('green'); expect(r.checks.some(c => c.key === 'check_content_c2pa' && c.status === 'pass')).toBe(true);
    expect(verdict({ payload: base({ softwareKey: true }), seal: ok, hamming: null, texture: null, level2: { kind: 'ok', lines: [], realDevice: false } }).headline).toBe('warn_software_key');
  });
  it('a level-1 green says what it proves and what it does not', () => { const k = v(base(), 0).checks.map(c => c.key);
    expect(k).toContain('proves_l1'); expect(k).toContain('proves_not_device'); });
  it('"unchanged since sealed" (proves_l1) appears ONLY on green (P25)', () => {
    const has = (r: ReturnType<typeof v>) => r.checks.some(c => c.key === 'proves_l1');
    expect(has(v(base(), 21)), 'red: picture differs').toBe(false);
    expect(has(v(base(), 0, { ok: false, keyIdHex: null })), 'red: seal broken').toBe(false);
    expect(has(verdict({ payload: base(), seal: ok, hamming: 1, texture: null, level2: { kind: 'invalid', lines: [], realDevice: false } })), 'red: original file broken').toBe(false);
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
    it('without the flag the texture is ignored and the hash decides', () => {
      expect(verdict({ payload: base(), seal: ok, hamming: 3, texture: FLAT_MISMATCH_TEXTURE * 100, level2: null }).color).toBe('green');
      expect(verdict({ payload: base(), seal: ok, hamming: 3, texture: 0, level2: null }).color).toBe('green');
    });
  });
});
