// @vitest-environment happy-dom
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { checkSeal } from '../src/crypto';
import { decodeFragment } from '../src/payload';
import { formatTime, line, render, RTL } from '../src/ui';
import { verdict } from '../src/verdict';
const en = JSON.parse(readFileSync('src/i18n/en.json', 'utf8')) as Record<string, string>;
const V = JSON.parse(readFileSync('test/vectors/verify-vectors.json', 'utf8'));
const OK = V.payloads[0];   // synthetic ocean point 30.12345, 140.54321 (P3)
describe('ui line text', () => {
  it('a key the dictionary does not know shows the generic line, never the raw key', () => {
    expect(line(en, 'l2_from_the_future')).toBe('Unrecognised check result');
    expect(line(en, 'check_image_match', { d: 3 })).toBe('The photo matches its seal (difference 3/64)');
  });
});
describe('ui RTL (Arabic)', () => {
  const view = (locale: string) => { const payload = decodeFragment(OK.base64url);
    return { dict: en, locale, payload, message: null, attested: undefined, onPick: () => {}, onLocale: () => {},
      verdict: verdict({ payload, seal: checkSeal(payload), hamming: null, texture: null, level2: null, picture: null }) }; };
  it('Arabic sets dir=rtl on <html>, and any other language sets it back to ltr', () => {
    expect(RTL.has('ar')).toBe(true); expect(RTL.has('en')).toBe(false);
    const root = document.createElement('main');
    render(root, view('ar')); expect(document.documentElement.dir).toBe('rtl'); expect(document.documentElement.lang).toBe('ar');
    render(root, view('en')); expect(document.documentElement.dir).toBe('ltr');
  });
  it('dates use Latin digits even where the locale defaults to Arabic-Indic (ar-EG; bare ar on this ICU is already Latin)', () => {
    for (const l of ['ar', 'ar-EG']) { const s = formatTime(1735689600, 180, l);
      expect(s, l).not.toMatch(/[٠-٩۰-۹]/); expect(s, l).toMatch(/2025/); expect(s, l).toMatch(/GMT\+03:00$/); }
  });
  it('coordinates, the GMT offset and the key id sit in LTR isolates', () => {
    const root = document.createElement('main'); render(root, view('ar'));
    expect(root.querySelector('[data-field="place"] bdi[dir="ltr"]')?.textContent).toBe('30.12345, 140.54321');
    const time = root.querySelector('[data-field="time"]')!;
    expect(time.querySelector('bdi[dir="ltr"]')?.textContent).toMatch(/^GMT[+-]\d\d:\d\d$/);
    expect(time.textContent).toBe(formatTime(OK.fields.epochSeconds, OK.fields.tzOffsetMinutes, 'ar'));
    const seal = root.querySelector('li[data-key="check_seal_ok"]')!;
    expect(seal.querySelector('bdi[dir="ltr"]')?.textContent).toBe(OK.expectKeyId);
    expect(seal.textContent).toBe(line(en, 'check_seal_ok', { id: OK.expectKeyId }));
  });
  it('the timestamp line isolates the TSA time and the TSA name, each in its own LTR bdi', () => {
    const v = view('ar'); const time = '2026-10-13 12:00:00 UTC', tsa = 'Example TSA';
    const verdict_ = { ...v.verdict, checks: [...v.verdict.checks, { key: 'l2_tsa', status: 'pass' as const, params: { time, tsa } }] };
    const root = document.createElement('main'); render(root, { ...v, verdict: verdict_ });
    const li = root.querySelector('li[data-key="l2_tsa"]')!;
    expect([...li.querySelectorAll('bdi[dir="ltr"]')].map(b => b.textContent)).toEqual([time, tsa]);
    expect(li.textContent).toBe(line(en, 'l2_tsa', { time, tsa }));
  });
  it('the filter name sits in an LTR isolate inside the Arabic sentence; the generic line has no name', () => {
    const v = view('ar'); const ar = JSON.parse(readFileSync('src/i18n/ar.json', 'utf8')) as Record<string, string>;
    const verdict_ = { ...v.verdict, checks: [...v.verdict.checks, { key: 'l2_filtered', status: 'info' as const, params: { name: 'Teal & Orange' } }] };
    const root = document.createElement('main'); render(root, { ...v, dict: ar, verdict: verdict_ });
    const li = root.querySelector('li[data-key="l2_filtered"]')!;
    expect([...li.querySelectorAll('bdi[dir="ltr"]')].map(b => b.textContent)).toEqual(['Teal & Orange']);
    expect(ar.l2_filtered_generic_line).not.toContain('{');
  });
  it('the attestation copy date (YYYY-MM-DD) sits in an LTR isolate, so an Arabic line cannot show it as 13-10-2026', () => {
    const root = document.createElement('main'); render(root, { ...view('ar'), attested: '2026-10-13' });
    const p = root.querySelector('[data-attested]')!;
    expect(p.querySelector('bdi[dir="ltr"]')?.textContent).toBe('2026-10-13'); expect(p.textContent).toBe(line(en, 'attested_on', { date: '2026-10-13' }));
  });
});
