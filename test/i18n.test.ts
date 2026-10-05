import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { LOCALES, pickLocale, t } from '../src/i18n';
const dict = (l: string) => JSON.parse(readFileSync(`src/i18n/${l}.json`, 'utf8')) as Record<string, string>;
const ph = (s: string) => [...s.matchAll(/\{(\w+)\}/g)].map(m => m[1]).sort();
const SAME_OK = new Set(['brand', 'label_accuracy']);   // a brand name and a pure unit pattern are legitimately identical
const G = JSON.parse(readFileSync('src/glossary.json', 'utf8')) as { terms: Record<string, Record<string, string>>; uses: Record<string, string[]> };
describe('i18n', () => {
  it('every locale has every key with the same placeholders, none left in English', () => {
    const en = dict('en');
    for (const l of LOCALES) { if (l === 'en') continue; const d = dict(l);
      expect(Object.keys(d).sort(), l).toEqual(Object.keys(en).sort());
      for (const k of Object.keys(en)) { expect(typeof d[k] === 'string' && d[k].trim().length > 0, `${l}.${k} empty`).toBe(true);
        expect(ph(d[k]), `${l}.${k}`).toEqual(ph(en[k])); if (en[k].length > 4 && !SAME_OK.has(k)) expect(d[k], `${l}.${k} untranslated`).not.toBe(en[k]); } }
  });
  it('every key the page uses exists in English', () => {
    const en = dict('en'); const src = ['src/verdict.ts', 'src/ui.ts', 'src/app.ts'].map(f => readFileSync(f, 'utf8')).join('\n');
    const used = new Set([...src.matchAll(/'((?:verdict|warn|info|gps|check|device|label|map|address|pick|working|error|no|footer|lang|proves|l2|attested|too|key)_[a-z0-9_]+)'/g)].map(m => m[1]));
    for (const k of used) expect(en[k], `en.json lacks ${k}`).toBeTypeOf('string');
  });
  it('shares the app glossary (the same word for "seal", "original file"... in each language)', () => {
    for (const l of LOCALES) { const d = dict(l);
      for (const [key, terms] of Object.entries(G.uses)) { expect(d[key], `${l}.${key} missing`).toBeTypeOf('string');
        for (const term of terms) expect(d[key].toLowerCase(), `${l}.${key} must use glossary term ${term}`).toContain(G.terms[term][l].toLowerCase()); } }
  });
  it('uses the spec §7.3 Vietnamese wording verbatim', () => { const d = dict('vi');
    expect(d.verdict_green).toBe('Ảnh không bị sửa'); expect(d.verdict_info_not_compared).toBe('Thông tin đúng — chưa so được ảnh');
    expect(d.verdict_red).toBe('Ảnh hoặc thông tin đã bị thay đổi'); expect(d.footer_local).toBe('Kiểm tra ngay trên máy bạn');
    expect(d.footer_upload).toBe('Ảnh không được tải lên'); expect(d.footer_app).toBe('Chụp bằng CameraStamp — tải app'); });
  it('picks the browser language, falling back sensibly', () => {
    expect(pickLocale(['vi-VN', 'en'])).toBe('vi'); expect(pickLocale(['pt-PT'])).toBe('pt-BR'); expect(pickLocale(['es-MX'])).toBe('es');
    expect(pickLocale(['in'])).toBe('id'); expect(pickLocale(['de-DE'])).toBe('en'); expect(pickLocale([])).toBe('en');
    expect(pickLocale(['de', 'th-TH'])).toBe('th');
  });
  it('fills placeholders and never returns undefined', () => { expect(t({ a: 'x {n} y' }, 'a', { n: 3 })).toBe('x 3 y'); expect(t({}, 'missing')).toBe('missing'); });
});
