import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { LOCALES, pickLocale, t } from '../src/i18n';
const dict = (l: string) => JSON.parse(readFileSync(`src/i18n/${l}.json`, 'utf8')) as Record<string, string>;
const ph = (s: string) => [...s.matchAll(/\{(\w+)\}/g)].map(m => m[1]).sort();
const SAME_OK = new Set(['brand', 'label_accuracy']);   // a brand name and a pure unit pattern are legitimately identical
const G = JSON.parse(readFileSync('src/glossary.json', 'utf8')) as { terms: Record<string, Record<string, string>>; uses: Record<string, string[]> };
// Per locale: phrases allowed first (the glossary's "real device" / "original file", and "approximate" in vi), then banned stems.
const g = (...x: string[]) => x.map(r => new RegExp(r, 'gu'));
const BANNED: Record<string, { allow: RegExp[]; ban: RegExp[] }> = {
  en: { allow: g('real device'), ban: g('\\breal\\b', 'authentic', 'genuine', '\\btrue\\b', 'taken with') },
  vi: { allow: g('máy thật', 'gần đúng'), ban: g('thật', 'xác thực', 'đúng', 'chụp bằng', 'nơi chụp') },
  hi: { allow: g('असली डिवाइस'), ban: g('असली', 'प्रामाणिक', 'सही', 'सच', 'से लिया') },
  id: { allow: g('perangkat asli', 'file asli'), ban: g('asli', 'autentik', 'benar', 'diambil dengan') },
  es: { allow: g('dispositivo real'), ban: g('\\breal', 'auténtic', 'genuin', 'verdader', 'tomada con', 'hecho con') },
  'pt-BR': { allow: g('aparelho real'), ban: g('\\breal', 'autêntic', 'genuín', 'verdadeir', 'tirada com', 'feito com') },
  it: { allow: g('dispositivo reale'), ban: g('\\breal', 'autentic', 'genuin', '\\bver[oaie]\\b', 'scattata con', 'creato con') },
  pl: { allow: g('prawdziw\\p{L}* urządzen\\p{L}*'), ban: g('prawdziw', 'autentycz', 'zrobion') },
  th: { allow: g('เครื่องจริง'), ban: g('จริง', 'แท้', 'ถ่ายด้วย', 'ข้อมูลถูกต้อง') },
  ms: { allow: g('peranti sebenar'), ban: g('sebenar', 'tulen', 'asli', 'benar', 'diambil dengan') },
};
describe('i18n', () => {
  it('every locale has every key with the same placeholders, none left in English', () => {
    const en = dict('en');
    for (const l of LOCALES) { if (l === 'en') continue; const d = dict(l);
      expect(Object.keys(d).sort(), l).toEqual(Object.keys(en).sort());
      for (const k of Object.keys(en)) { expect(typeof d[k] === 'string' && d[k].trim().length > 0, `${l}.${k} empty`).toBe(true);
        expect(ph(d[k]), `${l}.${k}`).toEqual(ph(en[k])); if (en[k].length > 4 && !SAME_OK.has(k)) expect(d[k], `${l}.${k} untranslated`).not.toBe(en[k]); } }
  });
  it('every key the page uses exists in English', () => {
    const en = dict('en'); const src = ['src/verdict.ts', 'src/ui.ts', 'src/app.ts', 'src/l2/device.ts', 'src/l2/summary.ts', 'src/l2/level2.ts'].map(f => readFileSync(f, 'utf8')).join('\n');
    const used = new Set([...src.matchAll(/'((?:verdict|warn|info|gps|check|device|label|map|address|pick|working|error|no|footer|lang|proves|l2|attested|too|key|notice|unknown|privacy)_[a-z0-9_]+)'/g)].map(m => m[1]));
    for (const k of used) expect(en[k], `en.json lacks ${k}`).toBeTypeOf('string');
  });
  it('shares the app glossary (the same word for "seal", "original file"... in each language)', () => {
    for (const l of LOCALES) { const d = dict(l);
      for (const [key, terms] of Object.entries(G.uses)) { expect(d[key], `${l}.${key} missing`).toBeTypeOf('string');
        for (const term of terms) expect(d[key].toLowerCase(), `${l}.${key} must use glossary term ${term}`).toContain(G.terms[term][l].toLowerCase()); } }
  });
  it('uses the P24/P25 wording (supersedes spec §7.3)', () => {
    const vi = dict('vi'), en = dict('en');
    expect(en.verdict_green_exact).toBe('Unchanged since it was sealed'); expect(vi.verdict_green_exact).toBe('Chưa bị sửa kể từ lúc niêm phong');
    expect(en.verdict_info_not_compared).toBe('Seal is valid — photo not compared yet'); expect(vi.verdict_info_not_compared).toBe('Niêm phong hợp lệ — chưa so ảnh');
    expect(en.label_time).toBe('Sealed at'); expect(vi.label_time).toBe('Thời điểm niêm phong'); expect(vi.label_place).toBe('Vị trí niêm phong');
    expect(en.proves_title_neutral).toBe('What this check shows'); expect(vi.proves_title_neutral).toBe('Kiểm tra này cho thấy gì');
    expect(en.footer_app).toBe('Checked with CameraStamp — get the app'); expect(vi.footer_app).toBe('Kiểm tra bằng CameraStamp — tải app');
    expect(vi.verdict_red).toBe('Ảnh hoặc thông tin đã bị thay đổi'); expect(vi.footer_local).toBe('Kiểm tra ngay trên máy bạn');
    expect(vi.footer_upload).toBe('Ảnh không được tải lên');
  });
  // P44: level 1 is a 64-bit perceptual hash: it shows the picture MATCHES what was sealed, never that it is unchanged or that any edit
  // shows. "Unchanged" belongs to the exact bytes of a bound original only (verdict_green_exact, check_content_c2pa, l2_signature_ok).
  it('P44: level-1 copy says "matches what was sealed" and never claims unchanged / not edited / any change detected', () => {
    const en = dict('en'), vi = dict('vi');
    expect(en.verdict_green).toBe('Matches what was sealed'); expect(vi.verdict_green).toBe('Khớp với lúc niêm phong');
    expect(en.proves_small_edits).toMatch(/^Noticeable changes to the picture are detected; tiny edits may not be/);
    expect(vi.proves_small_edits).toMatch(/^Thay đổi đáng kể trên ảnh sẽ bị phát hiện; chỉnh sửa rất nhỏ có thể không/);
    const L1 = ['verdict_green', 'verdict_green_sub', 'proves_l1', 'proves_small_edits', 'check_image_match', 'verdict_maybe_edited', 'check_image_maybe'];
    const OVER: Record<string, RegExp> = { en: /unchanged|not (been )?edited|not changed|any change|one detail|untouched/i,
      vi: /không đổi|chưa bị sửa|không bị (thay đổi|sửa)|mọi thay đổi|một chi tiết/i, hi: /नहीं बदल|बदला नहीं/, id: /tidak berubah|tidak diedit|setiap perubahan/i,
      es: /sin cambios|no ha cambiado|cualquier cambio/i, 'pt-BR': /sem altera|não mud|qualquer altera/i, it: /invariat|non è cambiat|qualsiasi modific/i,
      pl: /bez zmian|nie zmienił|każda zmiana/i, th: /ไม่เปลี่ยน/, ms: /tidak berubah|sebarang perubahan/i };
    for (const l of LOCALES) { const d = dict(l);
      for (const k of L1) expect(OVER[l].test(d[k]), `${l}.${k} overclaims: "${d[k]}"`).toBe(false);
      expect(d.verdict_green, l).not.toBe(d.verdict_green_exact); }
  });
  it('P42 / P41 / I4 copy: withheld location, maybe cropped, code not in the photo', () => {
    const en = dict('en'), vi = dict('vi');
    expect(en.info_location_withheld).toBe('Location not included in this seal'); expect(vi.info_location_withheld).toBe('Vị trí không nằm trong niêm phong này');
    expect(en.verdict_maybe_cropped).toBe('This photo may have been cropped'); expect(vi.verdict_maybe_cropped).toBe('Ảnh này có thể đã bị cắt');
    for (const l of LOCALES) { const d = dict(l);
      expect(d.info_location_withheld, l).not.toBe(d.info_no_location);
      for (const k of ['info_location_withheld', 'verdict_maybe_cropped', 'check_geometry_mismatch', 'verdict_code_not_in_photo', 'check_code_not_in_photo', 'verdict_l2_resaved'])
        expect(d[k], `${l}.${k}`).toBeTypeOf('string'); }
    expect(en.info_location_withheld).not.toMatch(/no location/i);
  });
  it('has the NO_FINGERPRINT copy (P26/P28) in every locale', () => {
    const en = dict('en'), vi = dict('vi');
    expect(en.verdict_too_flat).toBe('Details valid — this photo is too dark or flat to compare');
    expect(en.verdict_flat_mismatch).toBe("This photo isn't dark or flat — the seal belongs to a different photo");
    expect(vi.verdict_too_flat).toBe('Thông tin hợp lệ — ảnh quá tối hoặc quá ít chi tiết để so');
    for (const l of LOCALES) for (const k of ['verdict_too_flat', 'check_too_flat', 'verdict_flat_mismatch', 'check_flat_mismatch'])
      expect(dict(l)[k], `${l}.${k}`).toBeTypeOf('string');
  });
  it('no locale claims "real / authentic / genuine / true / taken with" (P25); only the glossary\'s "real device" may say real', () => {
    for (const l of LOCALES) { const { allow, ban } = BANNED[l];
      for (const [k, raw] of Object.entries(dict(l))) { let s = raw.toLowerCase(); for (const a of allow) s = s.replace(a, ' ');
        for (const w of ban) expect(new RegExp(w.source, "u").test(s), `${l}.${k} uses banned ${w}: "${raw}"`).toBe(false); } }
  });
  it('Hindi never uses the ambiguous "की" for "key" (it is also the genitive particle): the key is कुंजी', () => {
    const hi = dict('hi'); for (const k of ['check_seal_ok', 'proves_l1', 'warn_software_key', 'l2_chain_ok', 'l2_level_hw', 'l2_qr_link', 'l2_binding_bad'])
      expect(hi[k], k).toContain('कुंजी');
    expect(hi.check_seal_ok).not.toMatch(/(^|\s)की\s/);
  });
  it('Task 21 carry-over: "real device" is worded as a key in a real device\'s secure hardware, never "Real device confirmed"', () => {
    const en = dict('en'), vi = dict('vi');
    expect(en.l2_real_device).toBe('Sealed by a key in the secure hardware of a real device (an Android phone)');
    expect(en.l2_qr_link).toBe("This QR was sealed by the same key, kept in a real device's secure hardware");
    expect(vi.l2_real_device).toBe('Niêm phong bằng khoá trong phần cứng bảo mật của một máy thật (điện thoại Android)');
    expect(en.l2_level_sw).toMatch(/^Software key .*lower trust$/);
    for (const l of LOCALES) for (const k of ['l2_real_device', 'l2_qr_link']) expect(dict(l)[k], `${l}.${k}`).not.toMatch(/confirm|xác nhận máy|dikonfirmasi|confirmad|confermat|potwierdzon|ยืนยันเครื่อง|disahkan sebagai|पुष्टि/iu);
  });
  it('picks the browser language, falling back sensibly', () => {
    expect(pickLocale(['vi-VN', 'en'])).toBe('vi'); expect(pickLocale(['pt-PT'])).toBe('pt-BR'); expect(pickLocale(['es-MX'])).toBe('es');
    expect(pickLocale(['in'])).toBe('id'); expect(pickLocale(['de-DE'])).toBe('en'); expect(pickLocale([])).toBe('en');
    expect(pickLocale(['de', 'th-TH'])).toBe('th');
  });
  it('fills placeholders and never returns undefined', () => { expect(t({ a: 'x {n} y' }, 'a', { n: 3 })).toBe('x 3 y'); expect(t({}, 'missing')).toBe('missing'); });
});
