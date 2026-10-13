import { PLAY_URL } from './config';
import { LOCALES, NATIVE, t } from './i18n';
import type { SealPayload } from './payload';
import type { Verdict } from './verdict';
const el = <K extends keyof HTMLElementTagNameMap>(tag: K, attrs: Record<string, string> = {}, text?: string) => {
  const e = document.createElement(tag); for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v); if (text !== undefined) e.textContent = text; return e; };
/** A line key the dictionary does not know (e.g. from a newer level 2) is shown as a generic line, never as raw text. */
export const line = (d: Record<string, string>, key: string, p?: Record<string, string | number>) => (key in d ? t(d, key, p) : t(d, 'unknown_line'));
/** Languages written right to left: the page mirrors (dir=rtl); numbers, coordinates and key ids stay LTR inside <bdi dir="ltr">. */
export const RTL = new Set(['ar']);
const ltr = (text: string) => el('bdi', { dir: 'ltr' }, text);
/** Placeholder values that are Latin machine text (a key id, a UTC time, a YYYY-MM-DD date, a TSA name): isolated so an RTL line
 *  cannot reorder them (an Arabic paragraph would show 2026-10-13 as 13-10-2026). Plain numbers ({n}, {d}, {m}…) need no isolate. */
const LTR_PARAMS = new Set(['id', 'time', 'date', 'tsa']);
/** `line`, as DOM: the same text, with LTR_PARAMS values each in its own <bdi dir="ltr">. */
function lineInto<E extends HTMLElement>(e: E, d: Record<string, string>, key: string, p?: Record<string, string | number>): E {
  const tpl = key in d ? d[key] : d.unknown_line ?? 'unknown_line'; let at = 0;
  for (const m of tpl.matchAll(/\{(\w+)\}/g)) { const k = m[1]; e.append(tpl.slice(at, m.index));
    e.append(p && k in p ? (LTR_PARAMS.has(k) ? ltr(String(p[k])) : String(p[k])) : `{${k}}`); at = m.index + m[0].length; }
  e.append(tpl.slice(at)); return e;
}
const pad = (n: number) => String(n).padStart(2, '0');
/** The date and time part of formatTime, with Latin digits in every language (spec 4C-1 §3.5: ar-EG would print Arabic-Indic). */
function formatDate(epoch: number, offMin: number, locale: string): string {
  const d = new Date((epoch + offMin * 60) * 1000);
  try { return new Intl.DateTimeFormat(locale, { timeZone: 'UTC', dateStyle: 'full', timeStyle: 'medium', numberingSystem: 'latn' }).format(d); }
  catch { return d.toISOString().slice(0, 19).replace('T', ' '); }
}
const gmt = (offMin: number) => { const a = Math.abs(offMin); return `GMT${offMin < 0 ? '-' : '+'}${pad(Math.floor(a / 60))}:${pad(a % 60)}`; };
/** The capture time in the zone it was taken in: epoch + offset, shown with the offset (spec §7.3). */
export function formatTime(epoch: number, offMin: number, locale: string): string { return `${formatDate(epoch, offMin, locale)} ${gmt(offMin)}`; }
export interface View { dict: Record<string, string>; locale: string; verdict: Verdict | 'pending' | null; payload: SealPayload | null;
  message: string | null; notice?: string | null; attested: string | null | undefined; onPick: (f: File) => void; onLocale: (l: string) => void }
/** Verdict-first DOM. textContent and setAttribute only: nothing from the payload is ever parsed as HTML. */
export function render(root: HTMLElement, s: View) {
  const d = s.dict; root.replaceChildren();
  document.documentElement.lang = s.locale; document.documentElement.dir = RTL.has(s.locale) ? 'rtl' : 'ltr'; document.title = `${t(d, 'title')} · ${t(d, 'brand')}`;
  const head = el('header'); head.append(el('h1', {}, t(d, 'title')));
  const sel = el('select', { 'data-lang': '', 'aria-label': t(d, 'lang_label') });
  for (const l of LOCALES) { const o = el('option', { value: l, lang: l }, NATIVE[l]); if (l === s.locale) o.setAttribute('selected', ''); sel.append(o); }
  sel.addEventListener('change', () => s.onLocale(sel.value)); head.append(sel); root.append(head);
  const v = s.verdict;
  const band = el('section', { 'data-verdict': v === 'pending' ? 'pending' : v ? v.color : 'none', class: 'band', role: 'status' }, v === 'pending' ? t(d, 'working') : '');
  if (v && v !== 'pending') lineInto(band, d, v.headline, v.checks.find(c => c.key === v.headline)?.params);
  root.append(band);
  if (v && v !== 'pending' && v.sub) root.append(lineInto(el('p', { class: 'band-sub', 'data-sub': v.sub.key }), d, v.sub.key, v.sub.params));
  if (s.message) root.append(el('p', { class: 'message' }, line(d, s.message)));
  if (s.notice && v && v !== 'pending') root.append(el('p', { class: 'message notice', 'data-notice': s.notice }, line(d, s.notice)));
  const p = s.payload?.fields;
  if (v && v !== 'pending') {
    if (p && v.checks[0]?.key === 'check_seal_ok') {   // fields of a broken seal are not trustworthy: never present them as facts
      const facts = el('dl', { class: 'facts' });
      const time = el('dd', { 'data-field': 'time' }); time.append(formatDate(p.epochSeconds, p.tzOffsetMinutes, s.locale) + ' ', ltr(gmt(p.tzOffsetMinutes)));
      facts.append(el('dt', {}, t(d, 'label_time')), time);
      if (p.location) {
        const lat = (p.location.latE5 / 1e5).toFixed(5), lng = (p.location.lngE5 / 1e5).toFixed(5);
        const place = el('dd', { 'data-field': 'place' }); place.append(ltr(`${lat}, ${lng}`));
        if (p.location.accuracyM < 65535) place.append(' ' + t(d, 'label_accuracy', { m: p.location.accuracyM }));
        facts.append(el('dt', {}, t(d, 'label_place')), place);
        const dd = el('dd'); dd.append(el('a', { 'data-map': '', class: 'map', href: `https://www.openstreetmap.org/?mlat=${lat}&mlon=${lng}#map=17/${lat}/${lng}`,
          target: '_blank', rel: 'noopener noreferrer' }, t(d, 'map_button')));
        facts.append(dd, el('dd', { class: 'note' }, t(d, 'address_note')));
      }
      root.append(facts);
    }
    const list = el('ul', { class: 'checks' }); const proves = el('ul', { class: 'checks proves' });
    for (const c of v.checks) (c.key.startsWith('proves_') ? proves : list).append(lineInto(el('li', { 'data-status': c.status, 'data-key': c.key }), d, c.key, c.params));
    root.append(list);
    if (proves.childElementCount) { const sec = el('section', { class: 'explain' }); sec.append(el('h2', {}, t(d, v.color === 'green' ? 'proves_title' : 'proves_title_neutral')), proves); root.append(sec); }
  }
  const input = el('input', { type: 'file', accept: 'image/*,video/mp4' });
  input.addEventListener('change', () => { const f = input.files?.[0]; if (f) s.onPick(f); });
  const label = el('label', { class: 'pick' }); label.append(el('span', {}, t(d, 'pick_photo')), input); root.append(label);
  const foot = el('footer');
  const line_ = el('p'); line_.append(el('span', {}, t(d, 'footer_local')), el('span', { 'aria-hidden': 'true' }, ' · '), el('span', {}, t(d, 'footer_upload')),
    el('span', { 'aria-hidden': 'true' }, ' · '), el('a', { 'data-play': '', href: PLAY_URL, target: '_blank', rel: 'noopener noreferrer' }, t(d, 'footer_app')));
  foot.append(line_);
  foot.append(el('p', { class: 'small', 'data-privacy': '' }, t(d, 'privacy_history')));
  if (s.attested !== undefined) foot.append(lineInto(el('p', { 'data-attested': '', class: 'small' }), d, s.attested ? 'attested_on' : 'attested_unknown', s.attested ? { date: s.attested } : undefined));
  root.append(foot);
}
