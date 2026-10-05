import { PLAY_URL } from './config';
import { LOCALES, NATIVE, t } from './i18n';
import type { SealPayload } from './payload';
import type { Verdict } from './verdict';
const el = <K extends keyof HTMLElementTagNameMap>(tag: K, attrs: Record<string, string> = {}, text?: string) => {
  const e = document.createElement(tag); for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v); if (text !== undefined) e.textContent = text; return e; };
/** A line key the dictionary does not know (e.g. from a newer level 2) is shown as a generic line, never as raw text. */
export const line = (d: Record<string, string>, key: string, p?: Record<string, string | number>) => (key in d ? t(d, key, p) : t(d, 'unknown_line'));
const pad = (n: number) => String(n).padStart(2, '0');
/** The capture time in the zone it was taken in: epoch + offset, shown with the offset (spec §7.3). */
export function formatTime(epoch: number, offMin: number, locale: string): string {
  const d = new Date((epoch + offMin * 60) * 1000);
  let s: string; try { s = new Intl.DateTimeFormat(locale, { timeZone: 'UTC', dateStyle: 'full', timeStyle: 'medium' }).format(d); } catch { s = d.toISOString().slice(0, 19).replace('T', ' '); }
  const sign = offMin < 0 ? '-' : '+'; const a = Math.abs(offMin);
  return `${s} GMT${sign}${pad(Math.floor(a / 60))}:${pad(a % 60)}`;
}
export interface View { dict: Record<string, string>; locale: string; verdict: Verdict | 'pending' | null; payload: SealPayload | null;
  message: string | null; notice?: string | null; attested: string | null | undefined; onPick: (f: File) => void; onLocale: (l: string) => void }
/** Verdict-first DOM. textContent and setAttribute only: nothing from the payload is ever parsed as HTML. */
export function render(root: HTMLElement, s: View) {
  const d = s.dict; root.replaceChildren();
  document.documentElement.lang = s.locale; document.title = `${t(d, 'title')} · ${t(d, 'brand')}`;
  const head = el('header'); head.append(el('h1', {}, t(d, 'title')));
  const sel = el('select', { 'data-lang': '', 'aria-label': t(d, 'lang_label') });
  for (const l of LOCALES) { const o = el('option', { value: l, lang: l }, NATIVE[l]); if (l === s.locale) o.setAttribute('selected', ''); sel.append(o); }
  sel.addEventListener('change', () => s.onLocale(sel.value)); head.append(sel); root.append(head);
  const v = s.verdict;
  root.append(el('section', { 'data-verdict': v === 'pending' ? 'pending' : v ? v.color : 'none', class: 'band', role: 'status' },
    v === 'pending' ? t(d, 'working') : v ? line(d, v.headline, v.checks.find(c => c.key === v.headline)?.params) : ''));
  if (s.message) root.append(el('p', { class: 'message' }, line(d, s.message)));
  if (s.notice && v && v !== 'pending') root.append(el('p', { class: 'message notice', 'data-notice': s.notice }, line(d, s.notice)));
  const p = s.payload?.fields;
  if (v && v !== 'pending') {
    if (p && v.checks[0]?.key === 'check_seal_ok') {   // fields of a broken seal are not trustworthy: never present them as facts
      const facts = el('dl', { class: 'facts' });
      facts.append(el('dt', {}, t(d, 'label_time')), el('dd', { 'data-field': 'time' }, formatTime(p.epochSeconds, p.tzOffsetMinutes, s.locale)));
      if (p.location) {
        const lat = (p.location.latE5 / 1e5).toFixed(5), lng = (p.location.lngE5 / 1e5).toFixed(5);
        facts.append(el('dt', {}, t(d, 'label_place')),
          el('dd', { 'data-field': 'place' }, `${lat}, ${lng}` + (p.location.accuracyM < 65535 ? ' ' + t(d, 'label_accuracy', { m: p.location.accuracyM }) : '')));
        const dd = el('dd'); dd.append(el('a', { 'data-map': '', class: 'map', href: `https://www.openstreetmap.org/?mlat=${lat}&mlon=${lng}#map=17/${lat}/${lng}`,
          target: '_blank', rel: 'noopener noreferrer' }, t(d, 'map_button')));
        facts.append(dd, el('dd', { class: 'note' }, t(d, 'address_note')));
      }
      root.append(facts);
    }
    const list = el('ul', { class: 'checks' }); const proves = el('ul', { class: 'checks proves' });
    for (const c of v.checks) (c.key.startsWith('proves_') ? proves : list).append(el('li', { 'data-status': c.status, 'data-key': c.key }, line(d, c.key, c.params)));
    root.append(list);
    if (proves.childElementCount) { const sec = el('section', { class: 'explain' }); sec.append(el('h2', {}, t(d, 'proves_title')), proves); root.append(sec); }
  }
  const input = el('input', { type: 'file', accept: 'image/*,video/mp4' });
  input.addEventListener('change', () => { const f = input.files?.[0]; if (f) s.onPick(f); });
  const label = el('label', { class: 'pick' }); label.append(el('span', {}, t(d, 'pick_photo')), input); root.append(label);
  const foot = el('footer');
  const line_ = el('p'); line_.append(el('span', {}, t(d, 'footer_local')), el('span', { 'aria-hidden': 'true' }, ' · '), el('span', {}, t(d, 'footer_upload')),
    el('span', { 'aria-hidden': 'true' }, ' · '), el('a', { 'data-play': '', href: PLAY_URL, target: '_blank', rel: 'noopener noreferrer' }, t(d, 'footer_app')));
  foot.append(line_);
  foot.append(el('p', { class: 'small', 'data-privacy': '' }, t(d, 'privacy_history')));
  if (s.attested !== undefined) foot.append(el('p', { 'data-attested': '', class: 'small' }, s.attested ? t(d, 'attested_on', { date: s.attested }) : t(d, 'attested_unknown')));
  root.append(foot);
}
