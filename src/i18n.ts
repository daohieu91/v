export const LOCALES = ['en', 'hi', 'id', 'es', 'pt-BR', 'it', 'pl', 'vi', 'th', 'ms'] as const;
/** Each language in its own name, for the switcher. */
export const NATIVE: Record<string, string> = { en: 'English', hi: 'हिन्दी', id: 'Bahasa Indonesia', es: 'Español', 'pt-BR': 'Português (Brasil)',
  it: 'Italiano', pl: 'Polski', vi: 'Tiếng Việt', th: 'ไทย', ms: 'Bahasa Melayu' };
export function pickLocale(langs: readonly string[]): string {
  for (const raw of langs) { const l = raw.toLowerCase(); const base = l.split('-')[0];
    const exact = LOCALES.find(x => x.toLowerCase() === l); if (exact) return exact;
    if (base === 'pt') return 'pt-BR'; if (base === 'in') return 'id';
    const b = LOCALES.find(x => x.toLowerCase() === base); if (b) return b; }
  return 'en';
}
const loaders: Record<string, () => Promise<{ default: Record<string, string> }>> = {
  en: () => import('./i18n/en.json'), hi: () => import('./i18n/hi.json'), id: () => import('./i18n/id.json'), es: () => import('./i18n/es.json'),
  'pt-BR': () => import('./i18n/pt-BR.json'), it: () => import('./i18n/it.json'), pl: () => import('./i18n/pl.json'), vi: () => import('./i18n/vi.json'),
  th: () => import('./i18n/th.json'), ms: () => import('./i18n/ms.json'),
};
export async function loadDict(l: string): Promise<Record<string, string>> { return (await (loaders[l] ?? loaders.en)()).default; }
export function t(d: Record<string, string>, key: string, p?: Record<string, string | number>): string {
  return (d[key] ?? key).replace(/\{(\w+)\}/g, (_, k: string) => (p && k in p ? String(p[k]) : `{${k}}`));
}
