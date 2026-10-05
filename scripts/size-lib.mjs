// Gzipped size of a manifest entry plus everything it can load: static AND dynamic imports, their CSS, and assets that the JS
// references by URL (a `new Worker(new URL(...))` chunk is not in the manifest's import lists).
import { gzipSync } from 'node:zlib';
export const gz = (b) => gzipSync(b, { level: 9 }).length;
export function closure(manifest, key) {
  const seen = new Set(); const files = new Set();
  const walk = (k) => {
    if (seen.has(k)) return; seen.add(k);
    const c = manifest[k]; if (!c) throw new Error('manifest has no chunk ' + k);
    files.add(c.file); (c.css ?? []).forEach((x) => files.add(x));
    [...(c.imports ?? []), ...(c.dynamicImports ?? [])].forEach(walk);
  };
  walk(key); return [...files];
}
/** Adds every `assets/*.js` that a file in the set names in its text (worker chunks), transitively. */
export function withReferenced(files, read) {
  const out = new Set(files); const todo = [...files];
  while (todo.length) { const f = todo.pop(); if (!f.endsWith('.js')) continue;
    for (const m of read(f).toString('utf8').matchAll(/assets\/[\w.-]+\.js/g)) if (!out.has(m[0])) { out.add(m[0]); todo.push(m[0]); } }
  return [...out];
}
/**
 * What one visitor of level 1 downloads, at most: the whole closure, except that of the locale chunks (`isLocale(src)`) only the
 * largest counts, since a visitor loads one language (plus English only if they switch).
 */
export function levelOne(manifest, key, read, isLocale) {
  const all = withReferenced(closure(manifest, key), read);
  const locale = new Set(Object.values(manifest).filter((c) => c.src && isLocale(c.src)).map((c) => c.file));
  const rest = all.filter((f) => !locale.has(f));
  const biggest = [...locale].filter((f) => all.includes(f)).sort((a, b) => gz(read(b)) - gz(read(a)))[0];
  const files = biggest ? [...rest, biggest] : rest;
  return { files, total: files.reduce((n, f) => n + gz(read(f)), 0) };
}
export function closureSize(manifest, key, read) {
  return closure(manifest, key).reduce((n, f) => n + gz(read(f)), 0);
}
/**
 * Level-2 code must never reach level 1, however small the leak (a plain `import '@contentauth/c2pa-web'` adds only ~13 KB gz and would
 * pass the byte budget). Markers: WebAssembly (c2pa-web's loader; level 1's CSP has no wasm-unsafe-eval), c2pa_bg (its wasm-bindgen glue),
 * X509 (a certificate library), and the Android KeyDescription OID that only src/l2/attestation.ts names. Returns the offending "file: marker" pairs.
 */
export const L2_MARKERS = ['WebAssembly', 'c2pa_bg', 'X509', '1.3.6.1.4.1.11129.2.1.17'];
export function leaks(files, read, markers = L2_MARKERS) {
  const out = [];
  for (const f of files) { if (!f.endsWith('.js')) continue; const s = read(f).toString('utf8'); for (const m of markers) if (s.includes(m)) out.push(`${f}: ${m}`); }
  return out;
}
