// Gzipped size of a manifest entry plus everything it can load: static AND dynamic imports, and their CSS.
import { gzipSync } from 'node:zlib';
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
export function closureSize(manifest, key, read) {
  return closure(manifest, key).reduce((n, f) => n + gzipSync(read(f)).length, 0);
}
