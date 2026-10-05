// Spec §2.7: the level-1 part stays under 100 KB gzipped. Fails the build otherwise. BUDGET env overrides (bytes).
import { readFileSync } from 'node:fs';
import { gz, leaks, levelOne } from './size-lib.mjs';
const BUDGET = Number(process.env.BUDGET ?? 100_000);
const m = JSON.parse(readFileSync('dist/.vite/manifest.json', 'utf8'));
if (!m['index.html']) { console.error('index.html missing from manifest'); process.exit(1); }
const read = (f) => readFileSync('dist/' + f);
const { files, total } = levelOne(m, 'index.html', read, (src) => /^src\/i18n\/[\w-]+\.json$/.test(src));
const html = gz(read('index.html'));
for (const f of files) console.log(`  ${String(gz(read(f))).padStart(6)}  ${f}`);
console.log(`  ${String(html).padStart(6)}  index.html`);
console.log(`level-1 gzip total: ${total + html} B (budget ${BUDGET})`);
if (!(total + html < BUDGET)) { console.error('over the level-1 budget'); process.exit(1); }
const bad = leaks(files, read);
if (bad.length) { console.error('level-2 code in level 1: ' + bad.join(', ')); process.exit(1); }
