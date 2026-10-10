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
// Part 4B: the deployed page never registers the debug key (P36; it is DEV only in the `--mode e2e` build) and does register Play's.
import { readdirSync } from 'node:fs';
const assets = readdirSync('dist/assets').filter(f => f.endsWith('.js')).map(f => readFileSync('dist/assets/' + f, 'utf8')).join('\n');
if (assets.includes('6dcef54931f170eff8e8d53bd77e62ec66c078479a6141411d08b00287077602')) { console.error('debug signing digest in the deployed build'); process.exit(1); }
if (!assets.includes('b0ff802fd83926409ce0bab830a7ec9d292d86513ad661401c6a836586d07502')) { console.error('Play App Signing digest missing from the build'); process.exit(1); }
console.log('signing digests: Play only');
