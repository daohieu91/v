// Fails the build if the level-1 entry closure (JS + CSS, gzipped) exceeds its budget. BUDGET env overrides (bytes).
import { readFileSync } from 'node:fs';
import { closureSize } from './size-lib.mjs';
const BUDGET = Number(process.env.BUDGET ?? 60 * 1024);
const m = JSON.parse(readFileSync('dist/.vite/manifest.json', 'utf8'));
if (!m['index.html']) { console.error('index.html missing from manifest'); process.exit(1); }
const total = closureSize(m, 'index.html', (f) => readFileSync('dist/' + f));
console.log(`level-1 closure: ${total} B gzipped (budget ${BUDGET})`);
if (!(total <= BUDGET)) process.exit(1);
