// Fails the build if the level-1 entry (JS + CSS, gzipped) exceeds its budget.
import { readFileSync } from 'node:fs';
import { gzipSync } from 'node:zlib';
const BUDGET = 60 * 1024;
const m = JSON.parse(readFileSync('dist/.vite/manifest.json', 'utf8'));
const e = m['index.html'];
if (!e) { console.error('index.html missing from manifest'); process.exit(1); }
const files = [e.file, ...(e.css ?? [])];
const total = files.reduce((n, f) => n + gzipSync(readFileSync('dist/' + f)).length, 0);
console.log(`level-1 entry: ${total} B gzipped (budget ${BUDGET})`);
if (total > BUDGET) process.exit(1);
