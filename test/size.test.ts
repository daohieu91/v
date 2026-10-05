import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
// @ts-expect-error plain .mjs
import { closure, closureSize, leaks, levelOne, withReferenced } from '../scripts/size-lib.mjs';
const big = randomBytes(5000); const small = Buffer.from('x');
const files: Record<string, Buffer> = { 'a.js': small, 'b.js': small, 'dyn.js': big, 'c.css': small };
const m = {
  'index.html': { file: 'a.js', imports: ['b'], dynamicImports: ['dyn'] },
  b: { file: 'b.js', css: ['c.css'] },
  dyn: { file: 'dyn.js' },
};
describe('size closure', () => {
  it('walks static imports, css and dynamic imports', () => {
    expect(closure(m, 'index.html').sort()).toEqual(['a.js', 'b.js', 'c.css', 'dyn.js']);
  });
  it('a big dynamically imported module counts toward the size', () => {
    expect(closureSize(m, 'index.html', (f: string) => files[f])).toBeGreaterThan(5000);
  });
  it('tolerates import cycles', () => {
    const cyc = { x: { file: 'a.js', imports: ['y'] }, y: { file: 'b.js', imports: ['x'] } };
    expect(closure(cyc, 'x').length).toBe(2);
  });
  it('counts a worker the JS names by URL, transitively', () => {
    const f: Record<string, Buffer> = { 'assets/a.js': Buffer.from('new Worker(new URL(`assets/w-1.js`))'), 'assets/w-1.js': Buffer.from('"assets/w-2.js"'), 'assets/w-2.js': big };
    expect(withReferenced(['assets/a.js'], (x: string) => f[x]).sort()).toEqual(['assets/a.js', 'assets/w-1.js', 'assets/w-2.js']);
  });
  it('counts only the largest locale chunk', () => {
    const f: Record<string, Buffer> = { 'a.js': small, 'en.js': randomBytes(100), 'th.js': randomBytes(900) };
    const mm = { 'index.html': { file: 'a.js', dynamicImports: ['src/i18n/en.json', 'src/i18n/th.json'] },
      'src/i18n/en.json': { file: 'en.js', src: 'src/i18n/en.json' }, 'src/i18n/th.json': { file: 'th.js', src: 'src/i18n/th.json' } };
    const r = levelOne(mm, 'index.html', (x: string) => f[x], (s: string) => s.startsWith('src/i18n/'));
    expect(r.files.sort()).toEqual(['a.js', 'th.js']); expect(r.total).toBeGreaterThan(900);
  });
  it('flags level-2 code in a level-1 file', () => {
    const f: Record<string, Buffer> = { 'a.js': Buffer.from('WebAssembly.instantiate(x)'), 'b.js': Buffer.from('ok'), 'c.css': Buffer.from('WebAssembly') };
    expect(leaks(['a.js', 'b.js', 'c.css'], (x: string) => f[x])).toEqual(['a.js: WebAssembly']);
  });
});
