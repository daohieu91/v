import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
// @ts-expect-error plain .mjs
import { closure, closureSize } from '../scripts/size-lib.mjs';
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
});
