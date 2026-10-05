import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
const csp = (f: string) => /<meta http-equiv="Content-Security-Policy" content="([^"]+)"/.exec(readFileSync(f, 'utf8'))?.[1] ?? '';
describe('CSP', () => {
  it('level 1 page allows nothing but itself, and no wasm', () => {
    const c = csp('index.html');
    expect(c).toContain("default-src 'self'"); expect(c).toContain("script-src 'self'"); expect(c).toContain("connect-src 'self'");
    expect(c).not.toContain('wasm-unsafe-eval'); expect(c).not.toContain('unsafe-inline'); expect(c).not.toMatch(/https?:/);
  });
  it('level 2 page alone may compile wasm', () => {
    const c = csp('l2.html');
    expect(c).toContain("script-src 'self' 'wasm-unsafe-eval'"); expect(c).toContain("connect-src 'self'"); expect(c).not.toMatch(/https?:/);
  });
  it('no third-party script, analytics or cookie anywhere in the HTML', () => {
    for (const f of ['index.html', 'l2.html']) { const h = readFileSync(f, 'utf8');
      expect(h).not.toMatch(/<script[^>]+src="https?:/); expect(h).not.toMatch(/gtag|googletagmanager|analytics|document\.cookie/i); }
  });
});
