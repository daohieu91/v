import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
const html = (f: string) => readFileSync(f, 'utf8');
const csp = (f: string) => /<meta http-equiv="Content-Security-Policy" content="([^"]+)"/.exec(html(f))?.[1] ?? '';
const PAGES = ['index.html', 'l2.html'];

describe.each(PAGES)('CSP of %s', (f) => {
  it('closes every default door', () => {
    const c = csp(f);
    expect(c).toContain("default-src 'self'");
    expect(c).toContain("connect-src 'self'");
    expect(c).toContain("object-src 'none'");
    expect(c).toContain("base-uri 'none'");
    expect(c).toContain("form-action 'none'");
  });
  it('allows no eval, no inline, no remote origin', () => {
    const c = csp(f);
    expect(c).not.toContain("'unsafe-eval'");
    expect(c).not.toContain("'unsafe-inline'");
    expect(c).not.toMatch(/https?:/);
  });
  it('sends no referrer', () => {
    expect(html(f)).toContain('<meta name="referrer" content="no-referrer">');
  });
  it('has no third-party script, analytics or cookie', () => {
    const h = html(f);
    expect(h).not.toMatch(/<script[^>]+src="https?:/);
    expect(h).not.toMatch(/gtag|googletagmanager|analytics|document\.cookie/i);
  });
});

describe('page-specific CSP', () => {
  it('level 1 page: self scripts only, no wasm, frames restricted to self', () => {
    const c = csp('index.html');
    expect(c).toContain("script-src 'self'");
    expect(c).not.toContain('wasm-unsafe-eval');
    expect(c).toContain("frame-src 'self'");
  });
  it('level 2 page alone may compile wasm', () => {
    expect(csp('l2.html')).toContain("script-src 'self' 'wasm-unsafe-eval'");
  });
});
