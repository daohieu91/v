import { describe, expect, it } from 'vitest';
import { topIsCrossOrigin } from '../src/framing';
const loc = { href: 'https://daohieu91.github.io/v/' };
describe('framing guard', () => {
  it('top-level page is left alone', () => {
    const w: any = { location: loc }; w.self = w; w.top = w;
    expect(topIsCrossOrigin(w)).toBe(false);
  });
  it('same-origin parent (index embedding l2) is left alone', () => {
    expect(topIsCrossOrigin({ self: {}, top: { location: loc }, location: loc })).toBe(false);
  });
  it('cross-origin parent is detected (location access throws)', () => {
    const top = { get location(): never { throw new DOMException('blocked', 'SecurityError'); } };
    expect(topIsCrossOrigin({ self: {}, top: top as any, location: loc })).toBe(true);
  });
});
