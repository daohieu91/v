import { expect, it } from 'vitest';
import { parseCheckedAt } from '../src/attestation-date';
it('accepts only a plain date', () => {
  expect(parseCheckedAt({ checkedAt: '2026-10-05' })).toBe('2026-10-05');
  for (const bad of [null, {}, { checkedAt: '<img>' }, { checkedAt: 5 }, { checkedAt: 'x2026-10-05' }, { checkedAt: '2026-10-05\n' }]) expect(parseCheckedAt(bad)).toBeNull();
});
