import { describe, expect, it } from 'vitest';
import { decodeCbor } from '../../src/l2/cbor';
const h = (s: string) => Uint8Array.from(s.match(/../g)!.map(x => parseInt(x, 16)));
// RFC 8949 Appendix A vectors.
describe('cbor', () => {
  it.each([['00', 0], ['17', 23], ['1818', 24], ['1a000f4240', 1000000], ['20', -1], ['6161', 'a'], ['f4', false], ['f5', true], ['f6', null]])('%s', (hex, v) => expect(decodeCbor(h(hex))).toEqual(v));
  it('bytes, arrays, maps, tags', () => {
    expect(decodeCbor(h('4401020304'))).toEqual(h('01020304'));
    expect(decodeCbor(h('8201820203'))).toEqual([1, [2, 3]]);
    const m = decodeCbor(h('a26161016162820203')) as Map<unknown, unknown>; expect(m.get('a')).toBe(1); expect(m.get('b')).toEqual([2, 3]);
    expect(decodeCbor(h('d28140'))).toEqual({ tag: 18, value: [new Uint8Array()] });
    expect(decodeCbor(h('5f42010243030405ff'))).toEqual(h('0102030405'));     // indefinite byte string
    expect(decodeCbor(h('1bffffffffffffffff'))).toBe(18446744073709551615n);
  });
  it('truncated or hostile input throws at once, never reads past the end or hangs', () => {
    for (const bad of ['', '18', '1a000f42', '44010203', '9f01', '5f4201', 'bf6161', '82', 'a1', '7a7fffffff']) expect(() => decodeCbor(h(bad)), bad).toThrow();
    expect(() => decodeCbor(new Uint8Array(200).fill(0x81))).toThrow(/depth|eof/);         // [[[[…]]]] nested past 64
  });
});
