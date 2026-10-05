import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { level2, readFailure, type L2Deps } from '../../src/l2/level2';
// P35: what a reader failure means. Errors as c2pa-web 0.15.3 throws them (measured in Chromium on damaged copies of original_hw.jpg).
const file = new File([readFileSync('e2e/fixtures/original_hw.jpg')], 'o.jpg', { type: 'image/jpeg' });
const deps = (read: L2Deps['read'], deadlineMs = 200): L2Deps => ({ read, attestation: async () => ({ roots: [], status: { entries: {} } }), deadlineMs });
const keys = async (d: L2Deps) => { const r = await level2(file, null, d); return [r.summary.kind, r.summary.lines.map(l => l.key)]; };
describe('level 2 reader failures', () => {
  it('only a C2PA format/validation error is "the file was changed"', () => {
    expect(readFailure(new Error('C2pa(JumbfParseError(UnexpectedEof))'))).toBe('l2_invalid');
    expect(readFailure(new Error('C2pa(ClaimDecoding)'))).toBe('l2_invalid');
    for (const e of [new Error('C2pa(InvalidAsset("Could not parse input JPEG"))'), new RangeError('Out of memory'), new Error('RuntimeError: memory access out of bounds'),
      new Error('Worker terminated'), 'C2pa(Io)', null, undefined]) expect(readFailure(e), String(e)).toBe('l2_error');
  });
  it('a throw that is not a format error → l2_error ("couldn\'t read this file here"), never red', async () => {
    expect(await keys(deps(async () => { throw new RangeError('Out of memory'); }))).toEqual(['none', ['l2_error']]);
    expect(await keys(deps(async () => { throw new Error('C2pa(InvalidAsset("Could not parse input JPEG"))'); }))).toEqual(['none', ['l2_error']]);
    expect(await keys(deps(async () => { throw new Error('C2pa(JumbfParseError(UnexpectedEof))'); }))).toEqual(['invalid', ['l2_invalid']]);
  });
  it('a reader that hangs (crashed worker) ends at the deadline with l2_error, below the 60 s bridge timeout', async () => {
    const t0 = Date.now(); expect(await keys(deps(() => new Promise(() => undefined), 150))).toEqual(['none', ['l2_error']]); expect(Date.now() - t0).toBeLessThan(2000);
    const { READ_DEADLINE_MS } = await import('../../src/l2/level2'); expect(READ_DEADLINE_MS).toBeLessThan(60_000);
  });
  it('no C2PA data → l2_none', async () => expect(await keys(deps(async () => null))).toEqual(['none', ['l2_none']]));
});
