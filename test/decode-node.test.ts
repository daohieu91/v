import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { describe, expect, it } from 'vitest';
import { decodeLikeThePage, iccDescription } from '../scripts/decode-node';
import { BROWSER_RGBA } from './helpers/browser-rgba';
const sha = (b: Uint8ClampedArray) => createHash('sha256').update(b).digest('hex');
describe('verify-file decode (scripts/decode-node.ts) = the browsers\' decode', () => {
  it('is byte-identical to Chromium and Firefox on the fixtures', async () => {
    for (const [f, want] of Object.entries(BROWSER_RGBA)) {
      const im = await decodeLikeThePage(new Uint8Array(readFileSync('e2e/fixtures/' + f)));
      expect([im.w, im.h, im.via], f).toEqual([1600, 1200, 'plain']); expect(sha(im.data), f).toBe(want);
    }
  });
  it('follows the page\'s size plan: a 48 MP EXIF-rotated photo comes out upright at the bounded 4000 × 3000', async () => {
    const im = await decodeLikeThePage(new Uint8Array(readFileSync('e2e/fixtures/rotated_portrait_48mp.jpg')));
    expect([im.w, im.h, im.via]).toEqual([4000, 3000, 'resize']);
  });
  it('reads the ICC description (v4 mluc) that decides whether to skip the colour transform', () => {
    const jpg = readFileSync('e2e/fixtures/sealed_1600_q70.jpg'); const at = jpg.indexOf('ICC_PROFILE\0');
    expect(iccDescription(new Uint8Array(jpg.subarray(at + 14, at + 2 + jpg.readUInt16BE(at - 2))))).toBe('sRGB');
    expect(iccDescription(undefined)).toBeNull(); expect(iccDescription(new Uint8Array(10))).toBeNull();
  });
  it('verify-file gives the page\'s verdicts, NO_FINGERPRINT included', () => {
    const run = (f: string) => JSON.parse(execFileSync('npx', ['tsx', 'scripts/verify-file.ts', 'e2e/fixtures/' + f], { encoding: 'utf8' }));
    expect(run('sealed_1600_q70.jpg')).toMatchObject({ verdict: 'green', distance: 0, texture: null, noFingerprint: false });
    expect(run('dark_sealed.jpg')).toMatchObject({ verdict: 'yellow', headline: 'verdict_too_flat', distance: null, noFingerprint: true });
    expect(run('bright_sealed.jpg')).toMatchObject({ verdict: 'red', headline: 'verdict_flat_mismatch', distance: null, noFingerprint: true });
  }, 60_000);
});
