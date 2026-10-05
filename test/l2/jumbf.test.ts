import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { activeSignature, coseSigner, extractJumbf, formatGenTime, tstInfo } from '../../src/l2/jumbf';
import { hex } from '../../src/l2/der';
import { commonName, ecPoint, parseCert } from '../../src/l2/x509';
// test/fixtures/c2pa/*: the APP's own writer (C2PA_LIB=SELF), copied from app/build/c2pa-conformance (solid-colour picture, public TEST
// key, all-0x01 payload, no location: P3). photo_multiseg.jpg's store spans 3 APP11 segments; photo_tsa.jpg holds a real DigiCert token.
const f = (p: string) => new Uint8Array(readFileSync(p));
const TEST_KEY = '043a336eeda2c82b3955c947e81fc5c79924b105eb5848efb13e1e4301790530577a20e06f004362e469c57cf6468e7b6de0aa5714034e461c5cbab4646717ec44';
async function signerOf(p: string, asBlob = false) {
  const bytes = f(p); const j = await extractJumbf(asBlob ? new Blob([bytes]) : bytes); expect(j, p).not.toBeNull();
  const cose = activeSignature(j!); expect(cose, p).not.toBeNull(); return coseSigner(cose!);
}
describe('jumbf/cose', () => {
  it('finds the active manifest signature and its x5chain in the app\'s photo and video (bytes and File slices agree)', async () => {
    for (const p of ['test/fixtures/c2pa/photo.jpg', 'test/fixtures/c2pa/video.mp4', 'e2e/fixtures/original_hw.jpg', 'e2e/fixtures/original_video.mp4']) {
      const s = await signerOf(p); expect(s.x5chain.length, p).toBe(1);
      const c = parseCert(s.x5chain[0]); expect(hex(ecPoint(c)!), p).toBe(TEST_KEY); expect(commonName(c.subject)).toBe('CameraStamp seal f18fa21b6b1a2c70');
      expect((await signerOf(p, true)).x5chain[0], `${p} via Blob`).toEqual(s.x5chain[0]);
    }
  });
  it('reassembles a store split over several APP11 segments (packet headers skipped)', async () => {
    const one = await extractJumbf(f('test/fixtures/c2pa/photo_multiseg.jpg'));
    expect(one!.length).toBeGreaterThan(65535);
    const s = await signerOf('test/fixtures/c2pa/photo_multiseg.jpg'); expect(hex(ecPoint(parseCert(s.x5chain[0]))!)).toBe(TEST_KEY);
  });
  it('refuses APP11 packets out of order (a reordered store is not reassembled into something else)', async () => {
    const b = f('test/fixtures/c2pa/photo_multiseg.jpg'); const segs: [number, number][] = [];
    for (let i = 2; i + 4 <= b.length && b[i] === 0xff && b[i + 1] !== 0xda;) { const len = (b[i + 2] << 8) | b[i + 3]; if (b[i + 1] === 0xeb) segs.push([i, 2 + len]); i += 2 + len; }
    expect(segs.length).toBe(3); const [, s2, s3] = segs; expect(s2[0] + s2[1]).toBe(s3[0]);
    const swapped = new Uint8Array(b); swapped.set(b.subarray(s3[0], s3[0] + s3[1]), s2[0]); swapped.set(b.subarray(s2[0], s2[0] + s2[1]), s2[0] + s3[1]);
    expect(await extractJumbf(swapped)).toBeNull();
  });
  it('reads the DigiCert time-stamp (sigTst2): time and TSA name', async () => {
    const s = await signerOf('test/fixtures/c2pa/photo_tsa.jpg'); expect(s.tstTokens.length).toBe(1);
    const t = tstInfo(s.tstTokens[0])!; expect(t.genTime).toMatch(/^2026-\d\d-\d\d \d\d:\d\d:\d\d UTC$/); expect(t.tsaName).toMatch(/DigiCert/);
    expect((await signerOf('test/fixtures/c2pa/photo.jpg')).tstTokens).toEqual([]);
  });
  it('a plain JPEG or MP4 has no JUMBF; garbage gives null, never a throw', async () => {
    expect(await extractJumbf(f('e2e/fixtures/sealed.jpg'))).toBeNull();
    expect(await extractJumbf(f('e2e/fixtures/src/plain_3s.mp4'))).toBeNull();
    for (const g of [new Uint8Array(), Uint8Array.of(0xff, 0xd8, 0xff, 0xeb, 0, 2), new Uint8Array(64).fill(0xff)]) expect(await extractJumbf(g)).toBeNull();
    expect(activeSignature(new Uint8Array(40))).toBeNull(); expect(tstInfo(Uint8Array.of(0x30, 0))).toBeNull();
  });
  it('genTime is shown as a plain UTC time', () => {
    expect(formatGenTime('20261005123456Z')).toBe('2026-10-05 12:34:56 UTC'); expect(formatGenTime('20261005123456.789Z')).toBe('2026-10-05 12:34:56 UTC');
  });
});
