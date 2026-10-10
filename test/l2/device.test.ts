import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { keyIdOf } from '../../src/crypto';
import { checkChain, type ChainCheck } from '../../src/l2/attestation';
import { hex } from '../../src/l2/der';
import { deviceLines, type DeviceInput } from '../../src/l2/device';
import { pemToDer } from '../../src/l2/x509';
import { SIGNING_DIGESTS } from '../../src/config';
// The REAL M20 chain decides everything except the app digest: it carries the debug digest, which a test may register as "release"
// to reach the one path that says "real device". The shipped list (config.ts) has the debug digest as dev only.
const roots = JSON.parse(readFileSync('public/attestation/roots.json', 'utf8')) as string[];
const DEV = '6dcef54931f170eff8e8d53bd77e62ec66c078479a6141411d08b00287077602';
const RELEASE = [{ hex: DEV, dev: false }];
let m20: ChainCheck;
const input = async (o: Partial<DeviceInput> = {}): Promise<DeviceInput> => {
  m20 ??= await checkChain(pemToDer(readFileSync('test/fixtures/attestation/m20.pem', 'utf8')), roots, { entries: {} });
  return { chain: m20, signerKey: m20.leafKey, payloadKey: m20.leafKey, qrKeyIdHex: null, packageName: 'com.essenty.camerastamp', digests: RELEASE, ...o };
};
const keys = (r: ReturnType<typeof deviceLines>) => r.lines.map(l => l.key);
const other = Uint8Array.from([4, ...new Uint8Array(64).fill(5)]);
describe('device lines (spec §5.2, Task 21 carry-over)', () => {
  it('every condition met → "sealed by a key in a real device\'s secure hardware", one line per condition', async () => {
    const r = deviceLines(await input());
    expect(r.realDevice).toBe(true); expect(r.contentBound).toBe(true);
    expect(keys(r)).toEqual(['l2_chain_ok', 'l2_app_ok', 'l2_level_hw', 'l2_boot_ok', 'l2_locked_ok', 'l2_real_device']);
  });
  it('the QR link: same key → l2_qr_link (only when real); another key → l2_qr_other_key and never real', async () => {
    const m = await input(); const id = hex(keyIdOf(m.chain.leafKey!));
    expect(keys(deviceLines(await input({ qrKeyIdHex: id })))).toContain('l2_qr_link');
    const r = deviceLines(await input({ qrKeyIdHex: 'f18fa21b6b1a2c70' })); expect(r.realDevice).toBe(false); expect(keys(r)).toContain('l2_qr_other_key');
    expect(keys(deviceLines(await input({ qrKeyIdHex: id, digests: [{ hex: DEV, dev: true }] })))).toEqual(expect.arrayContaining(['l2_qr_same_key']));
  });
  it('each missing condition alone withholds "real device"', async () => {
    const m = await input(); const leaf = m.chain.leaf!;
    const cases: [string, Partial<DeviceInput>, string][] = [
      ['test build (dev digest)', { digests: [{ hex: DEV, dev: true }] }, 'l2_app_dev'],
      ['unregistered digest (no Play signing digest yet)', { digests: [{ hex: 'aa'.repeat(32), dev: true }] }, 'l2_app_unregistered'],
      ['M8: a release digest is registered and this one is unknown (a re-packaged app)', { digests: [{ hex: 'aa'.repeat(32), dev: false }] }, 'l2_app_bad'],
      ['another package', { packageName: 'com.example.other' }, 'l2_app_bad'],
      ['chain not certified', { chain: { ...m.chain, chainOk: false } }, 'l2_chain_bad'],
      ['revoked', { chain: { ...m.chain, chainOk: false, revoked: true } }, 'l2_revoked'],
      ['software attestation (P11)', { chain: { ...m.chain, leaf: { ...leaf, securityLevel: 0 } } }, 'l2_level_sw'],
      ['hardware attestation of a software key', { chain: { ...m.chain, leaf: { ...leaf, keySecurityLevel: 0 } } }, 'l2_level_sw'],
      ['unverified boot', { chain: { ...m.chain, leaf: { ...leaf, verifiedBootState: 2 } } }, 'l2_boot_bad'],
      ['unlocked bootloader', { chain: { ...m.chain, leaf: { ...leaf, deviceLocked: false } } }, 'l2_locked_bad'],
      ['C2PA signer is another key', { signerKey: other }, 'l2_binding_bad'],
      ['payload key is another key', { payloadKey: other }, 'l2_binding_bad'],
      ['payload did not verify', { payloadKey: null }, 'l2_binding_bad'],
      ['no C2PA signer certificate', { signerKey: null }, 'l2_binding_bad'],
    ];
    for (const [name, o, line] of cases) { const r = deviceLines(await input(o)); expect(r.realDevice, name).toBe(false);
      expect(keys(r), name).toContain(line); expect(keys(r), name).not.toContain('l2_real_device'); }
  });
  it('signer = payload key but an attested key that is not theirs: content bound, device not', async () => {
    const r = deviceLines(await input({ signerKey: other, payloadKey: other }));
    expect([r.contentBound, r.realDevice]).toEqual([true, false]); expect(keys(r)).toContain('l2_binding_bad');
  });
  it('no attestation at all: "not certified" only, no guesses; the content binding still holds', async () => {
    const r = deviceLines(await input({ chain: { chainOk: false, revoked: false, leaf: null, leafKey: null }, signerKey: other, payloadKey: other }));
    expect(keys(r)).toEqual(['l2_chain_bad']); expect(r.contentBound).toBe(true);
  });
  it('API 24 shape: no application id and no root of trust are "unknown", not "another app" or "unlocked"', async () => {
    const r = deviceLines(await input({ chain: { chainOk: false, revoked: false, leafKey: (await input()).chain.leafKey,
      leaf: { securityLevel: 0, keySecurityLevel: 0, packages: [], signatureDigests: [], verifiedBootState: null, deviceLocked: null } } }));
    expect(keys(r)).toEqual(['l2_chain_bad', 'l2_app_unknown', 'l2_level_sw', 'l2_boot_unknown']);
  });
});
describe('shipped SIGNING_DIGESTS: the Play App Signing certificate (Part 4B Task 9)', () => {
  const PLAY = 'b0ff802fd83926409ce0bab830a7ec9d292d86513ad661401c6a836586d07502';
  const UPLOAD = '1b866c28fb1128da20bbf726b731c4097e4779c67abcf37a9d3e539e844fd023';   // upload key: Play re-signs, never in a user's file
  it('holds exactly the Play digest as a release entry: 64 lower-case hex, never the upload key, never a SHA-1', () => {
    for (const d of SIGNING_DIGESTS) expect(d.hex).toMatch(/^[0-9a-f]{64}$/);
    expect(SIGNING_DIGESTS.map(d => d.hex)).not.toContain(UPLOAD);
    expect(SIGNING_DIGESTS).toEqual([{ hex: PLAY, dev: false }]);
  });
  it('a file from the Play-signed app (leaf digest = Play) reads l2_app_ok with the shipped list; a debug-signed one is l2_app_bad (M8)', async () => {
    const m = await input();
    const playSigned = { ...m.chain, leaf: { ...m.chain.leaf!, signatureDigests: [PLAY] } };
    expect(keys(deviceLines(await input({ chain: playSigned, digests: SIGNING_DIGESTS })))).toContain('l2_app_ok');
    expect(keys(deviceLines(await input({ digests: SIGNING_DIGESTS })))).toContain('l2_app_bad');
  });
});
