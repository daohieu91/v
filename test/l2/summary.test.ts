import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { activeSignature, extractJumbf } from '../../src/l2/jumbf';
import { SEAL_LABEL, summarize, type L2Input } from '../../src/l2/summary';
import { pemToDer } from '../../src/l2/x509';
// c2pa-web's manifest-store shape (as c2patool prints it: spike item 1c), with our own COSE read of a real signed file.
const V = JSON.parse(readFileSync('test/vectors/verify-vectors.json', 'utf8'));
const synthRoots = JSON.parse(readFileSync('test/fixtures/attestation/synth_roots.json', 'utf8')) as string[];
const b64 = (d: Uint8Array) => Buffer.from(d).toString('base64');
const chainOf = (f: string) => pemToDer(readFileSync(`test/fixtures/attestation/${f}`, 'utf8')).map(b64);
const cose = async (f: string) => activeSignature((await extractJumbf(new Uint8Array(readFileSync(f))))!);
// signature_info exactly as c2pa-web 0.15.3 reported it for original_hw.jpg (measured in Chromium; serial is decimal, issuer is the O).
const SIG_INFO = { alg: 'Es256', issuer: 'CameraStamp', common_name: 'CameraStamp seal f18fa21b6b1a2c70', cert_serial_number: '17406309323454950512' };
const OK_SUCCESS = ['timeStamp.validated', 'claimSignature.insideValidity', 'claimSignature.validated', 'assertion.hashedURI.match', 'assertion.dataHash.match'];
const store = (seal: Record<string, unknown> | null, failure: string[] = ['signingCredential.untrusted'], success: string[] = OK_SUCCESS, sigInfo: unknown = SIG_INFO) => ({ active_manifest: 'urn:x',
  manifests: { 'urn:x': { signature_info: sigInfo, assertions: seal ? [{ label: 'c2pa.actions.v2', data: {} }, { label: SEAL_LABEL, data: seal }] : [] } },
  validation_results: { activeManifest: { failure: failure.map(code => ({ code })), success: success.map(code => ({ code })) } } });
const DEV = [{ hex: '6dcef54931f170eff8e8d53bd77e62ec66c078479a6141411d08b00287077602', dev: true }];
const seal = (o: Record<string, unknown> = {}) => ({ version: 1, kind: 'photo', payload: V.payloads[0].base64url, keyId: 'f18fa21b6b1a2c70', attestationChain: chainOf('synth_hw.pem'), app: 't', ...o });
const run = async (o: Partial<L2Input>) => summarize({ store: store(seal()), cose: await cose('e2e/fixtures/original_hw.jpg'), roots: synthRoots, status: { entries: {} }, qrKeyIdHex: null, digests: DEV, ...o });
const keys = (r: Awaited<ReturnType<typeof run>>) => r.summary.lines.map(l => l.key);
describe('level-2 summary', () => {
  it('a valid file with a bound, certified seal (dev digest): signature, chain, device lines, TSA; no "real device" on a test build', async () => {
    const r = await run({});
    expect(r.summary.kind).toBe('ok'); expect(r.summary.bound).toBe(true); expect(r.summary.realDevice).toBe(false);
    expect(keys(r)).toEqual(['l2_signature_ok', 'l2_untrusted_note', 'l2_chain_ok', 'l2_app_dev', 'l2_level_hw', 'l2_boot_ok', 'l2_locked_ok', 'l2_tsa']);
    expect(r.summary.lines.at(-1)!.params).toMatchObject({ tsa: expect.stringMatching(/DigiCert/) });
    expect(r.payload?.fields.epochSeconds).toBe(V.payloads[0].fields.epochSeconds);
  });
  it('with the release digest registered, the same file says "sealed by a key in a real device"', async () => {
    const r = await run({ digests: [{ hex: '6dcef54931f170eff8e8d53bd77e62ec66c078479a6141411d08b00287077602', dev: false }] });
    expect(r.summary.realDevice).toBe(true); expect(keys(r)).toContain('l2_real_device');
  });
  it('no manifest → l2_none; any failure but "untrusted signer" → l2_invalid (red)', async () => {
    expect(keys(await run({ store: null }))).toEqual(['l2_none']);
    for (const code of ['assertion.dataHash.mismatch', 'claimSignature.mismatch', 'signingCredential.invalid', 'general.error']) {
      const r = await run({ store: store(seal(), ['signingCredential.untrusted', code]) }); expect([r.summary.kind, keys(r)], code).toEqual(['invalid', ['l2_invalid']]); }
  });
  it('a broken time-stamp is not a broken file: the token is ignored (no TSA line), the verdict stays', async () => {
    const r = await run({ store: store(seal(), ['signingCredential.untrusted', 'timeStamp.mismatch']) });
    expect(r.summary.kind).toBe('ok'); expect(keys(r)).toContain('l2_no_tsa'); expect(keys(r)).not.toContain('l2_tsa');
  });
  it('the shipped digest list (P36) holds no debug key: a debug-signed file is "app signature not yet registered"', async () => {
    const r = await run({ digests: undefined }); expect(keys(r)).toContain('l2_app_unregistered'); expect(keys(r)).not.toContain('l2_app_dev');
  });
  it('no validation report from the reader → l2_error, never assumed valid', async () => {
    const st: any = store(seal()); delete st.validation_results; expect(keys(await run({ store: st }))).toEqual(['l2_error']);
    const st2: any = store(seal()); delete st2.validation_results.activeManifest.success; expect(keys(await run({ store: st2 }))).toEqual(['l2_error']);
  });
  it('TSA "confirmed by" only when the reader validated the time-stamp (success: [] → no TSA line)', async () => {
    const r = await run({ store: store(seal(), ['signingCredential.untrusted'], []) });
    expect(keys(r)).toContain('l2_no_tsa'); expect(keys(r)).not.toContain('l2_tsa');
    expect(keys(await run({ store: store(seal(), ['signingCredential.untrusted'], ['timeStamp.trusted']) }))).toContain('l2_tsa');
  });
  it('our x5chain[0] must be the certificate the reader validated (signature_info): any mismatch → l2_error, unbound, never real', async () => {
    for (const bad of [{ ...SIG_INFO, cert_serial_number: '17406309323454950513' }, { ...SIG_INFO, common_name: 'CameraStamp seal 0000000000000000' },
      { ...SIG_INFO, issuer: 'Someone' }, null, {}]) {
      const r = await run({ store: store(seal(), undefined, undefined, bad), digests: [{ hex: DEV[0].hex, dev: false }] });
      expect([keys(r), r.summary.bound, r.summary.realDevice, r.payload], JSON.stringify(bad)).toEqual([['l2_error'], false, false, null]);
    }
    // a second, different store in the file: our COSE read (another signer) does not match what the reader validated
    const other = await cose('test/fixtures/c2pa/video.mp4'); expect(keys(await run({ cose: other, store: store(seal(), undefined, undefined, { ...SIG_INFO, cert_serial_number: '1' }) }))).toEqual(['l2_error']);
  });
  it('another app\'s C2PA file (no seal assertion) is "no CameraStamp seal", unbound, nothing about devices', async () => {
    const r = await run({ store: store(null) }); expect(keys(r)).toEqual(['l2_signature_ok', 'l2_untrusted_note', 'l2_no_seal']);
    expect([r.summary.bound, r.payload]).toEqual([false, null]);
  });
  it('a seal whose payload is not the signer\'s (a transplanted seal) is unbound and says so', async () => {
    const r = await run({ store: store(seal({ payload: V.payloads[0].base64url.replace(/^A/, 'B') })) });
    expect(r.summary.bound).toBe(false); expect(keys(r)).toContain('l2_binding_bad');
  });
  it('a video seal shows its duration; hostile seal fields are ignored, never thrown', async () => {
    expect((await run({ store: store(seal({ kind: 'video', durationMs: 2600 })) })).summary.lines.find(l => l.key === 'l2_video')?.params).toEqual({ s: 3 });
    for (const bad of [{ payload: 7 }, { payload: 'x'.repeat(5000) }, { attestationChain: 'nope' }, { attestationChain: ['%%%'] }, { attestationChain: Array(11).fill('MA==') }])
      expect((await run({ store: store(seal(bad)) })).summary.kind, JSON.stringify(bad).slice(0, 40)).toBe('ok');
  });
  it('no readable COSE signer (a truncated read) → l2_error, unbound', async () => {
    const r = await run({ cose: null }); expect([keys(r), r.summary.bound]).toEqual([['l2_error'], false]);
  });
});
