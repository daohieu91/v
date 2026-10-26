import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { activeClaim, activeSignature, extractJumbf } from '../src/l2/jumbf';
import { SEAL_LABEL, summarize } from '../src/l2/summary';
import { pemToDer } from '../src/l2/x509';
import { validL2Reply } from '../src/messages';

const V = JSON.parse(readFileSync('test/vectors/verify-vectors.json', 'utf8'));
const synthRoots = JSON.parse(readFileSync('test/fixtures/attestation/synth_roots.json', 'utf8')) as string[];
const b64 = (d: Uint8Array) => Buffer.from(d).toString('base64');
const F = 'e2e/fixtures/original_hw.jpg';
const jumbf = async () => (await extractJumbf(new Uint8Array(readFileSync(F))))!;
const CR = readFileSync('test/fixtures/c2pa/original_hw.crjson.json', 'utf8'); const LABEL = JSON.parse(CR).manifests[0].label as string;
const SIG_INFO = { alg: 'Es256', issuer: 'CameraStamp', common_name: 'CameraStamp seal f18fa21b6b1a2c70', cert_serial_number: '17406309323454950512' };
const OK = ['timeStamp.validated', 'claimSignature.validated', 'assertion.dataHash.match'];
const seal = { version: 1, kind: 'photo', payload: V.payloads[0].base64url, keyId: 'f18fa21b6b1a2c70', app: 't',
  attestationChain: pemToDer(readFileSync('test/fixtures/attestation/synth_hw.pem', 'utf8')).map(b64) };
const created = { action: 'c2pa.created', digitalSourceType: 'http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture' };
const run = async (actions: unknown, label = 'c2pa.actions.v2') => summarize({
  store: { active_manifest: LABEL, manifests: { [LABEL]: { signature_info: SIG_INFO, assertions: [{ label, data: { actions } }, { label: SEAL_LABEL, data: seal }] } },
    validation_results: { activeManifest: { failure: [{ code: 'signingCredential.untrusted' }], success: OK.map(code => ({ code })) } } },
  cose: activeSignature(await jumbf()), claim: activeClaim(await jumbf()), cr: CR, roots: synthRoots, status: { entries: {} }, qrKeyIdHex: null,
  digests: [{ hex: '6dcef54931f170eff8e8d53bd77e62ec66c078479a6141411d08b00287077602', dev: true }] });
const line = (r: Awaited<ReturnType<typeof run>>) => r.summary.lines.find(l => l.key === 'l2_filtered');
const filtered = (id: unknown, description = 'Color filter: Warm Film, 80%') => [created, { action: 'c2pa.filtered', parameters: { description, filter: id } }];

describe('c2pa.filtered line', () => {
  it('a known filter id → neutral info line with the display name; verdict inputs unchanged', async () => {
    const base = await run([created]); const r = await run(filtered('teal_orange'));
    expect(line(r)).toEqual({ key: 'l2_filtered', status: 'info', params: { name: 'Teal & Orange' } });
    expect(r.summary).toMatchObject({ kind: base.summary.kind, realDevice: base.summary.realDevice, bound: base.summary.bound });
    expect(r.summary.lines.filter(l => l.key !== 'l2_filtered')).toEqual(base.summary.lines);
    expect(validL2Reply(r)).not.toBeNull();
  });
  it('all 11 ids map to their English names; the legacy actions label works too', async () => {
    const names: Record<string, string> = { warm_film: 'Warm Film', cool_film: 'Cool Film', golden_hour: 'Golden Hour', teal_orange: 'Teal & Orange', vivid_travel: 'Vivid Travel',
      faded_retro: 'Faded Retro', soft_portrait: 'Soft Portrait', green_film: 'Green Film', mono: 'Mono', mono_contrast: 'Mono Contrast', night_neon: 'Night Neon' };
    for (const [id, n] of Object.entries(names)) expect(line(await run(filtered(id)))?.params?.name, id).toBe(n);
    expect(line(await run(filtered('mono'), 'c2pa.actions'))?.params?.name).toBe('Mono');
  });
  it('an unknown or non-string id → the localized generic name, never the description', async () => {
    for (const id of ['sepia_9000', 7, undefined, null, {}, '__proto__', 'constructor'])
      expect(line(await run(filtered(id, '<img src=x onerror=alert(1)>Evil')))?.params, String(id)).toEqual({ name: '@l2_filtered_generic' });
  });
  it('a malicious description is never rendered', async () => {
    const r = await run(filtered('warm_film', '<script>alert(1)</script> Totally Real'));
    expect(JSON.stringify(r.summary)).not.toMatch(/script|Totally/);
  });
  it('no filtered action → no line', async () => {
    expect(line(await run([created]))).toBeUndefined();
    expect(line(await run(undefined))).toBeUndefined();
    expect(line(await run('nope'))).toBeUndefined();
  });
});
