// Level-2 fixtures (Task 22): SYNTHETIC originals, signed with c2patool 0.27 by the vectors' PUBLIC TEST KEY under the app's own signer
// certificate for that key (e2e/fixtures/src/signer_*.pem, taken from the app's conformance sample: same profile as SignerCertificates).
// No M20 TEE-signed original exists yet (the app's capture path is wired in Task 13/23), so the attestation chains are synthetic too
// (test/helpers/attest-gen.ts) under FAKE roots that are never in public/attestation/roots.json: e2e injects the fake hardware root.
// Pictures: e2e/fixtures/sealed.jpg (synthetic scene, synthetic ocean coordinates: P3) and a synthetic 3 s ffmpeg clip. Re-run with
// `npx tsx scripts/make-l2-fixtures.ts` (needs c2patool on PATH and network for the DigiCert time-stamp; without it, no TSA).
import { createHash, createPrivateKey } from 'node:crypto'; import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'; import { tmpdir } from 'node:os'; import { join } from 'node:path';
import jpeg from 'jpeg-js';
import { SIGNING_DIGESTS } from '../src/config';
import { findSealUrl } from '../src/qr';
import { chain, genKey, importKey, pem } from '../test/helpers/attest-gen';
const V = JSON.parse(readFileSync('test/vectors/verify-vectors.json', 'utf8'));
const tk = V.testKey as { d: string; publicKey: string; keyId: string };
const work = mkdtempSync(join(tmpdir(), 'l2fx-'));
const testKey = await importKey(tk.d, tk.publicKey);
const b64u = (b: Uint8Array) => Buffer.from(b).toString('base64url');
writeFileSync(join(work, 'key.pem'), createPrivateKey({ key: { kty: 'EC', crv: 'P-256', d: b64u(Buffer.from(tk.d, 'hex')),
  x: b64u(Buffer.from(tk.publicKey, 'hex').subarray(1, 33)), y: b64u(Buffer.from(tk.publicKey, 'hex').subarray(33)) }, format: 'jwk' }).export({ type: 'pkcs8', format: 'pem' }));
// The QR the picture already carries: the original's seal assertion holds the same payload (what the app writes).
const j = jpeg.decode(readFileSync('e2e/fixtures/sealed.jpg'), { useTArray: true, formatAsRGBA: true });
const qrUrl = findSealUrl({ data: Uint8ClampedArray.from(j.data), w: j.width, h: j.height }); if (!qrUrl) throw new Error('no QR in sealed.jpg');
const photoPayload = qrUrl.slice(qrUrl.indexOf('#') + 1);
const DEV = SIGNING_DIGESTS.find(d => d.dev)!.hex; const UNKNOWN = createHash('sha256').update('camerastamp-test-unregistered-signer').digest('hex');
const PKG = [{ name: 'com.essenty.camerastamp', version: 1 }];
const hwRoot = await genKey('P-384');
const hwDesc = { attLevel: 1, keyLevel: 1, packages: PKG, digests: [DEV], rot: { locked: true, state: 0 } };
const hw = await chain({ leafSpki: testKey.spki, desc: hwDesc, root: hwRoot });
const unreg = await chain({ leafSpki: testKey.spki, desc: { ...hwDesc, digests: [UNKNOWN] }, root: hwRoot });
const other = await genKey('P-256');
const forged = await chain({ leafSpki: other.spki, desc: hwDesc, root: hwRoot });                  // a real-looking chain for ANOTHER key
// API 24 measured shape (spike item 4): software attestation, no attestationApplicationId, no root of trust, software root.
const sw = await chain({ leafSpki: testKey.spki, desc: { attLevel: 0, keyLevel: 0 }, rootName: 'FAKE Android Keystore Software Attestation Root' });
writeFileSync('e2e/fixtures/fake_attestation_roots.json', JSON.stringify([hw.rootPem], null, 1) + '\n');
writeFileSync('test/fixtures/attestation/synth_hw.pem', hw.ders.map(pem).join(''));
writeFileSync('test/fixtures/attestation/synth_sw.pem', sw.ders.map(pem).join(''));
writeFileSync('test/fixtures/attestation/synth_roots.json', JSON.stringify([hw.rootPem], null, 1) + '\n');
function sign(src: string, out: string, kind: 'photo' | 'video', payload: string, ders: Uint8Array[], tsa: boolean, extra: Record<string, unknown> = {}) {
  const manifest = { alg: 'es256', private_key: join(work, 'key.pem'), sign_cert: join(process.cwd(), 'e2e/fixtures/src/signer_f18fa21b6b1a2c70.pem'),
    ...(tsa ? { ta_url: 'http://timestamp.digicert.com' } : {}), claim_generator_info: [{ name: 'CameraStamp', version: 'fixture' }],
    assertions: [
      { label: 'c2pa.actions', data: { actions: [{ action: 'c2pa.created', digitalSourceType: 'http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture' }] } },
      { label: 'com.essenty.camerastamp.seal', kind: 'Json', data: { version: 1, kind, payload, keyId: tk.keyId,
        attestationChain: ders.map(d => Buffer.from(d).toString('base64')), app: 'fixture', ...extra } }] };
  const mf = join(work, 'manifest.json'); writeFileSync(mf, JSON.stringify(manifest));
  execFileSync('c2patool', [src, '-m', mf, '-o', out, '-f'], { stdio: ['ignore', 'ignore', 'inherit'] });
}
const tsa = process.env.NO_TSA !== '1';
sign('e2e/fixtures/sealed.jpg', 'e2e/fixtures/original_hw.jpg', 'photo', photoPayload, hw.ders, tsa);
sign('e2e/fixtures/sealed.jpg', 'e2e/fixtures/original_unreg.jpg', 'photo', photoPayload, unreg.ders, false);
sign('e2e/fixtures/sealed.jpg', 'e2e/fixtures/original_sw.jpg', 'photo', photoPayload, sw.ders, false);
sign('e2e/fixtures/sealed.jpg', 'e2e/fixtures/original_forged.jpg', 'photo', photoPayload, forged.ders, false);
// P30: dark_sealed.jpg carries a NO_FINGERPRINT seal (v1_case7). Its original, signed with that same seal, is green from the file binding;
// signed with ANOTHER seal of the same key (v1_case0), the file binding says nothing about the QR's seal (identity, P18 a).
const c7 = V.payloads.find((p: { name: string }) => p.name === 'v1_case7').base64url;
sign('e2e/fixtures/dark_sealed.jpg', 'e2e/fixtures/original_dark.jpg', 'photo', c7, hw.ders, false);
sign('e2e/fixtures/dark_sealed.jpg', 'e2e/fixtures/original_dark_other.jpg', 'photo', V.payloads[0].base64url, hw.ders, false);
sign('e2e/fixtures/src/plain_3s.mp4', 'e2e/fixtures/original_video.mp4', 'video', V.payloads[0].base64url, hw.ders, false, { durationMs: 3000 });
console.log('written; fake hardware root in e2e/fixtures/fake_attestation_roots.json; TSA', tsa);
