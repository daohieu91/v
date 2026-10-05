// P45 fixtures: a time-stamp the page must NOT confirm, on an original that is otherwise exactly like original_hw.jpg (sealed.jpg, the
// public test key, the app's signer certificate, the synthetic hardware chain).
//  1. A fresh original is signed by c2patool through an external signer (--signer-path: this same script with --sign, ES256 with the
//     test key; it answers --signer-info with a 24 000-byte reserve and DigiCert's TSA URL) with a REAL DigiCert time-stamp, so its COSE box has room for a second real token (c2patool's own
//     signer reserves ~10.9 KB: one DigiCert token, ~6 KB, fits, two do not). It is not committed; it only seeds the two below.
//  2. Its unprotected time-stamp tokens are replaced (the unprotected bucket is not covered by the claim signature) and "pad" resized so
//     the COSE bytes keep their length: the file stays validly signed and its hard binding still holds.
//     - original_tsa_two.jpg: TWO tokens — first a real DigiCert token over OTHER data (the app sample photo_tsa.jpg's), then its own;
//     - original_tsa_imprint.jpg: ONE token, that real DigiCert token over other data: a wrong imprint.
// Re-run with `npx tsx scripts/make-tsa-fixtures.ts` (needs c2patool on PATH and network for DigiCert).
import { createPrivateKey, sign } from 'node:crypto'; import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'; import { tmpdir } from 'node:os'; import { join } from 'node:path';
import jpeg from 'jpeg-js';
import { activeSignature, coseSigner, extractJumbf } from '../src/l2/jumbf';
import { findSealUrl } from '../src/qr';
import { pemToDer } from '../src/l2/x509';
import { patchFile, withTokens } from '../test/helpers/cose-tst';
const V = JSON.parse(readFileSync('test/vectors/verify-vectors.json', 'utf8'));
const tk = V.testKey as { d: string; publicKey: string; keyId: string };
const b64u = (b: Uint8Array) => Buffer.from(b).toString('base64url');
const key = () => createPrivateKey({ key: { kty: 'EC', crv: 'P-256', d: b64u(Buffer.from(tk.d, 'hex')),
  x: b64u(Buffer.from(tk.publicKey, 'hex').subarray(1, 33)), y: b64u(Buffer.from(tk.publicKey, 'hex').subarray(33)) }, format: 'jwk' });
const CERT = join(process.cwd(), 'e2e/fixtures/src/signer_f18fa21b6b1a2c70.pem');
if (process.argv.includes('--signer-info')) {                                   // c2patool asks the external signer what it is
  process.stdout.write(JSON.stringify({ alg: 'es256', sign_cert: readFileSync(CERT, 'utf8'), tsa_url: 'http://timestamp.digicert.com', reserve_size: 24000 }));
} else if (process.argv[2] === '--sign') {                                              // the external signer: claim bytes in, raw r‖s out
  const chunks: Buffer[] = []; for await (const c of process.stdin) chunks.push(c as Buffer);
  process.stdout.write(sign('sha256', Buffer.concat(chunks), { key: key(), dsaEncoding: 'ieee-p1363' }));
} else {
  const work = mkdtempSync(join(tmpdir(), 'tsafx-'));
  const j = jpeg.decode(readFileSync('e2e/fixtures/sealed.jpg'), { useTArray: true, formatAsRGBA: true });
  const qrUrl = findSealUrl({ data: Uint8ClampedArray.from(j.data), w: j.width, h: j.height }); if (!qrUrl) throw new Error('no QR in sealed.jpg');
  const ders = pemToDer(readFileSync('test/fixtures/attestation/synth_hw.pem', 'utf8'));
  const manifest = { claim_generator_info: [{ name: 'CameraStamp', version: 'fixture' }],
    assertions: [
      { label: 'c2pa.actions', data: { actions: [{ action: 'c2pa.created', digitalSourceType: 'http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture' }] } },
      { label: 'com.essenty.camerastamp.seal', kind: 'Json', data: { version: 1, kind: 'photo', payload: qrUrl.slice(qrUrl.indexOf('#') + 1), keyId: tk.keyId,
        attestationChain: ders.map(d => Buffer.from(d).toString('base64')), app: 'fixture' } }] };
  const mf = join(work, 'manifest.json'), seed = join(work, 'seed.jpg'); writeFileSync(mf, JSON.stringify(manifest));
  execFileSync('c2patool', ['e2e/fixtures/sealed.jpg', '-m', mf, '-o', seed, '-f', '--signer-path', `npx tsx ${join(process.cwd(), 'scripts/make-tsa-fixtures.ts')} --sign`], { stdio: ['ignore', 'ignore', 'inherit'] });
  const load = async (b: Uint8Array) => { const c = activeSignature((await extractJumbf(b))!)!; return { b, c, s: coseSigner(c) }; };
  const base = await load(new Uint8Array(readFileSync(seed))), other = await load(new Uint8Array(readFileSync('test/fixtures/c2pa/photo_tsa.jpg')));
  if (base.s.tstTokens.length !== 1) throw new Error('the seed has no DigiCert token (network?)');
  const own = base.s.tstTokens[0], old = other.s.tstTokens[0];
  writeFileSync('e2e/fixtures/original_tsa_two.jpg', patchFile(base.b, base.c, withTokens(base.c, [old, own])));
  writeFileSync('e2e/fixtures/original_tsa_imprint.jpg', patchFile(base.b, base.c, withTokens(base.c, [old])));
  console.log(`written original_tsa_two.jpg, original_tsa_imprint.jpg (COSE ${base.c.length} B, own token ${own.length} B, other ${old.length} B)`);
}
