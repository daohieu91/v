// Level-2 fixtures (Task 22): SYNTHETIC originals, signed with c2patool 0.27 by the vectors' PUBLIC TEST KEY under the app's own signer
// certificate for that key (e2e/fixtures/src/signer_*.pem, taken from the app's conformance sample: same profile as SignerCertificates).
// No M20 TEE-signed original exists yet (the app's capture path is wired in Task 13/23), so the attestation chains are synthetic too
// (test/helpers/attest-gen.ts) under FAKE roots that are never in public/attestation/roots.json: e2e injects the fake hardware root.
// Pictures: e2e/fixtures/sealed.jpg (synthetic scene, synthetic ocean coordinates: P3) and a synthetic 3 s ffmpeg clip. Re-run with
// `npx tsx scripts/make-l2-fixtures.ts` (needs c2patool on PATH and network for the DigiCert time-stamp; without it, no TSA).
import { createHash, createPrivateKey } from 'node:crypto'; import { execFileSync, execFile } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'; import { tmpdir } from 'node:os'; import { join } from 'node:path';
import jpeg from 'jpeg-js';
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
const DEV = '6dcef54931f170eff8e8d53bd77e62ec66c078479a6141411d08b00287077602';   // the debug key (releaseSmoke); not in the deployed list (P36)
const UNKNOWN = createHash('sha256').update('camerastamp-test-unregistered-signer').digest('hex');
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
function sign(src: string, out: string, kind: 'photo' | 'video', payload: string, ders: Uint8Array[], tsa: boolean | string, extra: Record<string, unknown> = {}): string[] {
  const manifest = { alg: 'es256', private_key: join(work, 'key.pem'), sign_cert: join(process.cwd(), 'e2e/fixtures/src/signer_f18fa21b6b1a2c70.pem'),
    ...(tsa ? { ta_url: typeof tsa === 'string' ? tsa : 'http://timestamp.digicert.com' } : {}), claim_generator_info: [{ name: 'CameraStamp', version: 'fixture' }],
    assertions: [
      { label: 'c2pa.actions', data: { actions: [{ action: 'c2pa.created', digitalSourceType: 'http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture' }] } },
      { label: 'com.essenty.camerastamp.seal', kind: 'Json', data: { version: 1, kind, payload, keyId: tk.keyId,
        attestationChain: ders.map(d => Buffer.from(d).toString('base64')), app: 'fixture', ...extra } }] };
  const mf = join(work, 'manifest.json'); writeFileSync(mf, JSON.stringify(manifest));
  return [src, '-m', mf, '-o', out, '-f'];
}
const run = (args: string[]) => execFileSync('c2patool', args, { stdio: ['ignore', 'ignore', 'inherit'] });
const tsa = process.env.NO_TSA !== '1';
run(sign('e2e/fixtures/sealed.jpg', 'e2e/fixtures/original_hw.jpg', 'photo', photoPayload, hw.ders, tsa));
run(sign('e2e/fixtures/sealed.jpg', 'e2e/fixtures/original_unreg.jpg', 'photo', photoPayload, unreg.ders, false));
run(sign('e2e/fixtures/sealed.jpg', 'e2e/fixtures/original_sw.jpg', 'photo', photoPayload, sw.ders, false));
run(sign('e2e/fixtures/sealed.jpg', 'e2e/fixtures/original_forged.jpg', 'photo', photoPayload, forged.ders, false));
// P30: dark_sealed.jpg carries a NO_FINGERPRINT seal (v1_case7). Its original, signed with that same seal, is green from the file binding;
// signed with ANOTHER seal of the same key (v1_case0), the file binding says nothing about the QR's seal (identity, P18 a).
const c7 = V.payloads.find((p: { name: string }) => p.name === 'v1_case7').base64url;
run(sign('e2e/fixtures/dark_sealed.jpg', 'e2e/fixtures/original_dark.jpg', 'photo', c7, hw.ders, false));
run(sign('e2e/fixtures/dark_sealed.jpg', 'e2e/fixtures/original_dark_other.jpg', 'photo', V.payloads[0].base64url, hw.ders, false));
run(sign('e2e/fixtures/src/plain_3s.mp4', 'e2e/fixtures/original_video.mp4', 'video', V.payloads[0].base64url, hw.ders, false, { durationMs: 3000 }));
// I2: a FORGED time-stamp. A self-made CA chain whose names copy DigiCert's (root "DigiCert Trusted Root G4", the 2025 TimeStamping
// CA, the 2026 responder with the timeStamping EKU), served by a local RFC 3161 responder (openssl ts) that c2patool calls. c2pa-web
// validates such a token (signature and imprint are fine); only the page's pinned-root check (src/l2/tsa.ts) can refuse its name.
const fx = join(work, 'forged-tsa'); execFileSync('mkdir', ['-p', fx]);
const o = (args: string[]) => execFileSync('openssl', args, { cwd: fx, stdio: 'ignore' });
// string_mask=default: PrintableString, as DigiCert encodes its names, so the forged CA's issuer is BYTE-identical to the pinned G4's
// subject and only the signature check can refuse it.
writeFileSync(join(fx, 'req.cnf'), '[ req ]\nstring_mask = default\ndistinguished_name = dn\n[ dn ]\n');
o(['req', '-config', 'req.cnf', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'root.key', '-subj', '/C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert Trusted Root G4',
  '-days', '36500', '-set_serial', '1', '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign', '-out', 'root.pem']);
writeFileSync(join(fx, 'ca.cnf'), 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n');
writeFileSync(join(fx, 'tsa.cnf'), 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=critical,timeStamping\n');
o(['req', '-config', 'req.cnf', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-subj', '/C=US/O=DigiCert, Inc./CN=DigiCert Trusted G4 TimeStamping RSA4096 SHA256 2025 CA1', '-out', 'ca.csr']);
o(['x509', '-req', '-in', 'ca.csr', '-CA', 'root.pem', '-CAkey', 'root.key', '-set_serial', '2', '-days', '36500', '-extfile', 'ca.cnf', '-out', 'ca.pem']);
o(['req', '-config', 'req.cnf', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'tsa.key', '-subj', '/C=US/O=DigiCert, Inc./CN=DigiCert SHA256 RSA4096 Timestamp Responder 2026 1', '-out', 'tsa.csr']);
o(['x509', '-req', '-in', 'tsa.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-set_serial', '3', '-days', '36500', '-extfile', 'tsa.cnf', '-out', 'tsa.pem']);
writeFileSync(join(fx, 'chain.pem'), readFileSync(join(fx, 'ca.pem'), 'utf8') + readFileSync(join(fx, 'root.pem'), 'utf8'));
writeFileSync(join(fx, 'ts.cnf'), ['[ tsa ]', 'default_tsa = t', '[ t ]', 'signer_cert = tsa.pem', 'signer_key = tsa.key', 'certs = chain.pem', 'signer_digest = sha256',
  'default_policy = 1.2.3.4.1', 'digests = sha256, sha384, sha512', 'ess_cert_id_alg = sha256', 'accuracy = secs:1', 'ordering = no', 'tsa_name = no',
  'ess_cert_id_chain = no', 'serial = serial.txt', ''].join('\n'));
writeFileSync(join(fx, 'serial.txt'), '01\n');
const server = createServer((req, res) => { const parts: Buffer[] = []; req.on('data', c => parts.push(c)); req.on('end', () => {
  writeFileSync(join(fx, 'q.tsq'), Buffer.concat(parts));
  execFile('openssl', ['ts', '-reply', '-config', 'ts.cnf', '-queryfile', 'q.tsq', '-out', 'r.tsr'], { cwd: fx }, err => {
    if (err) { res.writeHead(500).end(); return; } res.writeHead(200, { 'content-type': 'application/timestamp-reply' }).end(readFileSync(join(fx, 'r.tsr'))); }); }); });
await new Promise<void>(ok => server.listen(0, '127.0.0.1', ok));
const port = (server.address() as { port: number }).port;
// Asynchronously: the responder runs in this process's event loop.
try { await new Promise<void>((ok, bad) => execFile('c2patool', sign('e2e/fixtures/sealed.jpg', 'e2e/fixtures/original_tsa_forged.jpg', 'photo', photoPayload, hw.ders,
  `http://127.0.0.1:${port}/`), err => (err ? bad(err) : ok()))); }
finally { server.close(); }
console.log('written; fake hardware root in e2e/fixtures/fake_attestation_roots.json; TSA', tsa);
