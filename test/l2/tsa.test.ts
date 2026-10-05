import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { activeSignature, coseSigner, extractJumbf } from '../../src/l2/jumbf';
import { kids, readDer } from '../../src/l2/der';
import { verifyTsaToken } from '../../src/l2/tsa';
import { TSA_ROOTS_B64 } from '../../src/l2/tsa-roots';
import { commonName, parseCert } from '../../src/l2/x509';
// I2. photo_tsa.jpg (the app's own writer) and original_hw.jpg carry REAL DigiCert tokens. original_tsa_forged.jpg carries a token from a
// self-made chain whose names copy DigiCert's (scripts/make-l2-fixtures.ts): its forged CA's issuer is byte-identical to the pinned G4's
// subject, and c2pa-web 0.15.3 reports it `timeStamp.validated` (measured: test/fixtures/c2pa/original_tsa_forged.crjson.json).
const tokenOf = async (p: string) => coseSigner(activeSignature((await extractJumbf(new Uint8Array(readFileSync(p))))!)!).tstTokens[0];
const bag = (tok: Uint8Array) => { const sd = kids(readDer(kids(readDer(tok))[1].content)); const c = sd.find(p => p.cls === 2 && p.tag === 0)!;
  return kids(c).map(x => parseCert(c.content.subarray(x.start, x.end).slice())); };
const der = (b: string) => Uint8Array.from(Buffer.from(b, 'base64'));
describe('RFC 3161 token trust (I2: pinned TSA roots, as the app)', () => {
  it('pins exactly the app\'s three TsaTrust roots (SHA-256 fingerprints as TsaTrustTest)', () => {
    expect(TSA_ROOTS_B64.map(b => createHash('sha256').update(der(b)).digest('hex').toUpperCase())).toEqual([
      '552F7BDCF1A7AF9E6CE672017F4F12ABF77240C78E761AC203D1D9D20AC89988', '3E9099B5015E8F486C00BCEA9D111EE721FABA355A89BCF1DF69561E3DC6325C',
      'A6379E7CECC05FAA3CBF076013D745E327BBBAA38C0B9AF22469D4701D18AABC']);
  });
  it('a real DigiCert token chains to the pinned G4: time and the signer\'s name', async () => {
    for (const f of ['test/fixtures/c2pa/photo_tsa.jpg', 'e2e/fixtures/original_hw.jpg']) {
      const t = await verifyTsaToken(await tokenOf(f));
      expect(t, f).not.toBeNull(); expect(t!.genTime).toMatch(/^20\d\d-\d\d-\d\d \d\d:\d\d:\d\d UTC$/);
      expect(t!.tsaName).toBe('DigiCert SHA256 RSA4096 Timestamp Responder 2026 1');
    }
  });
  it('a self-made TSA carrying DigiCert\'s names is refused (no name, no time)', async () => {
    const tok = await tokenOf('e2e/fixtures/original_tsa_forged.jpg');
    expect(bag(tok).map(c => commonName(c.subject))).toEqual(['DigiCert SHA256 RSA4096 Timestamp Responder 2026 1',
      'DigiCert Trusted G4 TimeStamping RSA4096 SHA256 2025 CA1', 'DigiCert Trusted Root G4']);
    expect(await verifyTsaToken(tok)).toBeNull();
    // It is a well-formed token: pin ITS root and it passes, so only the pinned-root check refuses it.
    const forgedRoot = bag(tok).find(c => commonName(c.subject) === 'DigiCert Trusted Root G4')!;
    expect(await verifyTsaToken(tok, [forgedRoot])).toMatchObject({ tsaName: 'DigiCert SHA256 RSA4096 Timestamp Responder 2026 1' });
  });
  it('the signer is the certificate the SignerInfo names: a sid naming no certificate in the token → refused', async () => {
    const tok = await tokenOf('test/fixtures/c2pa/photo_tsa.jpg');
    const sd = readDer(kids(readDer(tok))[1].content); const parts = kids(sd); const sid = kids(kids(parts[parts.length - 1])[0])[1];
    expect(sid.tag).toBe(16);                                                              // DigiCert: issuerAndSerialNumber
    const ser = kids(sid)[1]; const off = ser.content.byteOffset - tok.byteOffset;
    const altered = tok.slice(); altered[off + ser.content.length - 1] ^= 1;
    expect(await verifyTsaToken(altered)).toBeNull();
  });
  it('any changed byte of the signed TSTInfo or the signature → refused', async () => {
    const tok = await tokenOf('test/fixtures/c2pa/photo_tsa.jpg');
    const sd = readDer(kids(readDer(tok))[1].content); const parts = kids(sd);
    const tst = kids(kids(parts[2])[1])[0].content; const at = tst.byteOffset - tok.byteOffset + tst.length - 3;   // [0] OCTET STRING → TSTInfo
    const t1 = tok.slice(); t1[at] ^= 1; expect(await verifyTsaToken(t1)).toBeNull();          // messageDigest no longer matches
    const si = kids(kids(parts[parts.length - 1])[0]); const sig = si[si.length - 1].content;
    const t2 = tok.slice(); t2[sig.byteOffset - tok.byteOffset + 10] ^= 1; expect(await verifyTsaToken(t2)).toBeNull();
    for (const g of [new Uint8Array(), Uint8Array.of(0x30, 0), new Uint8Array(64).fill(0x30)]) expect(await verifyTsaToken(g)).toBeNull();
  });
});
