import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { hex } from '../../src/l2/der';
import { commonName, ecPoint, isCa, parseCert, pemToDer, signedBy } from '../../src/l2/x509';
// The REAL Galaxy M20 TEE chain (Task 4 spike; app repo app/src/test/resources/attestation/m20_chain.pem). Expected values are from
// `openssl x509 -serial` (hex) / `-pubkey` and `openssl verify -no_check_time` on the same PEM (independent reader), not from this code.
const m20 = pemToDer(readFileSync('test/fixtures/attestation/m20.pem', 'utf8')).map(parseCert);
describe('x509 (own reader, WebCrypto signatures)', () => {
  it('reads serials, keys and names as openssl does', () => {
    expect(m20.map(c => c.serial)).toEqual(['1', '15250848638864758498', '38826676065899685ce', 'e8fa196314d2fa18']);
    expect(hex(ecPoint(m20[0])!)).toBe('048b657744ee51a098507bbc40fadd7165def469fd29808ab68ae07f3b9d9bf4851070645519646985ca4a5ef7e54b64a588186969e66abd6ae450d59a1405e453');
    expect(commonName(m20[0].subject)).toBe('Android Keystore Key');
    expect(m20.map(isCa)).toEqual([false, true, true, true]);
    expect([m20[1].curve, m20[2].curve, m20[3].keyAlg]).toEqual(['1.2.840.10045.3.1.7', '1.3.132.0.34', '1.2.840.113549.1.1.1']);
    expect(ecPoint(m20[2])).toBeNull();                                                   // P-384: not a seal key
  });
  it('verifies every link (ECDSA P-256, P-384 and RSA signatures), and the root signs itself', async () => {
    for (let i = 0; i < 3; i++) expect(await signedBy(m20[i], m20[i + 1]), `link ${i}`).toBe(true);
    expect(await signedBy(m20[3], m20[3])).toBe(true);
  });
  it('a changed certificate body, or the wrong issuer, does not verify', async () => {
    const der = pemToDer(readFileSync('test/fixtures/attestation/m20.pem', 'utf8'))[0].slice(); der[200] ^= 1;
    expect(await signedBy(parseCert(der), m20[1])).toBe(false);
    expect(await signedBy(m20[0], m20[2])).toBe(false);
    expect(await signedBy(m20[1], m20[3])).toBe(false);
  });
  it('refuses trailing bytes and truncation', () => {
    const der = pemToDer(readFileSync('test/fixtures/attestation/m20.pem', 'utf8'))[0];
    expect(() => parseCert(Uint8Array.from([...der, 0]))).toThrow(); expect(() => parseCert(der.subarray(0, der.length - 1))).toThrow();
  });
});
