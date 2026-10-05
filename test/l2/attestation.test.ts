import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { checkChain, OID_KEY_DESC, parseKeyDescription } from '../../src/l2/attestation';
import { hex } from '../../src/l2/der';
import { eq } from '../../src/l2/der';
import { parseCert, pemToDer } from '../../src/l2/x509';
import { CA_EXT, cert, chain, genKey, keyDescription } from '../helpers/attest-gen';
const roots = JSON.parse(readFileSync('public/attestation/roots.json', 'utf8')) as string[];
const synthRoots = JSON.parse(readFileSync('test/fixtures/attestation/synth_roots.json', 'utf8')) as string[];
const ders = (f: string) => pemToDer(readFileSync(`test/fixtures/attestation/${f}`, 'utf8'));
const DEV = '6dcef54931f170eff8e8d53bd77e62ec66c078479a6141411d08b00287077602';
const PKG = [{ name: 'com.essenty.camerastamp', version: 1 }];
describe('attestation (real Galaxy M20 chain: values measured in the Task 4 spike)', () => {
  it('M20 hardware chain: Google root, TEE, verified boot, locked, our package with the debug digest', async () => {
    // The chain's own root (f92009e853b6b045) expired on 2026-05-24; roots.json holds Google's re-issued root with the SAME key (to 2042).
    const c = await checkChain(ders('m20.pem'), roots, { entries: {} });
    expect(c.chainOk).toBe(true); expect(c.revoked).toBe(false);
    expect(c.leaf).toEqual({ securityLevel: 1, keySecurityLevel: 1, packages: ['com.essenty.camerastamp'], signatureDigests: [DEV], verifiedBootState: 0, deviceLocked: true });
    expect(hex(c.leafKey!)).toBe('048b657744ee51a098507bbc40fadd7165def469fd29808ab68ae07f3b9d9bf4851070645519646985ca4a5ef7e54b64a588186969e66abd6ae450d59a1405e453');
  });
  it('a revoked serial (lowercase hex, no leading zeros: status.json\'s form) is reported and breaks the chain', async () => {
    const d = ders('m20.pem');
    for (const serial of ['15250848638864758498', '38826676065899685ce']) {
      const c = await checkChain(d, roots, { entries: { [serial]: { status: 'REVOKED' } } }); expect([c.revoked, c.chainOk], serial).toEqual([true, false]); }
    expect((await checkChain(d, roots, { entries: { '038826676065899685CE': { status: 'REVOKED' } } })).revoked, 'other spellings are not Google\'s keys').toBe(false);
  });
  it('a broken link fails the chain', async () => {
    const d = ders('m20.pem'); d.splice(1, 1); expect((await checkChain(d, roots, { entries: {} })).chainOk).toBe(false);
  });
  it('a root that is not Google\'s fails the chain, even when every link verifies', async () => {
    expect((await checkChain(ders('m20.pem').slice(0, 3), roots, { entries: {} })).chainOk).toBe(false);   // ends at an intermediate
    expect((await checkChain(ders('synth_hw.pem'), roots, { entries: {} })).chainOk).toBe(false);
    expect((await checkChain(ders('synth_hw.pem'), synthRoots, { entries: {} })).chainOk).toBe(true);    // same chain, its (fake) root trusted
  });
  it('a root is pinned by its KEY: a self-signed root with Google\'s subject name but another key is not Google', async () => {
    const google = parseCert(ders('m20.pem')[3]); const fakeRoot = await genKey('P-384'); const inter = await genKey('P-256');
    const rootDer = await cert({ serial: 0xe8fa196314d2fa18n, issuer: google.subject, subject: google.subject, spki: fakeRoot.spki, signer: fakeRoot, exts: [CA_EXT] });
    const interDer = await cert({ serial: 5n, issuer: google.subject, subject: 'FAKE TEST INTERMEDIATE', spki: inter.spki, signer: fakeRoot, exts: [CA_EXT] });
    const leaf = await cert({ serial: 6n, issuer: 'FAKE TEST INTERMEDIATE', subject: 'Android Keystore Key', spki: (await genKey()).spki, signer: inter,
      exts: [{ oid: OID_KEY_DESC, value: keyDescription({ attLevel: 1, keyLevel: 1, packages: PKG, digests: [DEV], rot: { locked: true, state: 0 } }) }] });
    expect(eq(parseCert(rootDer).subject, google.subject)).toBe(true);
    expect((await checkChain([leaf, interDer, rootDer], roots, { entries: {} })).chainOk).toBe(false);
  });
  it('Google\'s real root key with a corrupted self-signature is refused', async () => {
    const d = ders('m20.pem'); const root = d[3].slice(); root[root.length - 10] ^= 0x01;               // inside the RSA signature value
    expect(parseCert(root).spki).toEqual(parseCert(d[3]).spki);
    expect((await checkChain([d[0], d[1], d[2], root], roots, { entries: {} })).chainOk).toBe(false);
  });
  it('garbage never throws', async () => {
    for (const bad of [[], [new Uint8Array([0x30, 0x03, 1, 2])], Array(11).fill(ders('m20.pem')[0])])
      expect((await checkChain(bad, roots, { entries: {} })).chainOk).toBe(false);
    expect((await checkChain(ders('m20.pem'), ['not a pem'], { entries: {} })).chainOk).toBe(false);
  });
});
describe('attestation (synthetic chains, test/helpers/attest-gen.ts)', () => {
  it('API 24 shape (spike): software attestation, no application id, no root of trust, software root → not certified', async () => {
    const c = await checkChain(ders('synth_sw.pem'), roots, { entries: {} });
    expect(c.chainOk).toBe(false); expect(c.leaf).toEqual({ securityLevel: 0, keySecurityLevel: 0, packages: [], signatureDigests: [], verifiedBootState: null, deviceLocked: null });
  });
  it('attestation level and key level are separate fields (1 and 3)', () => {
    const k = parseKeyDescription(keyDescription({ attLevel: 1, keyLevel: 0, packages: PKG, digests: [DEV], rot: { locked: true, state: 0 } }));
    expect([k.securityLevel, k.keySecurityLevel]).toEqual([1, 0]);
    expect(parseKeyDescription(keyDescription({ attLevel: 0, keyLevel: 2 })).keySecurityLevel).toBe(2);
  });
  it('a hardware attestation never takes its root of trust from the software list (Android writes that one, not the TEE)', () => {
    const k = parseKeyDescription(keyDescription({ attLevel: 1, keyLevel: 1, rot: { locked: true, state: 0 }, rotInSoftware: true }));
    expect([k.verifiedBootState, k.deviceLocked]).toEqual([null, null]);
    const emu = parseKeyDescription(keyDescription({ attLevel: 0, keyLevel: 0, rot: { locked: false, state: 2 }, rotInSoftware: true }));
    expect([emu.verifiedBootState, emu.deviceLocked]).toEqual([2, false]);                // API 35 emulator: Unverified / unlocked, in software
  });
  it('a hardware key cannot vouch for a fake leaf: an issuer must be a CA and only the leaf may carry a KeyDescription', async () => {
    const root = await genKey('P-384'); const victim = await genKey('P-256');
    const desc = { attLevel: 1, keyLevel: 1, packages: [{ name: 'com.attacker', version: 1 }], digests: [DEV], rot: { locked: true, state: 0 } };
    const real = await chain({ leafSpki: victim.spki, desc, root });       // a genuine chain for the attacker's own hardware key
    const fake = (exts: { oid: string; critical?: boolean; value: Uint8Array }[]) => cert({ serial: 7n, issuer: 'Android Keystore Key', subject: 'Android Keystore Key', spki: victim.spki, signer: victim, exts });
    const forgedDesc = { oid: OID_KEY_DESC, value: keyDescription({ ...desc, packages: PKG }) };
    const trusted = [real.rootPem];
    expect((await checkChain(real.ders, trusted, { entries: {} })).chainOk, 'the genuine chain itself is fine').toBe(true);
    // (a) the attacker's leaf (no basicConstraints, as every Keystore leaf) signs a "leaf" naming our package
    expect((await checkChain([await fake([forgedDesc]), ...real.ders], trusted, { entries: {} })).chainOk).toBe(false);
    // (b) even an issuer that claims CA is refused while it carries a KeyDescription itself
    const caLeaf = await cert({ serial: 9n, issuer: 'FAKE TEST INTERMEDIATE', subject: 'Android Keystore Key', spki: victim.spki, signer: real.inter,
      exts: [CA_EXT, { oid: OID_KEY_DESC, value: keyDescription(desc) }] });
    expect((await checkChain([await fake([forgedDesc]), caLeaf, ...real.ders.slice(1)], trusted, { entries: {} })).chainOk).toBe(false);
    // (c) an issuer without basicConstraints cA (and without a KeyDescription) is not an issuer
    const notCa = await genKey('P-256');
    const notCaDer = await cert({ serial: 11n, issuer: 'FAKE TEST ROOT (not Google)', subject: 'NOT A CA', spki: notCa.spki, signer: root });
    const leafUnder = await cert({ serial: 12n, issuer: 'NOT A CA', subject: 'Android Keystore Key', spki: victim.spki, signer: notCa, exts: [forgedDesc] });
    expect((await checkChain([leafUnder, notCaDer, real.ders[2]], trusted, { entries: {} })).chainOk).toBe(false);
  });
});
