// SYNTHETIC Android key-attestation chains for tests and e2e fixtures. Every key here is generated for the test (or is the public TEST
// KEY of the vectors); the roots are FAKE and never in public/attestation/roots.json. Shape follows the real M20 chain (Task 4 spike):
// leaf "Android Keystore Key" with the KeyDescription extension and no basicConstraints, CA intermediates, a self-signed root.
import { webcrypto } from 'node:crypto';
import { bits, bool, cat, ctx, enumerated, genTime, int, name, octet, oid, seq, set, utcTime, type Bytes } from './asn1';
const subtle = webcrypto.subtle;
export type Curve = 'P-256' | 'P-384';
export interface Key { priv: webcrypto.CryptoKey; spki: Bytes; curve: Curve }
export async function genKey(curve: Curve = 'P-256'): Promise<Key> {
  const k = await subtle.generateKey({ name: 'ECDSA', namedCurve: curve }, true, ['sign', 'verify']) as webcrypto.CryptoKeyPair;
  return { priv: k.privateKey, spki: new Uint8Array(await subtle.exportKey('spki', k.publicKey)), curve };
}
const b64u = (b: Bytes) => Buffer.from(b).toString('base64url');
/** The vectors' public TEST KEY (d, uncompressed point) as a Key. */
export async function importKey(dHex: string, pubHex: string): Promise<Key> {
  const pub = Buffer.from(pubHex, 'hex'); const jwk = { kty: 'EC', crv: 'P-256', d: b64u(Buffer.from(dHex, 'hex')), x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33)), ext: true };
  const priv = await subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
  const pubKey = await subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y, ext: true }, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
  return { priv, spki: new Uint8Array(await subtle.exportKey('spki', pubKey)), curve: 'P-256' };
}
const ALG = { 'P-256': ['1.2.840.10045.4.3.2', 'SHA-256', 32], 'P-384': ['1.2.840.10045.4.3.3', 'SHA-384', 48] } as const;
function derSig(raw: Bytes, n: number): Bytes {
  const i = (x: Bytes) => { let k = 0; while (k < x.length - 1 && x[k] === 0) k++; x = x.subarray(k); return x[0] & 0x80 ? cat(Uint8Array.of(0), x) : x; };
  return seq(cat(Uint8Array.of(0x02, i(raw.subarray(0, n)).length), i(raw.subarray(0, n))), cat(Uint8Array.of(0x02, i(raw.subarray(n)).length), i(raw.subarray(n))));
}
export interface Ext { oid: string; critical?: boolean; value: Bytes }
const ext = (e: Ext) => seq(oid(e.oid), ...(e.critical ? [bool(true)] : []), octet(e.value));
export const CA_EXT: Ext = { oid: '2.5.29.19', critical: true, value: seq(bool(true)) };
export async function cert(o: { serial: bigint; issuer: string | Bytes; subject: string | Bytes; spki: Bytes; signer: Key; exts?: Ext[] }): Promise<Bytes> {
  const [alg, hash, n] = ALG[o.signer.curve]; const algId = seq(oid(alg));
  const nm = (x: string | Bytes) => (typeof x === 'string' ? name(x) : x);
  const tbs = seq(ctx(0, true, int(2)), int(o.serial), algId, nm(o.issuer), seq(utcTime('200101000000Z'), genTime('99991231235959Z')), nm(o.subject), o.spki,
    ...(o.exts?.length ? [ctx(3, true, seq(...o.exts.map(ext)))] : []));
  const raw = new Uint8Array(await subtle.sign({ name: 'ECDSA', hash }, o.signer.priv, tbs));
  return seq(tbs, algId, bits(derSig(raw, n)));
}
export interface KeyDesc { attLevel: number; keyLevel: number; packages?: { name: string; version: number }[]; digests?: string[];
  rot?: { locked: boolean; state: number } | null; rotInSoftware?: boolean }
/** KeyDescription (attestation v3 layout): AAID in softwareEnforced [709], rootOfTrust [704] in hardwareEnforced (or software). */
export function keyDescription(k: KeyDesc): Bytes {
  const aid = k.packages ? [ctx(709, true, octet(seq(set(...k.packages.map(p => seq(octet(p.name), int(p.version)))), set(...(k.digests ?? []).map(d => octet(Buffer.from(d, 'hex')))))))] : [];
  const rot = k.rot ? [ctx(704, true, seq(octet(new Uint8Array(32).fill(7)), bool(k.rot.locked), enumerated(k.rot.state), octet(new Uint8Array(32).fill(9))))] : [];
  const sw = seq(...(k.rotInSoftware ? rot : []), ...aid), hw = seq(...(k.rotInSoftware ? [] : rot));
  return seq(int(3), enumerated(k.attLevel), int(4), enumerated(k.keyLevel), octet('challenge'), octet(new Uint8Array()), sw, hw);
}
export const KEY_DESC_OID = '1.3.6.1.4.1.11129.2.1.17';
/** leaf → intermediate → root. `leafKey` is the attested key (its public half goes in the leaf). Returns DERs and the root as PEM. */
export async function chain(o: { leafSpki: Bytes; desc: KeyDesc; rootName?: string; root?: Key; leafSigner?: Key }): Promise<{ ders: Bytes[]; rootPem: string; root: Key; inter: Key }> {
  const root = o.root ?? await genKey('P-384'); const inter = await genKey('P-256'); const rootName = o.rootName ?? 'FAKE TEST ROOT (not Google)';
  const rootDer = await cert({ serial: 0xfa4e0001n, issuer: rootName, subject: rootName, spki: root.spki, signer: root, exts: [CA_EXT] });
  const interDer = await cert({ serial: 0xfa4e0002n, issuer: rootName, subject: 'FAKE TEST INTERMEDIATE', spki: inter.spki, signer: root, exts: [CA_EXT] });
  const leafDer = await cert({ serial: 1n, issuer: 'FAKE TEST INTERMEDIATE', subject: 'Android Keystore Key', spki: o.leafSpki, signer: o.leafSigner ?? inter,
    exts: [{ oid: KEY_DESC_OID, value: keyDescription(o.desc) }] });
  return { ders: [leafDer, interDer, rootDer], rootPem: pem(rootDer), root, inter };
}
export const pem = (der: Bytes) => `-----BEGIN CERTIFICATE-----\n${Buffer.from(der).toString('base64').replace(/.{64}/g, '$&\n')}\n-----END CERTIFICATE-----\n`;
