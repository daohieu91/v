import { p256 } from '@noble/curves/nist.js';
import { sha256 } from '@noble/hashes/sha2.js';
import type { SealPayload } from './payload';

const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const big = (b: Uint8Array) => b.reduce((a, x) => (a << 8n) | BigInt(x), 0n);
const b32 = (v: bigint) => { const o = new Uint8Array(32); for (let i = 31; i >= 0; i--) { o[i] = Number(v & 0xffn); v >>= 8n; } return o; };
const hex = (b: Uint8Array) => [...b].map(x => x.toString(16).padStart(2, '0')).join('');

/**
 * Q = r⁻¹(sR − eG) with e = SHA-256(msg), R the curve point with x = r and y-parity v. 65-byte uncompressed point, or null; never throws.
 * Android Keystore signatures are not low-S (the app normalises since Task 5, but older or foreign payloads may not): (r, s, v) and
 * (r, n − s, v ⊕ 1) recover the same key (−R flips the y-parity), so a high-S input is normalised first. noble 2.4's recovery does not
 * itself enforce low S (measured: the normalisation mutation stays green), so this is for any low-S `verify` built on it later.
 * Recovery proves nothing about the key's owner: the key TAG check in checkSeal is what makes an edited payload fail.
 */
export function recoverRaw(msg: Uint8Array, r: bigint, s: bigint, v: 0 | 1): Uint8Array | null {
  try {
    if (r <= 0n || r >= N || s <= 0n || s >= N) return null;
    let rv: number = v;
    if (s > N / 2n) { s = N - s; rv ^= 1; }
    const rec = new Uint8Array(65); rec[0] = rv; rec.set(b32(r), 1); rec.set(b32(s), 33);
    const pk = p256.recoverPublicKey(rec, msg);                // prehash: SHA-256(msg), as the Keystore's SHA256withECDSA
    return p256.Point.fromBytes(pk).toBytes(false);
  } catch { return null; }
}
export function recoverPublicKey(p: SealPayload): Uint8Array | null {
  return recoverRaw(p.signed, big(p.signature.subarray(0, 32)), big(p.signature.subarray(32, 64)), p.recoveryBit);
}
/** SHA-256 of the 65-byte uncompressed point, first 8 bytes. The page shows all 8 bytes, never only the 4-byte tag (P18 e). */
export const keyIdOf = (pub65: Uint8Array): Uint8Array => sha256(pub65).slice(0, 8);
export function checkSeal(p: SealPayload): { ok: boolean; keyIdHex: string | null } {
  const pub = recoverPublicKey(p); if (!pub) return { ok: false, keyIdHex: null };
  const id = keyIdOf(pub); const tag = new DataView(id.buffer, id.byteOffset, 4).getInt32(0);
  return tag === p.fields.keyTag ? { ok: true, keyIdHex: hex(id) } : { ok: false, keyIdHex: null };
}
