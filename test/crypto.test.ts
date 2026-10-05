import { describe, expect, it } from 'vitest';
import { sha256 } from '@noble/hashes/sha2.js';
import { recoverRaw } from '../src/crypto';

const hex = (b: Uint8Array) => [...b].map(x => x.toString(16).padStart(2, '0')).join('');
const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

// Independent known answer: RFC 6979 §A.2.5 (P-256, SHA-256, message "sample"). Its s is HIGH (> n/2), so this also checks recovery of
// a high-S signature against a key from a source that is not ours.
describe('P-256 public-key recovery, RFC 6979 A.2.5 known answer', () => {
  const U = '0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299';
  const r = 0xefd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716n;
  const s = 0xf7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8n;
  const msg = new TextEncoder().encode('sample');
  it('exactly one recovery bit yields the RFC public key, and the low-S twin with the other bit yields it too', () => {
    expect(s > N / 2n).toBe(true);
    const got = [0, 1].map(v => recoverRaw(msg, r, s, v as 0 | 1)).map(k => (k ? hex(k) : null));
    expect(got.filter(k => k === U)).toHaveLength(1);
    const v = got.indexOf(U) as 0 | 1;
    expect(hex(recoverRaw(msg, r, N - s, (v ^ 1) as 0 | 1)!)).toBe(U);
    expect(recoverRaw(msg, r, N - s, v)).not.toBeNull();
    expect(hex(recoverRaw(msg, r, N - s, v)!)).not.toBe(U);
  });
  it('out-of-range scalars return null and never throw', () => {
    for (const [rr, ss] of [[0n, s], [r, 0n], [N, s], [r, N], [2n ** 256n - 1n, s]] as const) expect(recoverRaw(msg, rr, ss, 0)).toBeNull();
    expect(recoverRaw(sha256(msg), 1n, 1n, 0)).toBeNull();   // r = 1 is not the x of a curve point
  });
});
