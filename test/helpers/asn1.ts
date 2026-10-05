// A tiny DER WRITER for test fixtures only (synthetic attestation chains). The page has no DER writer.
export type Bytes = Uint8Array;
const cat = (...p: Bytes[]) => { const o = new Uint8Array(p.reduce((s, x) => s + x.length, 0)); let i = 0; for (const x of p) { o.set(x, i); i += x.length; } return o; };
const len = (n: number): number[] => n < 0x80 ? [n] : n < 0x100 ? [0x81, n] : n < 0x10000 ? [0x82, n >> 8, n & 255] : [0x83, n >> 16, (n >> 8) & 255, n & 255];
export const tlv = (tag: number[] | number, ...content: Bytes[]) => { const c = cat(...content); return cat(Uint8Array.from(Array.isArray(tag) ? tag : [tag]), Uint8Array.from(len(c.length)), c); };
export const seq = (...c: Bytes[]) => tlv(0x30, ...c);
export const set = (...c: Bytes[]) => tlv(0x31, ...c);
export const octet = (b: Bytes | string) => tlv(0x04, typeof b === 'string' ? new TextEncoder().encode(b) : b);
export const bool = (v: boolean) => tlv(0x01, Uint8Array.of(v ? 0xff : 0));
export const nul = () => Uint8Array.of(0x05, 0);
function intBytes(v: bigint): Bytes { const out: number[] = []; do { out.unshift(Number(v & 0xffn)); v >>= 8n; } while (v > 0n); if (out[0] & 0x80) out.unshift(0); return Uint8Array.from(out); }
export const int = (v: number | bigint) => tlv(0x02, intBytes(BigInt(v)));
export const enumerated = (v: number) => tlv(0x0a, intBytes(BigInt(v)));
export const bits = (b: Bytes) => tlv(0x03, Uint8Array.of(0), b);
export const utf8 = (s: string) => tlv(0x0c, new TextEncoder().encode(s));
export const printable = (s: string) => tlv(0x13, new TextEncoder().encode(s));
export const genTime = (s: string) => tlv(0x18, new TextEncoder().encode(s));
export const utcTime = (s: string) => tlv(0x17, new TextEncoder().encode(s));
export function oid(dotted: string): Bytes {
  const p = dotted.split('.').map(Number); const out = [40 * p[0] + p[1]];
  for (const v of p.slice(2)) { const s: number[] = [v & 0x7f]; let x = Math.floor(v / 128); while (x > 0) { s.unshift((x & 0x7f) | 0x80); x = Math.floor(x / 128); } out.push(...s); }
  return tlv(0x06, Uint8Array.from(out));
}
/** Context-specific tag [n]; constructed (EXPLICIT) by default. Multi-byte tag numbers for n ≥ 31 ([704] → BF 85 40). */
export function ctx(n: number, constructed: boolean, ...c: Bytes[]): Bytes {
  const first = 0x80 | (constructed ? 0x20 : 0);
  if (n < 31) return tlv(first | n, ...c);
  const s: number[] = [n & 0x7f]; let x = n >> 7; while (x > 0) { s.unshift((x & 0x7f) | 0x80); x >>= 7; }
  return tlv([first | 0x1f, ...s], ...c);
}
export const name = (cn: string) => seq(set(seq(oid('2.5.4.3'), utf8(cn))));
export { cat };
