export interface Der { tag: number; cls: number; constructed: boolean; content: Uint8Array; end: number; start: number }
/**
 * Minimal DER reader, multi-byte tags included (Android's AuthorizationList uses [700+]). Bounded: a length past the end of the buffer,
 * an indefinite length or a length of more than 4 bytes throws (never a silently truncated `content`).
 */
export function readDer(b: Uint8Array, off = 0): Der {
  let i = off; if (i + 2 > b.length) throw new Error('der');
  const t0 = b[i++]; const cls = t0 >> 6, constructed = (t0 & 0x20) !== 0; let tag = t0 & 0x1f;
  if (tag === 0x1f) { tag = 0; let c; let n = 0; do { if (i >= b.length || ++n > 4) throw new Error('der tag'); c = b[i++]; tag = tag * 128 + (c & 0x7f); } while (c & 0x80); }
  if (i >= b.length) throw new Error('der');
  let len = b[i++];
  if (len & 0x80) { const n = len & 0x7f; if (n === 0 || n > 4) throw new Error('der length'); len = 0; for (let k = 0; k < n; k++) { if (i >= b.length) throw new Error('der'); len = len * 256 + b[i++]; } }
  if (i + len > b.length) throw new Error('der overrun');
  return { tag, cls, constructed, content: b.subarray(i, i + len), end: i + len, start: off };
}
export function kids(n: Der): Der[] { const out: Der[] = []; let i = 0; while (i < n.content.length) { const d = readDer(n.content, i); out.push(d); i = d.end; } return out; }
/** Non-negative INTEGER / ENUMERATED as a number (attestation fields are small). */
export const int = (n: Der) => n.content.reduce((a, x) => a * 256 + x, 0);
export const hex = (b: Uint8Array) => [...b].map(x => x.toString(16).padStart(2, '0')).join('');
export const eq = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);
/** Dotted OID from an OBJECT IDENTIFIER's content bytes. */
export function oid(c: Uint8Array): string {
  if (!c.length) return '';
  const first = Math.min(2, Math.floor(c[0] / 40)); const out = [first, c[0] - 40 * first]; let v = 0;
  for (let i = 1; i < c.length; i++) { v = v * 128 + (c[i] & 0x7f); if (!(c[i] & 0x80)) { out.push(v); v = 0; } }
  return out.join('.');
}
