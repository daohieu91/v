// P45 fixtures: a COSE_Sign1 (tag 18, [protected, unprotected, nil, signature]) with its unprotected time-stamp tokens replaced. The
// unprotected bucket is not covered by the claim signature, so the file stays validly signed; `sameSize` shrinks or grows "pad" so the
// COSE bytes keep their length and the file can be patched in place (the JUMBF box sizes and the hard-binding exclusion are unchanged).
const cat = (p: Uint8Array[]) => { const o = new Uint8Array(p.reduce((s, x) => s + x.length, 0)); let i = 0; for (const x of p) { o.set(x, i); i += x.length; } return o; };
const head = (major: number, n: number) => Uint8Array.from(n < 24 ? [(major << 5) | n] : n < 256 ? [(major << 5) | 24, n] : n < 65536 ? [(major << 5) | 25, n >> 8, n & 255]
  : [(major << 5) | 26, n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);
const text = (s: string) => { const b = new TextEncoder().encode(s); return cat([head(3, b.length), b]); };
const bytes = (b: Uint8Array) => cat([head(2, b.length), b]);
/** Length of the CBOR item at `i` (definite lengths only: enough for a COSE protected bstr). */
function itemEnd(b: Uint8Array, i: number): number {
  const info = b[i] & 31; const w = info < 24 ? 0 : info === 24 ? 1 : info === 25 ? 2 : 4;
  let n = info < 24 ? info : 0; for (let k = 0; k < w; k++) n = n * 256 + b[i + 1 + k]; return i + 1 + w + n;
}
/** The unprotected map as the writers lay it out (sigTst2 then pad, or pad then sigTst2), with `tokens` and a pad of `pad` bytes. */
function unprotected(tokens: Uint8Array[], pad: number, padFirst: boolean): Uint8Array {
  const tst = cat([text('sigTst2'), head(5, 1), text('tstTokens'), head(4, tokens.length), ...tokens.map(t => cat([head(5, 1), text('val'), bytes(t)]))]);
  const p = cat([text('pad'), bytes(new Uint8Array(pad))]);
  return cat([head(5, 2), ...(padFirst ? [p, tst] : [tst, p])]);
}
export function withTokens(cose: Uint8Array, tokens: Uint8Array[], sameSize = true): Uint8Array {
  if (cose[0] !== 0xd2 || cose[1] !== 0x84) throw new Error('not a tagged COSE_Sign1');
  const mapStart = itemEnd(cose, 2), tail = cose.subarray(cose.length - 67);              // nil, then the 64-byte signature bstr
  if (tail[0] !== 0xf6 || tail[1] !== 0x58 || tail[2] !== 0x40) throw new Error('unexpected COSE tail');
  const padFirst = new TextDecoder().decode(cose.subarray(mapStart, mapStart + 8)).includes('pad');
  const build = (pad: number) => cat([cose.subarray(0, mapStart), unprotected(tokens, pad, padFirst), tail]);
  if (!sameSize) return build(256);
  for (let pad = Math.max(0, cose.length - build(0).length - 5); pad <= cose.length; pad++) { const c = build(pad); if (c.length === cose.length) return c; if (c.length > cose.length) break; }
  throw new Error('the tokens do not fit in this COSE box');
}
/** Patches a file's COSE bytes in place (they must sit in one piece, e.g. one APP11 segment). */
export function patchFile(file: Uint8Array, cose: Uint8Array, next: Uint8Array): Uint8Array {
  if (next.length !== cose.length) throw new Error('size changed');
  const at = Buffer.from(file).indexOf(Buffer.from(cose)); if (at < 0) throw new Error('COSE not contiguous in the file');
  const out = file.slice(); out.set(next, at); return out;
}
