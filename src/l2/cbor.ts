/** Minimal CBOR decoder (RFC 8949) for the COSE / claim structures level 2 reads. Bounded: reading past the end, or nesting deeper than 64, throws. */
export type Cbor = number | bigint | string | boolean | null | undefined | Uint8Array | Cbor[] | Map<Cbor, Cbor> | { tag: number; value: Cbor };
export function decodeCbor(b: Uint8Array): Cbor { const [v] = item(b, 0, 0); return v; }
const need = (b: Uint8Array, i: number) => { if (i >= b.length) throw new Error('cbor eof'); };
function head(b: Uint8Array, i: number): [number, number, number | bigint, number] {   // major, info, value, next
  need(b, i); const ib = b[i], major = ib >> 5, info = ib & 31; let v: number | bigint = info, n = i + 1;
  const width = info === 24 ? 1 : info === 25 ? 2 : info === 26 ? 4 : info === 27 ? 8 : 0; if (width) need(b, n + width - 1);
  if (info === 24) { v = b[n]; n += 1; } else if (info === 25) { v = (b[n] << 8) | b[n + 1]; n += 2; }
  else if (info === 26) { v = ((b[n] << 24) >>> 0) + (b[n + 1] << 16) + (b[n + 2] << 8) + b[n + 3]; n += 4; }
  else if (info === 27) { let x = 0n; for (let k = 0; k < 8; k++) x = (x << 8n) | BigInt(b[n + k]); v = x <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(x) : x; n += 8; }
  else if (info > 27 && info !== 31) throw new Error('cbor');
  return [major, info, v, n];
}
function item(b: Uint8Array, i: number, depth: number): [Cbor, number] {
  if (depth > 64) throw new Error('cbor depth');
  const [major, info, v, n] = head(b, i); const len = Number(v); const d = depth + 1;
  switch (major) {
    case 0: return [v, n];
    case 1: return [typeof v === 'bigint' ? -1n - v : -1 - v, n];
    case 2: case 3: {
      if (info === 31) { const parts: Uint8Array[] = []; let k = n; while ((need(b, k), b[k]) !== 0xff) { const [p, nk] = item(b, k, d); parts.push(typeof p === 'string' ? new TextEncoder().encode(p) : p as Uint8Array); k = nk; }
        const all = new Uint8Array(parts.reduce((s, p) => s + p.length, 0)); let o = 0; for (const p of parts) { all.set(p, o); o += p.length; }
        return [major === 2 ? all : new TextDecoder().decode(all), k + 1]; }
      if (n + len > b.length) throw new Error('cbor eof');
      const s = b.slice(n, n + len); return [major === 2 ? s : new TextDecoder().decode(s), n + len]; }
    case 4: { const a: Cbor[] = []; let k = n; if (info === 31) { while ((need(b, k), b[k]) !== 0xff) { const [x, nk] = item(b, k, d); a.push(x); k = nk; } return [a, k + 1]; }
      for (let c = 0; c < len; c++) { const [x, nk] = item(b, k, d); a.push(x); k = nk; } return [a, k]; }
    case 5: { const m = new Map<Cbor, Cbor>(); let k = n; const one = () => { const [key, k1] = item(b, k, d); const [val, k2] = item(b, k1, d); m.set(key, val); k = k2; };
      if (info === 31) { while ((need(b, k), b[k]) !== 0xff) one(); return [m, k + 1]; } for (let c = 0; c < len; c++) one(); return [m, k]; }
    case 6: { const [x, k] = item(b, n, d); return [{ tag: len, value: x }, k]; }
    default: { if (info === 20) return [false, n]; if (info === 21) return [true, n]; if (info === 22) return [null, n]; if (info === 23) return [undefined, n];
      if (info === 25 || info === 26 || info === 27) return [len, n]; throw new Error('cbor simple'); }
  }
}
