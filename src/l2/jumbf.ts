import { decodeCbor, type Cbor } from './cbor';
import { kids, readDer } from './der';
import { commonName, hasEku, parseCert } from './x509';
/**
 * Finds the C2PA manifest store (JUMBF) of a JPEG or an MP4 and reads the two things c2pa-web's report does not expose (spike item 1c):
 * the COSE signer's x5chain and its RFC 3161 time-stamp token. Reads a File by slices (segment and box headers, then the store itself),
 * never the whole file, and refuses a store larger than MAX_STORE.
 */
export const MAX_STORE = 16 * 1024 * 1024;
const C2PA_UUID = [0xd8, 0xfe, 0xc3, 0xd6, 0x1b, 0x0e, 0x48, 0x3c, 0x92, 0x97, 0x58, 0x28, 0x87, 0x7e, 0xc4, 0x81];
const u32 = (b: Uint8Array, i: number) => ((b[i] << 24) >>> 0) + (b[i + 1] << 16) + (b[i + 2] << 8) + b[i + 3];
const str = (b: Uint8Array, i: number, n: number) => String.fromCharCode(...b.subarray(i, i + n));
type At = (off: number, n: number) => Promise<Uint8Array>;
function source(f: Uint8Array | Blob): { size: number; at: At } {
  if (f instanceof Uint8Array) return { size: f.length, at: async (o, n) => f.subarray(o, Math.min(f.length, o + n)) };
  return { size: f.size, at: async (o, n) => new Uint8Array(await f.slice(o, Math.min(f.size, o + n)).arrayBuffer()) };
}
const cat = (parts: Uint8Array[]) => { const out = new Uint8Array(parts.reduce((s, p) => s + p.length, 0)); let o = 0; for (const p of parts) { out.set(p, o); o += p.length; } return out; };

/**
 * JPEG: the APP11 "JP" segments (ISO 19566-5 / C2PA §A.3.1) of the first JUMBF box instance, in packet order. The first packet keeps
 * its box header; later ones repeat LBox/TBox (8 bytes, or 16 with an XLBox), which is skipped. MP4: the C2PA `uuid` box with
 * purpose "manifest" (C2PA §A.4.2). Null when there is none, or the store is malformed or too large.
 */
export async function extractJumbf(file: Uint8Array | Blob): Promise<Uint8Array | null> {
  const { size, at } = source(file);
  try {
    const sig = await at(0, 2);
    if (sig[0] === 0xff && sig[1] === 0xd8) {
      const parts: Uint8Array[] = []; let i = 2, en = -1, next = 1, total = 0;
      while (i + 4 <= size) {
        const h = await at(i, 4); if (h[0] !== 0xff) break;
        const m = h[1], len = (h[2] << 8) | h[3]; if (m === 0xda || m === 0xd9) break;
        if (m === 0xeb && len >= 18) {
          const seg = await at(i + 4, len - 2);
          if (str(seg, 0, 2) === 'JP') { const e = (seg[2] << 8) | seg[3], z = u32(seg, 4); const body = seg.subarray(8);
            if (en < 0 && z === 1 && str(body, 4, 4) === 'jumb') en = e;
            if (e === en) { if (z !== next) return null; next++;
              const p = z === 1 ? body : body.subarray(u32(body, 0) === 1 ? 16 : 8); total += p.length; if (total > MAX_STORE) return null; parts.push(p); } }
        }
        i += 2 + len;
      }
      return parts.length ? cat(parts) : null;
    }
    for (let i = 0, k = 0; i + 8 <= size && k < 4096; k++) {
      const h = await at(i, 16); let bsize = u32(h, 0); const type = str(h, 4, 4); let hdr = 8;
      if (bsize === 1) { bsize = u32(h, 8) * 2 ** 32 + u32(h, 12); hdr = 16; } else if (bsize === 0) bsize = size - i;
      if (bsize < hdr || i + bsize > size) return null;
      if (type === 'uuid' && bsize <= MAX_STORE + 1024) {
        const box = await at(i + hdr, bsize - hdr);
        if (C2PA_UUID.every((x, j) => box[j] === x)) {
          let p = 16 + 4; const start = p; while (p < box.length && box[p] !== 0) p++;
          if (str(box, start, p - start) === 'manifest') return box.subarray(p + 1 + 8);       // purpose\0, then the 8-byte merkle offset
        }
      }
      i += bsize;
    }
  } catch { return null; }
  return null;
}
export interface Box { type: string; label: string | null; payload: Uint8Array; children: Box[] }
function boxes(b: Uint8Array, depth = 0): Box[] {
  const out: Box[] = []; let i = 0; if (depth > 16) throw new Error('jumbf depth');
  while (i + 8 <= b.length) { const len = u32(b, i), type = str(b, i + 4, 4); if (len < 8 || i + len > b.length) break; const body = b.subarray(i + 8, i + len);
    if (type === 'jumb') { const kidsB = boxes(body, depth + 1); const d = kidsB[0]; out.push({ type, label: d?.type === 'jumd' ? d.label : null, payload: body, children: kidsB.slice(1) }); }
    else if (type === 'jumd') { const toggles = body[16]; let label: string | null = null;
      if (toggles & 0x02) { let e = 17; while (e < body.length && body[e] !== 0) e++; label = new TextDecoder().decode(body.subarray(17, e)); }
      out.push({ type, label, payload: body, children: [] }); }
    else out.push({ type, label: null, payload: body, children: [] });
    i += len; }
  return out;
}
/** The active manifest is the last one in the store (C2PA §11.1.4.2). Returns the COSE_Sign1 bytes of its c2pa.signature box. */
export function activeSignature(jumbf: Uint8Array): Uint8Array | null {
  try {
    const store = boxes(jumbf).find(b => b.label === 'c2pa'); const manifests = store?.children.filter(c => c.type === 'jumb') ?? [];
    const active = manifests[manifests.length - 1]; const sig = active?.children.find(c => c.label === 'c2pa.signature');
    return sig?.children.find(c => c.type === 'cbor')?.payload ?? null;
  } catch { return null; }
}
/** COSE_Sign1 (RFC 9052): x5chain (label 33) from the protected header, else the unprotected one; tokens of sigTst2 (C2PA 2.x), else sigTst. */
export function coseSigner(cose: Uint8Array): { x5chain: Uint8Array[]; tstTokens: Uint8Array[] } {
  let v = decodeCbor(cose); if (v && typeof v === 'object' && 'tag' in (v as object)) v = (v as { value: Cbor }).value;
  if (!Array.isArray(v) || v.length !== 4 || !(v[0] instanceof Uint8Array) || !(v[1] instanceof Map)) throw new Error('cose');
  const p = v[0].length ? decodeCbor(v[0]) as Map<Cbor, Cbor> : new Map<Cbor, Cbor>(); const u = v[1] as Map<Cbor, Cbor>;
  const x = (p.get(33) ?? u.get(33)) as Uint8Array | Uint8Array[] | undefined;
  const tst = (u.get('sigTst2') ?? u.get('sigTst')) as Map<Cbor, Cbor> | undefined;
  const list = tst instanceof Map ? tst.get('tstTokens') : undefined;
  const tokens = (Array.isArray(list) ? list : []).map(t => (t instanceof Map ? t.get('val') : null)).filter((t): t is Uint8Array => t instanceof Uint8Array);
  const chain = x instanceof Uint8Array ? [x] : Array.isArray(x) ? x.filter((c): c is Uint8Array => c instanceof Uint8Array) : [];
  return { x5chain: chain, tstTokens: tokens };
}
/** GeneralizedTime "YYYYMMDDHHMMSS[.f]Z" → "YYYY-MM-DD HH:MM:SS UTC"; anything else is returned unchanged (it is shown as text only). */
export function formatGenTime(g: string): string {
  const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.\d+)?Z$/.exec(g);
  return m ? `${m[1]}-${m[2]}-${m[3]} ${m[4]}:${m[5]}:${m[6]} UTC` : g.slice(0, 40);
}
/** RFC 3161 token: ContentInfo → SignedData → encapContentInfo → TSTInfo.genTime; the TSA name is the CN of the certificate with EKU timeStamping. */
export function tstInfo(token: Uint8Array): { genTime: string; tsaName: string | null } | null {
  try {
    const sd = readDer(kids(readDer(token))[1].content);                                // [0] EXPLICIT → SignedData SEQUENCE
    const parts = kids(sd); const eci = parts[2];                                        // version, digestAlgorithms, encapContentInfo, [0] certificates, …
    const tst = kids(readDer(kids(kids(eci)[1])[0].content));                            // [0] EXPLICIT eContent OCTET STRING → TSTInfo SEQUENCE
    if (tst[4]?.tag !== 24) return null;                                                 // version, policy, messageImprint, serialNumber, genTime
    const genTime = formatGenTime(new TextDecoder().decode(tst[4].content));
    let tsaName: string | null = null;
    const certs = parts.find(p => p.cls === 2 && p.tag === 0);
    if (certs) for (const c of kids(certs)) {
      const raw = certs.content.subarray(c.start, c.end);
      try { const cert = parseCert(raw); if (hasEku(cert, '1.3.6.1.5.5.7.3.8')) { tsaName = commonName(cert.subject); break; } } catch { /* next */ }
    }
    return { genTime, tsaName };
  } catch { return null; }
}
