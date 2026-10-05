import { createC2pa, Reader, type C2pa } from '@contentauth/c2pa-web';
import wasmSrc from '@contentauth/c2pa-web/resources/c2pa.wasm?url';
import { MAX_VIDEO_BYTES } from '../config';
import { activeSignature, extractJumbf } from './jumbf';
import { summarize, type L2Reply } from './summary';
/** The page's own caps (40 MB photo, 100 MB video) come first; this bounds level 2 whoever calls it. c2pa-web reads the File by slices in its worker, and we read only the store. */
export const L2_MAX_BYTES = MAX_VIDEO_BYTES;
let c2pa: Promise<C2pa> | null = null;
const INIT_TIMEOUT_MS = 20_000;
const fail = (key: string): L2Reply => ({ summary: { kind: 'none', lines: [{ key, status: 'info' }], realDevice: false, bound: false }, payload: null });
async function attestationData(): Promise<{ roots: string[]; status: { entries: Record<string, unknown> } }> {
  // The daily copy (attestation-sync.yml); the page never contacts Google. Unreadable → no roots, so nothing can be "certified" (fail closed).
  try {
    const get = (f: string) => fetch(new URL('attestation/' + f, location.href), { cache: 'no-cache' }).then(r => { if (!r.ok) throw new Error(f); return r.json(); });
    const [roots, status] = await Promise.all([get('roots.json'), get('status.json')]);
    if (!Array.isArray(roots) || !roots.every(r => typeof r === 'string') || !status || typeof status.entries !== 'object' || status.entries === null) throw new Error('shape');
    return { roots, status };
  } catch { return { roots: [], status: { entries: {} } }; }
}
/** Level 2 for one picked file (spec §5.2). Never rejects: every failure is a line. */
export async function level2(file: File, qrKeyIdHex: string | null): Promise<L2Reply> {
  if (file.size > L2_MAX_BYTES) return fail('l2_error');
  let c: C2pa;
  // This browser cannot run the reader (no wasm, worker blocked): say so instead of leaving the page to the bridge's 60 s timeout.
  let timer: ReturnType<typeof setTimeout> | undefined;
  try { c = await Promise.race([c2pa ??= createC2pa({ wasmSrc }), new Promise<never>((_, no) => { timer = setTimeout(() => no(new Error('init timeout')), INIT_TIMEOUT_MS); })]); }
  catch { c2pa?.then(x => x.dispose(), () => undefined); c2pa = null; return fail('l2_error'); }
  finally { clearTimeout(timer); }
  let store: unknown = null;
  try { const r = await Reader.fromBlob(c, file.type || undefined, file);
    if (r) { try { store = await r.manifestStore(); } finally { await r.free().catch(() => undefined); } } }
  catch { return { summary: { kind: 'invalid', lines: [{ key: 'l2_invalid', status: 'fail' }], realDevice: false, bound: false }, payload: null }; }  // C2PA bytes present but unreadable: damaged
  if (!store) return summarize({ store, cose: null, roots: [], status: { entries: {} }, qrKeyIdHex });
  const [jumbf, att] = await Promise.all([extractJumbf(file), attestationData()]);
  return summarize({ store, cose: jumbf ? activeSignature(jumbf) : null, roots: att.roots, status: att.status, qrKeyIdHex });
}
