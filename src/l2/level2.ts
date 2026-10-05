import { createC2pa, Reader, type C2pa } from '@contentauth/c2pa-web';
import wasmSrc from '@contentauth/c2pa-web/resources/c2pa.wasm?url';
import { MAX_VIDEO_BYTES } from '../config';
import { activeSignature, extractJumbf } from './jumbf';
import { summarize, type L2Reply } from './summary';
/** The page's own caps (40 MB photo, 100 MB video) come first; this bounds level 2 whoever calls it. c2pa-web reads the File by slices in its worker, and we read only the store. */
export const L2_MAX_BYTES = MAX_VIDEO_BYTES;
/** Init + read must end well before the page's 60 s bridge timeout (l2client.ts), so a hang is "couldn't read this file here", never silence. */
export const READ_DEADLINE_MS = 45_000;
const fail = (key: 'l2_error' | 'l2_invalid'): L2Reply => ({ summary: { kind: key === 'l2_invalid' ? 'invalid' : 'none', lines: [{ key, status: key === 'l2_invalid' ? 'fail' : 'info' }], realDevice: false, bound: false }, payload: null });
/**
 * P35: only a C2PA format/validation error (c2pa-rs `C2pa(<variant>…)`, measured on damaged JUMBF: `C2pa(JumbfParseError(UnexpectedEof))`)
 * means the file's C2PA data is damaged (red). Everything else — `C2pa(InvalidAsset(…))` on a truncated file, IO, OOM ("memory access out
 * of bounds", RangeError), a crashed worker, a timeout — says nothing about the file: "couldn't read this file here".
 */
const FORMAT_ERROR = /^C2pa\((Jumbf|Claim|Assertion|Hash|Cose|Cbor|Manifest|Signature|Invalid(Claim|Cose|Manifest)|Verify|BadParam|Json|DuplicateLabel|UnreferencedManifest|Prerelease)/;
export function readFailure(e: unknown): 'l2_invalid' | 'l2_error' {
  const msg = e instanceof Error ? e.message : typeof e === 'string' ? e : '';
  return FORMAT_ERROR.test(msg) ? 'l2_invalid' : 'l2_error';
}
export interface L2Deps {
  read(file: File): Promise<unknown>;                  // the manifest store, or null when the file has no C2PA data
  attestation(): Promise<{ roots: string[]; status: { entries: Record<string, unknown> } }>;
  deadlineMs: number;
}
class Timeout extends Error {}
function within<T>(p: Promise<T>, ms: number): Promise<T> {
  let t: ReturnType<typeof setTimeout> | undefined;
  return Promise.race([p, new Promise<never>((_, no) => { t = setTimeout(() => no(new Timeout('deadline')), ms); })]).finally(() => clearTimeout(t));
}
let c2pa: Promise<C2pa> | null = null;
async function readStore(file: File): Promise<unknown> {
  let c: C2pa;
  try { c = await (c2pa ??= createC2pa({ wasmSrc })); } catch (e) { c2pa = null; throw e; }   // no wasm / worker blocked: l2_error
  const r = await Reader.fromBlob(c, file.type || undefined, file); if (!r) return null;
  try { return await r.manifestStore(); } finally { await r.free().catch(() => undefined); }
}
async function attestationData(): Promise<{ roots: string[]; status: { entries: Record<string, unknown> } }> {
  // The daily copy (attestation-sync.yml); the page never contacts Google. Unreadable → no roots, so nothing can be "certified" (fail closed).
  try {
    const get = (f: string) => fetch(new URL('attestation/' + f, location.href), { cache: 'no-cache' }).then(r => { if (!r.ok) throw new Error(f); return r.json(); });
    const [roots, status] = await Promise.all([get('roots.json'), get('status.json')]);
    if (!Array.isArray(roots) || !roots.every(r => typeof r === 'string') || !status || typeof status.entries !== 'object' || status.entries === null) throw new Error('shape');
    return { roots, status };
  } catch { return { roots: [], status: { entries: {} } }; }
}
const DEFAULT: L2Deps = { read: readStore, attestation: attestationData, deadlineMs: READ_DEADLINE_MS };
/** Level 2 for one picked file (spec §5.2). Never rejects: every failure is a line. */
export async function level2(file: File, qrKeyIdHex: string | null, deps: L2Deps = DEFAULT): Promise<L2Reply> {
  if (file.size > L2_MAX_BYTES) return fail('l2_error');
  try {
    return await within((async () => {
      let store: unknown;
      try { store = await deps.read(file); } catch (e) { if (e instanceof Timeout) throw e; if (readFailure(e) === 'l2_error') c2pa = null; return fail(readFailure(e)); }
      if (!store) return summarize({ store, cose: null, roots: [], status: { entries: {} }, qrKeyIdHex });
      const [jumbf, att] = await Promise.all([extractJumbf(file), deps.attestation()]);
      return summarize({ store, cose: jumbf ? activeSignature(jumbf) : null, roots: att.roots, status: att.status, qrKeyIdHex });
    })(), deps.deadlineMs);
  } catch { c2pa?.then(x => x.dispose(), () => undefined); c2pa = null; return fail('l2_error'); }   // timeout or anything unexpected
}
