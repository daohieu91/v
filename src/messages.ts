import { URL_PREFIX } from './config';
import { MAX_FRAGMENT_LEN, encodeHeader, type SealPayload } from './payload';
import type { Analysis } from './analyze';
import type { Check, L2Summary } from './verdict';
/**
 * Shape checks for everything that crosses a postMessage boundary (worker, level-2 iframe). Anything malformed is null: the page then
 * shows "could not be read", never a guess. Pure, so they are unit-tested.
 */
const isInt = (x: unknown, lo: number, hi: number): x is number => typeof x === 'number' && Number.isInteger(x) && x >= lo && x <= hi;
const isObj = (x: unknown): x is Record<string, unknown> => typeof x === 'object' && x !== null;
const fallbackOk = (x: unknown) => x === null || (typeof x === 'string' && x.length <= MAX_FRAGMENT_LEN);

export type Job = { file: Blob; fallback: string | null } | { data: ArrayBuffer; w: number; h: number; fallback: string | null };
export function validJob(m: unknown): Job | null {
  if (!isObj(m) || !fallbackOk(m.fallback)) return null;
  if (typeof Blob !== 'undefined' && m.file instanceof Blob) return { file: m.file, fallback: m.fallback as string | null };
  if (m.data instanceof ArrayBuffer && isInt(m.w, 1, 8192) && isInt(m.h, 1, 8192) && m.w * m.h * 4 === m.data.byteLength)
    return { data: m.data, w: m.w, h: m.h, fallback: m.fallback as string | null };
  return null;
}
export type Reply = { ok: true; r: Analysis; dec: { w: number; h: number; via: 'plain' | 'resize' | 'page' } } | { ok: false; need?: 'pixels'; err?: 'oversize' };
export function validReply(m: unknown): Reply | null {
  if (!isObj(m)) return null;
  if (m.ok === false) return { ok: false, ...(m.need === 'pixels' ? { need: 'pixels' as const } : {}), ...(m.err === 'oversize' ? { err: 'oversize' as const } : {}) };
  if (m.ok !== true || !isObj(m.r) || !isObj(m.dec)) return null;
  const { url, hamming } = m.r; const d = m.dec;
  const urlOk = url === null || (typeof url === 'string' && url.startsWith(URL_PREFIX) && url.length <= URL_PREFIX.length + MAX_FRAGMENT_LEN);
  if (!urlOk || !(hamming === null || isInt(hamming, 0, 64)) || !isInt(d.w, 1, 8192) || !isInt(d.h, 1, 8192) || !['plain', 'resize', 'page'].includes(d.via as string)) return null;
  return { ok: true, r: { url: url as string | null, hamming: hamming as number | null }, dec: { w: d.w, h: d.h, via: d.via as 'plain' | 'resize' | 'page' } };
}
const STATUS = ['pass', 'warn', 'fail', 'info'];
function validCheck(c: unknown): Check | null {
  if (!isObj(c) || typeof c.key !== 'string' || !/^[a-z0-9_]{1,40}$/.test(c.key) || !STATUS.includes(c.status as string)) return null;
  if (c.params === undefined) return { key: c.key, status: c.status as Check['status'] };
  if (!isObj(c.params)) return null; const p: Record<string, string | number> = {};
  for (const [k, v] of Object.entries(c.params)) { if (!/^\w{1,20}$/.test(k) || !((typeof v === 'string' && v.length <= 200) || (typeof v === 'number' && Number.isFinite(v)))) return null; p[k] = v; }
  return { key: c.key, status: c.status as Check['status'], params: p };
}
/** The level-2 reply. A payload is accepted only if its signed bytes ARE the header of its fields (else valid bytes could carry other fields). */
export function validL2Reply(m: unknown): { summary: L2Summary; payload: SealPayload | null } | null {
  if (!isObj(m) || !isObj(m.summary)) return null;
  const s = m.summary; if (!['none', 'invalid', 'ok'].includes(s.kind as string) || typeof s.realDevice !== 'boolean' || !Array.isArray(s.lines) || s.lines.length > 64) return null;
  const lines = s.lines.map(validCheck); if (lines.some(x => x === null)) return null;
  let payload: SealPayload | null = null;
  if (m.payload !== null && m.payload !== undefined) {
    const p = m.payload; if (!isObj(p) || !isObj(p.fields) || !(p.signature instanceof Uint8Array) || p.signature.length !== 64
      || !(p.signed instanceof Uint8Array) || p.signed.length !== 39 || (p.recoveryBit !== 0 && p.recoveryBit !== 1)) return null;
    try { const h = encodeHeader(p.fields as unknown as SealPayload['fields'], 0); if (h.some((x, i) => x !== (p.signed as Uint8Array)[i])) return null; } catch { return null; }
    payload = p as unknown as SealPayload;
  }
  return { summary: { kind: s.kind as L2Summary['kind'], lines: lines as Check[], realDevice: s.realDevice }, payload };
}
