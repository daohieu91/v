import { parseCheckedAt } from './attestation-date';
import { checkSeal } from './crypto';
import { fileToRgba, MAX_FILE_BYTES, sniffC2pa, type Rgba } from './image';
import { loadDict, pickLocale } from './i18n';
import { runLevel2 } from './l2client';
import { decodeFragment, payloadFromUrl, type SealPayload } from './payload';
import type { Analysis } from './analyze';
import { render } from './ui';
import { verdict, type L2Summary, type Verdict } from './verdict';

const root = document.getElementById('app')!;
let locale = pickLocale(navigator.languages?.length ? navigator.languages : [navigator.language ?? 'en']);
let dict = await loadDict(locale);
let state: { verdict: Verdict | 'pending' | null; payload: SealPayload | null; message: string | null } = { verdict: null, payload: null, message: null };
let attested: string | null | undefined;
let busy = false;
const draw = () => render(root, { dict, locale, ...state, attested, onPick: pick,
  onLocale: async l => { try { const d = await loadDict(l); locale = l; dict = d; } catch { /* keep the current language */ } draw(); } });

const fragment = () => location.hash.slice(1);
function fromHash(): SealPayload | null { try { return decodeFragment(fragment()); } catch { return null; } }
/** The verdict comes from checkSeal alone (never from a recovered key); `payload` null or a failed seal is red. */
function show(payload: SealPayload | null, h: number | null, l2: L2Summary | null) {
  state = { verdict: verdict({ payload, seal: payload ? checkSeal(payload) : null, hamming: h, level2: l2 }), payload, message: null }; draw(); }
const fail = (message: string) => { state = { verdict: null, payload: null, message }; draw(); };

type Reply = { ok: boolean; r?: Analysis; need?: 'pixels' };
function job(msg: object, transfer: Transferable[]): Promise<Reply> {
  return new Promise((ok, bad) => {
    const w = new Worker(new URL('./analyze.worker.ts', import.meta.url));
    const done = () => { clearTimeout(to); w.terminate(); };
    const to = setTimeout(() => { done(); bad(new Error('timeout')); }, 90_000);
    w.onmessage = (e: MessageEvent<Reply>) => { done(); ok(e.data); };
    w.onerror = () => { done(); bad(new Error('worker')); };
    w.postMessage(msg, transfer);
  });
}
/**
 * Decode + QR search + fingerprint off the main thread: a 12 MP photo is seconds of work on a mid phone. The worker decodes the File
 * itself where OffscreenCanvas exists; elsewhere the page decodes (bounded to 4096 px) and transfers the pixels. One worker per job.
 */
async function analyzeOffThread(f: File, fallback: string | null): Promise<Analysis> {
  let r = await job({ file: f, fallback }, []);
  if (!r.ok && r.need === 'pixels') { const im: Rgba = await fileToRgba(f); r = await job({ data: im.data.buffer, w: im.w, h: im.h, fallback }, [im.data.buffer]); }
  if (!r.ok || !r.r) throw new Error('analyze');
  return r.r;
}

async function pick(f: File) {
  if (busy) return;
  if (f.size > MAX_FILE_BYTES) return fail('error_too_big');
  busy = true; state = { ...state, verdict: 'pending', message: null }; draw();
  try {
    const c2pa = await sniffC2pa(f);
    let payload: SealPayload | null = null; let h: number | null = null; let code = false;
    if (!f.type.startsWith('video/')) {
      const r = await analyzeOffThread(f, fromHash() ? fragment() : null);
      if (r.url) { code = true; payload = payloadFromUrl(r.url); h = payload ? r.hamming : null; }
    }
    const seal = payload ? checkSeal(payload) : null;
    const l2 = c2pa ? await runLevel2(f, seal?.ok ? seal.keyIdHex : null) : null;
    if (!payload && l2?.payload) payload = l2.payload;                              // a video original: level 2 carries the fields
    if (!payload && !code && !l2) return fail('no_code');
    show(payload, h, l2?.summary ?? null);
  } catch { fail('error_read'); }
  finally { busy = false; }
}

window.addEventListener('hashchange', () => { if (fragment()) show(fromHash(), null, null); });
if (fragment()) show(fromHash(), null, null); else draw();
fetch(import.meta.env.BASE_URL + 'attestation/meta.json', { cache: 'no-cache' }).then(r => r.json())
  .then(j => { attested = parseCheckedAt(j); }, () => { attested = null; }).then(() => { if (!busy) draw(); });
