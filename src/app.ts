import { parseCheckedAt } from './attestation-date';
import { checkSeal } from './crypto';
import { fileToRgba, MAX_FILE_BYTES, sniffC2pa, TooLargeImage, UnsupportedImage, type Rgba } from './image';
import { validReply, type Reply } from './messages';
import { loadDict, pickLocale } from './i18n';
import { runLevel2 } from './l2client';
import { URL_PREFIX } from './config';
import { decodeFragment, payloadFromUrl, sealIdentity, type SealPayload } from './payload';
import type { Analysis } from './analyze';
import { render } from './ui';
import { verdict, type L2Summary, type Verdict } from './verdict';

const root = document.getElementById('app')!;
let locale = pickLocale(navigator.languages?.length ? navigator.languages : [navigator.language ?? 'en']);
let dict = await loadDict(locale);
let state: { verdict: Verdict | 'pending' | null; payload: SealPayload | null; message: string | null; notice: string | null } = { verdict: null, payload: null, message: null, notice: null };
let attested: string | null | undefined;
let busy = false;
const draw = () => render(root, { dict, locale, ...state, attested, onPick: pick,
  onLocale: async l => { try { const d = await loadDict(l); locale = l; dict = d; } catch { /* keep the current language */ } draw(); } });

const fragment = () => location.hash.slice(1);
function fromHash(): SealPayload | null { try { return decodeFragment(fragment()); } catch { return null; } }
/** The verdict comes from checkSeal alone (never from a recovered key); `payload` null or a failed seal is red. */
function show(payload: SealPayload | null, h: number | null, l2: L2Summary | null, notice: string | null = null) {
  state = { verdict: verdict({ payload, seal: payload ? checkSeal(payload) : null, hamming: h, level2: l2 }), payload, message: null, notice }; draw(); }
const fail = (message: string) => { state = { verdict: null, payload: null, message, notice: null }; draw(); };
class Refused extends Error { constructor(readonly key: string) { super(key); } }

function job(msg: object, transfer: Transferable[]): Promise<Reply> {
  return new Promise((ok, bad) => {
    const w = new Worker(new URL('./analyze.worker.ts', import.meta.url));
    const done = () => { clearTimeout(to); w.terminate(); };
    const to = setTimeout(() => { done(); bad(new Error('timeout')); }, 90_000);
    w.onmessage = (e: MessageEvent<unknown>) => { done(); const r = validReply(e.data); r ? ok(r) : bad(new Error('reply')); };
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
  if (!r.ok && r.need === 'pixels') {
    let im: Rgba; try { im = await fileToRgba(f); } catch (e) { throw e instanceof TooLargeImage ? new Refused('error_too_large_image') : e instanceof UnsupportedImage ? new Refused('error_unsupported') : e; }
    r = await job({ data: im.data.buffer, w: im.w, h: im.h, fallback }, [im.data.buffer]);
    if (r.ok) r.dec.via = im.via ?? 'plain';
  }
  if (!r.ok) throw r.err === 'oversize' ? new Refused('error_too_large_image') : r.err === 'format' ? new Refused('error_unsupported') : new Error('analyze');
  root.dataset.decoded = `${r.dec.w}x${r.dec.h} ${r.dec.via}`;              // test hook: the bounded size actually decoded (no image data)
  return r.r;
}

async function pick(f: File) {
  if (busy) return;
  if (f.size > MAX_FILE_BYTES) return fail('error_too_big');
  busy = true; state = { ...state, verdict: 'pending', message: null }; draw();
  try {
    const c2pa = await sniffC2pa(f);
    let payload: SealPayload | null = null; let h: number | null = null; let code = false; let r0url: string | null = null;
    if (!f.type.startsWith('video/')) {
      const r = await analyzeOffThread(f, fromHash() ? fragment() : null);
      r0url = r.url;
      if (r.url) { code = true; payload = payloadFromUrl(r.url); h = payload ? r.hamming : null; }
    }
    // The photo's own seal wins over the link's; say so when they differ (identity = header + r, P18 a), and make the URL match.
    const linked = fromHash(); let notice: string | null = null;
    if (payload && linked && sealIdentity(payload) !== sealIdentity(linked)) notice = 'notice_other_seal';
    // Only when the page was opened from a link: a photo checked on the bare page leaves nothing in the URL or the history.
    if (payload && r0url && fragment() && r0url !== URL_PREFIX + fragment()) history.replaceState(null, '', '#' + r0url.slice(URL_PREFIX.length));
    const seal = payload ? checkSeal(payload) : null;
    const l2 = c2pa ? await runLevel2(f, seal?.ok ? seal.keyIdHex : null) : null;
    if (!payload && l2?.payload) payload = l2.payload;                              // a video original: level 2 carries the fields
    if (!payload && !code && !l2) return fail('no_code');
    show(payload, h, l2?.summary ?? null, notice);
  } catch (e) { fail(e instanceof Refused ? e.key : 'error_read'); }
  finally { busy = false; }
}

window.addEventListener('hashchange', () => { if (fragment()) show(fromHash(), null, null); });
if (fragment()) show(fromHash(), null, null); else draw();
fetch(import.meta.env.BASE_URL + 'attestation/meta.json', { cache: 'no-cache' }).then(r => r.json())
  .then(j => { attested = parseCheckedAt(j); }, () => { attested = null; }).then(() => { if (!busy) draw(); });
