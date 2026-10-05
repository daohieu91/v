import { validL2Reply } from './messages';
import type { SealPayload } from './payload';
import type { L2Summary } from './verdict';
export interface L2Reply { summary: L2Summary; payload: SealPayload | null }
let frame: Promise<HTMLIFrameElement> | null = null;
function load(): Promise<HTMLIFrameElement> {
  return frame ??= new Promise((ok, bad) => { const f = document.createElement('iframe'); f.hidden = true; f.src = new URL('l2.html', location.href).pathname;
    f.onload = () => ok(f); f.onerror = () => { frame = null; bad(new Error('l2')); }; document.body.append(f); });
}
/** Level 2 runs in a same-origin iframe whose own CSP alone allows wasm (spec §7.3); the File is structured-cloned, never uploaded. */
export async function runLevel2(file: File, qrKeyIdHex: string | null): Promise<L2Reply | null> {
  try {
    const f = await load(); const ch = new MessageChannel();
    const reply = new Promise<L2Reply | null>(res => { const to = setTimeout(() => res(null), 60_000);
      ch.port1.onmessage = e => { clearTimeout(to); res(validL2Reply(e.data)); }; });   // malformed or null → no level 2
    f.contentWindow!.postMessage({ file, qrKeyIdHex }, location.origin, [ch.port2]);
    return await reply;
  } catch { return null; }
}
