import { guardFraming } from '../framing';
guardFraming(window);
/**
 * The level-2 iframe (l2.html, the only page whose CSP allows wasm). The reader (c2pa-web + its 9 MB wasm) is imported on the first
 * request only, i.e. when the user picks an original file. Only our own parent is answered; a malformed request gets null.
 */
let mod: Promise<typeof import('./level2')> | null = null;
window.addEventListener('message', async (e: MessageEvent) => {
  if (e.origin !== location.origin || e.source !== window.parent) return;
  const port = e.ports[0]; if (!port) return;
  const d = e.data as { file?: unknown; qrKeyIdHex?: unknown } | null;
  const qr = d?.qrKeyIdHex ?? null;
  if (!(d?.file instanceof Blob) || !(qr === null || (typeof qr === 'string' && /^[0-9a-f]{16}$/.test(qr)))) { port.postMessage(null); return; }
  try { const { level2 } = await (mod ??= import('./level2')); port.postMessage(await level2(d.file as File, qr)); }
  catch { mod = null; port.postMessage(null); }
});
