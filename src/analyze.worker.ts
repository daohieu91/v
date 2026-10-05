import { analyze } from './analyze';
import { fileToRgbaOffscreen } from './image';
// One job per worker; the page terminates it afterwards, so nothing outlives a pick.
// {file}: decode here (OffscreenCanvas) and analyze; replies {ok:false, need:'pixels'} where the engine cannot decode in a worker.
// {data,w,h}: pixels already decoded by the page.
type Job = { file?: Blob; data?: ArrayBuffer; w?: number; h?: number; fallback: string | null };
self.onmessage = async (e: MessageEvent<Job>) => {
  const m = e.data;
  try {
    const im = m.file ? await fileToRgbaOffscreen(m.file) : { data: new Uint8ClampedArray(m.data!), w: m.w!, h: m.h! };
    if (!im) { self.postMessage({ ok: false, need: 'pixels' }); return; }
    self.postMessage({ ok: true, r: analyze(im, m.fallback) });
  } catch { self.postMessage({ ok: false }); }
};
