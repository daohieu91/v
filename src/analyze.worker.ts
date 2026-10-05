import { analyze } from './analyze';
import { fileToRgbaOffscreen, TooLargeImage, UnsupportedImage, type Rgba } from './image';
import { validJob } from './messages';
// One job per worker; the page terminates it afterwards, so nothing outlives a pick.
// {file}: decode here (OffscreenCanvas) and analyze; replies {ok:false, need:'pixels'} where the engine cannot decode in a worker.
// {data,w,h}: pixels already decoded by the page (validated: exactly w·h·4 bytes).
self.onmessage = async (e: MessageEvent<unknown>) => {
  const m = validJob(e.data);
  if (!m) { self.postMessage({ ok: false }); return; }
  try {
    const im: Rgba | null = 'file' in m ? await fileToRgbaOffscreen(m.file) : { data: new Uint8ClampedArray(m.data), w: m.w, h: m.h, via: undefined };
    if (!im) { self.postMessage({ ok: false, need: 'pixels' }); return; }
    self.postMessage({ ok: true, r: analyze(im, m.fallback), dec: { w: im.w, h: im.h, via: im.via ?? 'page' } });
  } catch (err) { self.postMessage(err instanceof TooLargeImage ? { ok: false, err: 'oversize' } : err instanceof UnsupportedImage ? { ok: false, err: 'format' } : { ok: false }); }
};
