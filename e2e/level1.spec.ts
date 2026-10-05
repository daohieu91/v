import { expect, test, type Page } from '@playwright/test';
import { readdirSync, readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { phashHex, phashRgba } from '../src/phash';
import { deflateSync } from 'node:zlib';
import jpeg from 'jpeg-js';
import { findSealUrl } from '../src/qr';
import { payloadFromUrl } from '../src/payload';
import { checkSeal } from '../src/crypto';
import { BROWSER_RGBA } from '../test/helpers/browser-rgba';
const V = JSON.parse(readFileSync('test/vectors/verify-vectors.json', 'utf8'));
/** The seal URL printed in the fixtures' QR, read here with the same jsQR plan in node (independent of the page). */
const FIXTURE_URL = (() => { const j = jpeg.decode(readFileSync('e2e/fixtures/sealed.jpg'), { useTArray: true, formatAsRGBA: true });
  return findSealUrl({ data: Uint8ClampedArray.from(j.data), w: j.width, h: j.height })!; })();
/** A 1-bit grayscale PNG of w × h (all white): a tiny file with a huge bitmap. */
function bigPng(w: number, h: number): Buffer {
  const T = Array.from({ length: 256 }, (_, n) => { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; return c >>> 0; });
  const crc = (b: Buffer) => { let c = 0xffffffff; for (const x of b) c = T[(c ^ x) & 255] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; };
  const chunk = (t: string, d: Buffer) => { const n = Buffer.alloc(4); n.writeUInt32BE(d.length); const td = Buffer.concat([Buffer.from(t), d]);
    const c = Buffer.alloc(4); c.writeUInt32BE(crc(td)); return Buffer.concat([n, td, c]); };
  const ihdr = Buffer.alloc(13); ihdr.writeUInt32BE(w, 0); ihdr.writeUInt32BE(h, 4); ihdr[8] = 1; ihdr[9] = 0;
  const row = Buffer.alloc(1 + Math.ceil(w / 8), 0xff); row[0] = 0; const raw = Buffer.alloc(row.length * h); for (let y = 0; y < h; y++) row.copy(raw, y * row.length);
  return Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk('IHDR', ihdr), chunk('IDAT', deflateSync(raw)), chunk('IEND', Buffer.alloc(0))]);
}
const OK = V.payloads[0];                                                         // v1_case0: synthetic ocean point 30.12345, 140.54321 (P3)
// F-L11: record and abort every request that leaves localhost (blob:/data: are in-memory; WebKit routes its File decode through blob:), and fail the test in afterEach (a throw inside page.on is not reliable).
let foreign: string[] = [];
test.beforeEach(async ({ page }) => { foreign = [];
  await page.route('**/*', r => { const u = new URL(r.request().url()); const local = u.protocol === 'blob:' || u.protocol === 'data:' || u.hostname === 'localhost';
    if (!local) { foreign.push(u.protocol + '//' + u.hostname); return r.abort(); } return r.continue(); }); });
// A request the page's own CSP blocks never reaches the network (so never reaches page.route): count CSP violations too.
test.beforeEach(async ({ page }) => { await page.addInitScript(() => { (window as any).__csp = [];
  document.addEventListener('securitypolicyviolation', e => (window as any).__csp.push(e.violatedDirective + ' ' + e.blockedURI)); }); });
test.afterEach(async ({ page }) => {
  expect(foreign, 'third-party requests').toEqual([]);
  expect(await page.evaluate(() => (window as any).__csp ?? []).catch(() => []), 'CSP violations').toEqual([]);
});
const band = (page: Page) => page.locator('[data-verdict]');
const pick = async (page: Page, f: string) => { await page.setInputFiles('input[type=file]', `e2e/fixtures/${f}`);
  await expect(band(page)).not.toHaveAttribute('data-verdict', 'pending', { timeout: 30_000 }); };

test('QR link alone: yellow, signed time, full key id, OSM link only', async ({ page }) => {
  await page.goto('./#' + OK.base64url);
  await expect(band(page)).toHaveAttribute('data-verdict', 'yellow');
  await expect(page.locator('[data-field=time]')).toContainText('2025');
  await expect(page.locator('li[data-key=check_seal_ok]')).toContainText(OK.expectKeyId);   // all 8 bytes (P18 e)
  await expect(page.locator('li[data-key=device_unknown]')).toHaveText('Real device not confirmed yet — needs the original file');
  await expect(page.locator('li[data-key=proves_l1]'), 'P25: "unchanged since sealed" only on green').toHaveCount(0);
  await expect(page.locator('.explain li[data-key=proves_not_device]')).toBeVisible();
  await expect(page.locator('footer [data-privacy]')).toHaveText("The link you opened, with its coordinates, stays in this browser's history");
  const map = page.locator('a[data-map]');
  await expect(map).toHaveAttribute('href', /^https:\/\/www\.openstreetmap\.org\/\?mlat=30\.12345&mlon=140\.54321/);
  await expect(map).toHaveAttribute('target', '_blank'); await expect(map).toHaveAttribute('rel', 'noopener noreferrer');
  await expect(page.locator('iframe:not([hidden]), img[src*="tile"]')).toHaveCount(0);   // no embedded map
});
test('hex-edited link is red', async ({ page }) => {
  await page.goto('./#' + V.payloads.find((p: any) => p.expectKeyId === null).base64url);
  await expect(band(page)).toHaveAttribute('data-verdict', 'red');
  await expect(page.locator('li[data-key=proves_l1]')).toHaveCount(0);
});
test('garbage fragment is red, not a blank page', async ({ page }) => {
  await page.goto('./#not-a-seal');
  await expect(band(page)).toHaveAttribute('data-verdict', 'red');
});
test('sealed photo after chat-app compression is green', async ({ page }) => { await page.goto('./'); await pick(page, 'sealed_1600_q70.jpg');
  await expect(band(page)).toHaveAttribute('data-verdict', 'green');
  await expect(page.locator('li[data-key=check_seal_ok]')).toContainText(OK.expectKeyId);
  await expect(page.locator('li[data-key=check_image_match]')).toBeVisible();
  await expect(band(page)).toHaveText('Unchanged since it was sealed');
  await expect(page.locator('.explain li[data-key=proves_l1]')).toContainText(OK.expectKeyId); });
test('original-size sealed photo is green', async ({ page }) => { await page.goto('./'); await pick(page, 'sealed.jpg');
  await expect(band(page)).toHaveAttribute('data-verdict', 'green'); });
test('QR copied onto another photo is red', async ({ page }) => { await page.goto('./'); await pick(page, 'copied_qr.jpg');
  await expect(band(page)).toHaveAttribute('data-verdict', 'red'); await expect(page.locator('li[data-key=proves_l1]')).toHaveCount(0); });
test('a light filter over the photo is the yellow "maybe edited" band (distance 9–16), without "unchanged"', async ({ page }) => {
  await page.goto('./'); await pick(page, 'maybe_edited.jpg');
  await expect(band(page)).toHaveAttribute('data-verdict', 'yellow'); await expect(band(page)).toHaveText('May have been lightly edited');
  const d = Number(/difference (\d+)\/64/.exec((await page.locator('li[data-key=check_image_maybe]').textContent()) ?? '')?.[1]);
  expect(d).toBeGreaterThanOrEqual(9); expect(d).toBeLessThanOrEqual(16);
  await expect(page.locator('li[data-key=proves_l1]')).toHaveCount(0);
});
test('a 48 MP portrait-stored photo with EXIF rotation is decoded at the bounded size, upright, and is green', async ({ page }) => {
  await page.goto('./'); await pick(page, 'rotated_portrait_48mp.jpg');
  await expect(page.locator('#app')).toHaveAttribute('data-decoded', '4000x3000 resize');
  await expect(band(page)).toHaveAttribute('data-verdict', 'green');
});
test('a huge-pixel PNG (12000 × 9000, tiny file) is decoded only at the bounded size', async ({ page }) => {
  await page.goto('./');
  await page.setInputFiles('input[type=file]', { name: 'big.png', mimeType: 'image/png', buffer: bigPng(12000, 9000) });
  await expect(page.locator('p.message')).toHaveText('No CameraStamp code found in this photo', { timeout: 30_000 });
  await expect(page.locator('#app')).toHaveAttribute('data-decoded', '3000x2250 resize');
});
test('a file whose size cannot be read from its header is refused as unsupported, never decoded (large or small)', async ({ page }) => {
  await page.goto('./');
  await page.setInputFiles('input[type=file]', { name: 'x.heic', mimeType: 'image/heic', buffer: Buffer.alloc(7 * 1024 * 1024, 7) });
  await expect(page.locator('p.message')).toHaveText("This file type can't be checked here. Choose a JPEG, PNG, WebP or HEIC photo");
  // A small TIFF (browsers that decode TIFF would decode it plain before): refused the same way.
  const tiff = Buffer.concat([Buffer.from('II*\0'), Buffer.from([8, 0, 0, 0]), Buffer.alloc(64)]);
  await page.setInputFiles('input[type=file]', { name: 'x.tif', mimeType: 'image/tiff', buffer: tiff });
  await expect(page.locator('p.message')).toHaveText("This file type can't be checked here. Choose a JPEG, PNG, WebP or HEIC photo");
});
test('a photo whose seal differs from the opened link: notice, and the URL now names the photo\'s seal', async ({ page }) => {
  await page.goto('./#' + OK.base64url); await expect(band(page)).toHaveAttribute('data-verdict', 'yellow');
  await pick(page, 'sealed.jpg');
  await expect(page.locator('[data-notice=notice_other_seal]')).toHaveText(/carries a different seal than the link you opened/);
  expect(new URL(page.url()).hash.slice(1)).toBe(FIXTURE_URL.split('#')[1]);
});
test('opened without a link: checking a photo writes nothing into the URL or history', async ({ page }) => {
  await page.goto('./'); const before = await page.evaluate(() => history.length);
  await pick(page, 'sealed.jpg'); await expect(band(page)).toHaveAttribute('data-verdict', 'green');
  expect(new URL(page.url()).hash).toBe(''); expect(await page.evaluate(() => history.length)).toBe(before);
});
test('the heading of the explainer is neutral unless green', async ({ page }) => {
  await page.goto('./#' + OK.base64url); await expect(page.locator('.explain h2')).toHaveText('What this check shows');
  await page.goto('./'); await pick(page, 'sealed.jpg'); await expect(page.locator('.explain h2')).toHaveText('What this proves');
  await page.goto('./'); await pick(page, 'copied_qr.jpg'); await expect(page.locator('.explain h2')).toHaveText('What this check shows');
});
test('the same seal as the opened link: no notice', async ({ page }) => {
  await page.goto('./#' + FIXTURE_URL.split('#')[1]); await pick(page, 'sealed.jpg');
  await expect(band(page)).toHaveAttribute('data-verdict', 'green'); await expect(page.locator('[data-notice]')).toHaveCount(0);
});
for (const f of ['edited.jpg', 'cropped.jpg']) test(`${f} is not green`, async ({ page }) => { await page.goto('./'); await pick(page, f);
  await expect(band(page)).toHaveAttribute('data-verdict', /yellow|red/); });
test('QR cropped away: no code found', async ({ page }) => { await page.goto('./'); await pick(page, 'cropped_no_qr.jpg');
  await expect(band(page)).toHaveAttribute('data-verdict', 'none'); await expect(page.locator('p.message')).toHaveText('No CameraStamp code found in this photo'); });
test('language switch and footer', async ({ page }) => {
  await page.goto('./#' + OK.base64url);
  await page.selectOption('select[data-lang]', 'vi');
  await expect(page.locator('footer')).toContainText('Ảnh không được tải lên');
  await expect(page.locator('footer')).toContainText('Kiểm tra bằng CameraStamp — tải app');
  await expect(band(page)).toHaveText('Niêm phong hợp lệ — chưa so ảnh');
  await expect(page.locator('dt').first()).toHaveText('Thời điểm niêm phong');
  await expect(page.locator('footer a[data-play]')).toHaveAttribute('href', /referrer=utm_source%3Dverify/);
  await expect(page.locator('footer [data-attested]')).toContainText(/\d{4}-\d{2}-\d{2}/);
});
test('the browser language is picked', async ({ browser }) => {
  const ctx = await browser.newContext({ locale: 'vi-VN' }); const page = await ctx.newPage();
  await page.goto('./#' + OK.base64url); await expect(band(page)).toHaveText('Niêm phong hợp lệ — chưa so ảnh'); await ctx.close();
});
test('a browser without BigInt gets a readable "too old" message, and the core chunk is never fetched', async ({ page }) => {
  const fetched: string[] = []; page.on('request', r => fetched.push(r.url()));
  await page.addInitScript(() => { delete (window as any).BigInt; });
  await page.goto('./#' + OK.base64url);
  await expect(page.locator('#too-old')).toBeVisible(); await expect(page.locator('#too-old')).toContainText('too old');
  await expect(page.locator('#too-old')).toHaveCSS('opacity', '1');
  await expect(band(page)).toHaveCount(0);
  expect(fetched.filter(u => /\/assets\/app-/.test(u)), 'the core chunk must not load').toEqual([]);
});
test('if the core chunk fails (an engine that cannot parse it), the "too old" note shows, not a blank page', async ({ page }) => {
  await page.route(/\/assets\/app-[^/]*\.js$/, r => r.abort());
  await page.goto('./#' + OK.base64url);
  await expect(page.locator('#too-old')).toHaveCSS('opacity', '1'); await expect(band(page)).toHaveCount(0);
});
test('a modern browser never shows the "too old" note', async ({ page }) => {
  await page.goto('./#' + OK.base64url); await expect(band(page)).toHaveAttribute('data-verdict', 'yellow');
  await expect(page.locator('#too-old')).toHaveCount(0);
});
test('browser decode is pixel-exact on the vector PNGs, so the page fingerprint equals the golden vectors', async ({ page }) => {
  await page.goto('./');
  for (const fx of V.phashFixtures) {
    const b64 = readFileSync('test/vectors/' + fx.file).toString('base64');
    const out: { w: number; h: number; px: string } = await page.evaluate(async (b: string) => {
      const bin = atob(b); const u = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
      const bmp = await createImageBitmap(new Blob([u], { type: 'image/png' }));
      const c = document.createElement('canvas'); c.width = bmp.width; c.height = bmp.height; const g = c.getContext('2d', { willReadFrequently: true })!; g.drawImage(bmp, 0, 0);
      const d = g.getImageData(0, 0, c.width, c.height).data; let s = ''; for (let i = 0; i < d.length; i += 0x8000) s += String.fromCharCode(...d.subarray(i, i + 0x8000));
      return { w: c.width, h: c.height, px: btoa(s) };
    }, b64);
    const rgba = Buffer.from(out.px, 'base64');
    expect([out.w, out.h], fx.name).toEqual([fx.w, fx.h]);
    expect(createHash('sha256').update(rgba).digest('hex'), fx.name + ': browser pixels differ from the pinned RGBA').toBe(fx.rgbaSha256);
    expect(phashHex(phashRgba(rgba, out.w, out.h, fx.frame)), fx.name).toBe(fx.phash);
  }
});
test('the worker also accepts pixels decoded by the page (engines without OffscreenCanvas)', async ({ page }) => {
  const worker = readdirSync('dist/assets').find(f => /^analyze\.worker-.*\.js$/.test(f))!;
  await page.goto('./');
  const b64 = readFileSync('e2e/fixtures/sealed_1600_q70.jpg').toString('base64');
  const r = await page.evaluate(async ([b, w]) => {
    const bin = atob(b); const u = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
    const bmp = await createImageBitmap(new Blob([u], { type: 'image/jpeg' }));
    const c = document.createElement('canvas'); c.width = bmp.width; c.height = bmp.height; const g = c.getContext('2d')!; g.drawImage(bmp, 0, 0);
    const d = g.getImageData(0, 0, c.width, c.height).data;
    const wk = new Worker('assets/' + w);
    return await new Promise<any>(ok => { wk.onmessage = e => { wk.terminate(); ok(e.data); }; wk.postMessage({ data: d.buffer, w: c.width, h: c.height, fallback: null }, [d.buffer]); });
  }, [b64, worker] as const);
  expect(r.ok).toBe(true); expect(r.dec).toEqual({ w: 1600, h: 1200, via: 'page' });
  expect(r.r.url).toBe(FIXTURE_URL);                                        // the fixture's own signed URL, decoded independently in node
  expect(checkSeal(payloadFromUrl(r.r.url)!).keyIdHex).toBe(OK.expectKeyId);
  expect(r.r.hamming).toBeLessThanOrEqual(8);
});
test('a file over 40 MB is refused with a friendly message, before any decode', async ({ page }) => {
  await page.goto('./');
  await page.setInputFiles('input[type=file]', { name: 'big.jpg', mimeType: 'image/jpeg', buffer: Buffer.alloc(40 * 1024 * 1024 + 1, 0xff) });
  await expect(page.locator('p.message')).toHaveText('This file is larger than 40 MB. Choose a smaller copy of the photo');
});
test('an unreadable file shows "could not be read", not a blank page', async ({ page }) => {
  await page.goto('./');                       // a valid JPEG header (size known) with a broken body: the decoder itself fails
  const broken = Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xc0, 0, 17, 8, 0, 100, 0, 100, 3]), Buffer.alloc(9), Buffer.from([0xff, 0xda, 0, 2]), Buffer.from('garbage')]);
  await page.setInputFiles('input[type=file]', { name: 'x.jpg', mimeType: 'image/jpeg', buffer: broken });
  await expect(page.locator('p.message')).toHaveText('This file could not be read', { timeout: 15_000 });
});

// P26 + P28: a NO_FINGERPRINT seal (v1_case7: flag bit 7, phash 0) is never judged by a hash; the page measures the picture's texture.
const C7 = V.payloads.find((p: any) => p.name === 'v1_case7');
test('NO_FINGERPRINT seal, link only: yellow "not compared yet"', async ({ page }) => {
  await page.goto('./#' + C7.base64url);
  await expect(band(page)).toHaveAttribute('data-verdict', 'yellow'); await expect(band(page)).toHaveText('Seal is valid — photo not compared yet');
  await expect(page.locator('li[data-key=check_seal_ok]')).toContainText(C7.expectKeyId);
  await expect(page.locator('li[data-key=proves_l1]')).toHaveCount(0);
});
test('NO_FINGERPRINT seal on its dark photo: yellow "too dark or flat to compare", no distance, no "unchanged"', async ({ page }) => {
  await page.goto('./'); await pick(page, 'dark_sealed.jpg');
  await expect(band(page)).toHaveAttribute('data-verdict', 'yellow');
  await expect(band(page)).toHaveText('Details valid — this photo is too dark or flat to compare');
  await expect(page.locator('li[data-key=check_too_flat]')).toBeVisible();
  await expect(page.locator('li[data-key^=check_image], li[data-key=proves_l1]')).toHaveCount(0);
  await expect(page.locator('li[data-key=check_seal_ok]')).toContainText(C7.expectKeyId);
});
test('NO_FINGERPRINT seal moved onto a photo with detail: red', async ({ page }) => {
  await page.goto('./'); await pick(page, 'bright_sealed.jpg');
  await expect(band(page)).toHaveAttribute('data-verdict', 'red');
  await expect(band(page)).toHaveText("This photo isn't dark or flat — the seal belongs to a different photo");
  await expect(page.locator('li[data-key=check_flat_mismatch]')).toBeVisible();
  await expect(page.locator('li[data-key=proves_l1]')).toHaveCount(0);
});
test('NO_FINGERPRINT in Vietnamese', async ({ page }) => {
  await page.goto('./'); await page.selectOption('select[data-lang]', 'vi'); await pick(page, 'dark_sealed.jpg');
  await expect(band(page)).toHaveText('Thông tin hợp lệ — ảnh quá tối hoặc quá ít chi tiết để so');
});
// Task 10C follow-up: scripts/verify-file.ts decodes with libjpeg-turbo (sharp); test/decode-node.test.ts pins its RGBA to these digests.
// Here the same digests are measured in the real engines, so the pins are the browsers' pixels, not node's. WebKit decodes with
// ImageIO, which differs from both (measured), so it is checked for size only.
test('the JPEG decode verify-file uses is byte-identical to this browser (Chromium, Firefox)', async ({ page, browserName }) => {
  await page.goto('./');
  for (const [f, want] of Object.entries(BROWSER_RGBA)) {
    const b64 = readFileSync('e2e/fixtures/' + f).toString('base64');
    const out: { w: number; h: number; px: string } = await page.evaluate(async (b: string) => {
      const bin = atob(b); const u = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
      const bmp = await createImageBitmap(new Blob([u], { type: 'image/jpeg' }), { imageOrientation: 'from-image' });
      const c = document.createElement('canvas'); c.width = bmp.width; c.height = bmp.height; const g = c.getContext('2d', { willReadFrequently: true })!; g.drawImage(bmp, 0, 0);
      const d = g.getImageData(0, 0, c.width, c.height).data; let s = ''; for (let i = 0; i < d.length; i += 0x8000) s += String.fromCharCode(...d.subarray(i, i + 0x8000));
      return { w: c.width, h: c.height, px: btoa(s) };
    }, b64);
    expect([out.w, out.h], f).toEqual([1600, 1200]);
    if (browserName !== 'webkit') expect(createHash('sha256').update(Buffer.from(out.px, 'base64')).digest('hex'), f).toBe(want);
  }
});
