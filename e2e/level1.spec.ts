import { expect, test, type Page } from '@playwright/test';
import { readdirSync, readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { phashHex, phashRgba } from '../src/phash';
const V = JSON.parse(readFileSync('test/vectors/verify-vectors.json', 'utf8'));
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
  await expect(page.locator('.explain li[data-key=proves_l1]')).toContainText(OK.expectKeyId);
  await expect(page.locator('.explain li[data-key=proves_not_device]')).toBeVisible();
  const map = page.locator('a[data-map]');
  await expect(map).toHaveAttribute('href', /^https:\/\/www\.openstreetmap\.org\/\?mlat=30\.12345&mlon=140\.54321/);
  await expect(map).toHaveAttribute('target', '_blank'); await expect(map).toHaveAttribute('rel', 'noopener noreferrer');
  await expect(page.locator('iframe:not([hidden]), img[src*="tile"]')).toHaveCount(0);   // no embedded map
});
test('hex-edited link is red', async ({ page }) => {
  await page.goto('./#' + V.payloads.find((p: any) => p.expectKeyId === null).base64url);
  await expect(band(page)).toHaveAttribute('data-verdict', 'red');
});
test('garbage fragment is red, not a blank page', async ({ page }) => {
  await page.goto('./#not-a-seal');
  await expect(band(page)).toHaveAttribute('data-verdict', 'red');
});
test('sealed photo after chat-app compression is green', async ({ page }) => { await page.goto('./'); await pick(page, 'sealed_1600_q70.jpg');
  await expect(band(page)).toHaveAttribute('data-verdict', 'green');
  await expect(page.locator('li[data-key=check_seal_ok]')).toContainText(OK.expectKeyId);
  await expect(page.locator('li[data-key=check_image_match]')).toBeVisible(); });
test('original-size sealed photo is green', async ({ page }) => { await page.goto('./'); await pick(page, 'sealed.jpg');
  await expect(band(page)).toHaveAttribute('data-verdict', 'green'); });
test('QR copied onto another photo is red', async ({ page }) => { await page.goto('./'); await pick(page, 'copied_qr.jpg');
  await expect(band(page)).toHaveAttribute('data-verdict', 'red'); });
for (const f of ['edited.jpg', 'cropped.jpg']) test(`${f} is not green`, async ({ page }) => { await page.goto('./'); await pick(page, f);
  await expect(band(page)).toHaveAttribute('data-verdict', /yellow|red/); });
test('QR cropped away: no code found', async ({ page }) => { await page.goto('./'); await pick(page, 'cropped_no_qr.jpg');
  await expect(band(page)).toHaveAttribute('data-verdict', 'none'); await expect(page.locator('p.message')).toHaveText('No CameraStamp code found in this photo'); });
test('language switch and footer', async ({ page }) => {
  await page.goto('./#' + OK.base64url);
  await page.selectOption('select[data-lang]', 'vi');
  await expect(page.locator('footer')).toContainText('Ảnh không được tải lên');
  await expect(band(page)).toHaveText('Thông tin đúng — chưa so được ảnh');
  await expect(page.locator('footer a[data-play]')).toHaveAttribute('href', /referrer=utm_source%3Dverify/);
  await expect(page.locator('footer [data-attested]')).toContainText(/\d{4}-\d{2}-\d{2}/);
});
test('the browser language is picked', async ({ browser }) => {
  const ctx = await browser.newContext({ locale: 'vi-VN' }); const page = await ctx.newPage();
  await page.goto('./#' + OK.base64url); await expect(band(page)).toHaveText('Thông tin đúng — chưa so được ảnh'); await ctx.close();
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
  expect(r.ok).toBe(true); expect(r.r.url).toBe(OK.url.slice(0, OK.url.indexOf('#') + 1) + r.r.url.split('#')[1]);
  expect(r.r.hamming).toBeLessThanOrEqual(8);
});
test('a file over 40 MB is refused with a friendly message, before any decode', async ({ page }) => {
  await page.goto('./');
  await page.setInputFiles('input[type=file]', { name: 'big.jpg', mimeType: 'image/jpeg', buffer: Buffer.alloc(40 * 1024 * 1024 + 1, 0xff) });
  await expect(page.locator('p.message')).toHaveText('This file is larger than 40 MB. Choose a smaller copy of the photo');
});
test('an unreadable file shows "could not be read", not a blank page', async ({ page }) => {
  await page.goto('./');
  await page.setInputFiles('input[type=file]', { name: 'x.jpg', mimeType: 'image/jpeg', buffer: Buffer.from('not a jpeg at all') });
  await expect(page.locator('p.message')).toHaveText('This file could not be read', { timeout: 15_000 });
});
