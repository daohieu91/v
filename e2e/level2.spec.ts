import { expect, test, type Page } from '@playwright/test';
import { readFileSync } from 'node:fs';
// Level 2 (Task 22) on SYNTHETIC originals (scripts/make-l2-fixtures.ts): c2patool-signed by the vectors' public TEST KEY with the app's
// signer certificate for it, carrying synthetic attestation chains. Their hardware chain ends at a FAKE root, which only these tests add
// to roots.json (withFakeRoot). No real M20 original exists yet (Task 23). The picture is sealed.jpg (synthetic ocean coordinates, P3).
const REAL_ROOTS = JSON.parse(readFileSync('public/attestation/roots.json', 'utf8')) as string[];
const FAKE_ROOTS = JSON.parse(readFileSync('e2e/fixtures/fake_attestation_roots.json', 'utf8')) as string[];
let foreign: string[] = []; let requested: string[] = [];
// WebKit + Playwright request interception breaks c2pa-web: it starts its worker from a blob: URL and revokes it at once, and ANY
// page.route makes WebKit's blob: load fail ("WebKitBlobResource error 1"); without a route the page works in WebKit (measured).
// So on WebKit nothing is routed: third-party requests are only observed (the CSP blocks them anyway), and the tests that need an
// injected root or revocation list run on the other engines.
const ROUTABLE = (b: string) => b !== 'webkit';
test.beforeEach(async ({ page, browserName }) => { foreign = []; requested = [];
  const seen = (url: string) => { const u = new URL(url); if (u.protocol === 'blob:' || u.protocol === 'data:') return true; requested.push(u.pathname);
    if (u.hostname !== 'localhost') { foreign.push(u.protocol + '//' + u.hostname); return false; } return true; };
  if (ROUTABLE(browserName)) await page.route('**/*', r => (seen(r.request().url()) ? r.fallback() : r.abort()));
  else page.on('request', r => { seen(r.url()); });
  await page.addInitScript(() => { (window as any).__csp = []; document.addEventListener('securitypolicyviolation', e => (window as any).__csp.push(e.violatedDirective + ' ' + e.blockedURI)); });
});
test.afterEach(async ({ page }) => {
  expect(foreign, 'third-party requests').toEqual([]);
  const csp = [page, ...page.frames().slice(1)].map(f => (f as Page).evaluate?.(() => (window as any).__csp ?? []).catch(() => []) ?? Promise.resolve([]));
  expect((await Promise.all(csp)).flat(), 'CSP violations').toEqual([]);
});
const withFakeRoot = (page: Page) => page.context().browser()?.browserType().name() === 'webkit' ? Promise.resolve() : page.route('**/attestation/roots.json', r => r.fulfill({ json: [...REAL_ROOTS, ...FAKE_ROOTS] }));
const band = (page: Page) => page.locator('[data-verdict]');
const line = (page: Page, key: string) => page.locator(`li[data-key=${key}]`);
async function pick(page: Page, f: string | { name: string; mimeType: string; buffer: Buffer }) {
  await page.setInputFiles('input[type=file]', typeof f === 'string' ? `e2e/fixtures/${f}` : f);
  await expect(band(page)).not.toHaveAttribute('data-verdict', 'pending', { timeout: 60_000 });
}
test.describe.configure({ timeout: 90_000 });

test('certified hardware original (debug-signed, P36: not registered): green, every device line, the time-stamp; never "real device"', async ({ page, browserName }) => {
  test.skip(!ROUTABLE(browserName), 'needs the injected fake root (no routing on WebKit)');
  await withFakeRoot(page); await page.goto('./'); await pick(page, 'original_hw.jpg');
  await expect(band(page)).toHaveAttribute('data-verdict', 'green');
  for (const k of ['l2_signature_ok', 'l2_chain_ok', 'l2_level_hw', 'l2_boot_ok', 'l2_locked_ok']) await expect(line(page, k), k).toHaveAttribute('data-status', 'pass');
  await expect(line(page, 'l2_app_unregistered')).toHaveText('App signature not yet registered on this page — not confirmed as the CameraStamp app');
  await expect(line(page, 'l2_app_dev')).toHaveCount(0);
  await expect(line(page, 'l2_qr_same_key')).toHaveText('This QR was sealed by the same key as this original file');
  await expect(line(page, 'l2_tsa')).toContainText(/Existed no later than 20\d\d-\d\d-\d\d \d\d:\d\d:\d\d UTC — confirmed by DigiCert/);
  await expect(line(page, 'l2_untrusted_note')).toBeVisible();
  await expect(line(page, 'l2_real_device')).toHaveCount(0); await expect(line(page, 'l2_qr_link')).toHaveCount(0);
  await expect(line(page, 'proves_not_device')).toHaveCount(0); await expect(line(page, 'proves_screen')).toBeVisible();
});
test('the same original against Google\'s real roots (the live page today): YELLOW "key not certified — lower trust", never green (P35)', async ({ page }) => {
  await page.goto('./'); await pick(page, 'original_hw.jpg');
  await expect(band(page)).toHaveAttribute('data-verdict', 'yellow'); await expect(band(page)).toHaveText('Key not certified — lower trust');
  await expect(line(page, 'proves_l1')).toHaveCount(0);
  await expect(line(page, 'l2_signature_ok')).toHaveText('The original file is signed and unchanged');
  await expect(line(page, 'l2_chain_bad')).toHaveText("Key not certified by Google");
  await expect(line(page, 'l2_real_device')).toHaveCount(0);
});
test('tampered original (one byte of the picture changed): never green, "the file was changed"', async ({ page }) => {
  const b = readFileSync('e2e/fixtures/original_hw.jpg'); const sos = b.lastIndexOf(Buffer.from([0xff, 0xda])); b[sos + 4000] ^= 0x01;
  await withFakeRoot(page); await page.goto('./'); await pick(page, { name: 'tampered.jpg', mimeType: 'image/jpeg', buffer: b });
  await expect(band(page)).toHaveAttribute('data-verdict', /red|yellow/);    // M13: yellow only if the damaged picture still matches its own QR
  await expect(line(page, 'l2_invalid')).toHaveText("The original file's signature is not valid: the file was changed");
  await expect(line(page, 'l2_chain_ok')).toHaveCount(0);
});
test('M13: an original re-saved with its C2PA data kept (bytes changed, picture identical) is yellow "re-saved or edited", not red', async ({ page }) => {
  const b = readFileSync('e2e/fixtures/original_hw.jpg'); const com = Buffer.from([0xff, 0xfe, 0x00, 0x0a, ...Buffer.from('resaved!')]);
  const buf = Buffer.concat([b.subarray(0, 2), com, b.subarray(2)]);                 // a JPEG comment after SOI: the data hash breaks, no pixel moves
  await withFakeRoot(page); await page.goto('./'); await pick(page, { name: 'resaved.jpg', mimeType: 'image/jpeg', buffer: buf });
  await expect(band(page)).toHaveAttribute('data-verdict', 'yellow');
  await expect(band(page)).toHaveText('Re-saved or edited after sealing — the picture still matches its seal');
  await expect(line(page, 'l2_invalid')).toBeVisible(); await expect(line(page, 'proves_l1')).toHaveCount(0);
});
test('I2: a time-stamp from a self-made TSA carrying DigiCert\'s names gets no "confirmed by" line', async ({ page, browserName }) => {
  test.skip(!ROUTABLE(browserName), 'needs the injected fake root (no routing on WebKit)');
  await withFakeRoot(page); await page.goto('./'); await pick(page, 'original_tsa_forged.jpg');
  await expect(line(page, 'l2_signature_ok')).toBeVisible();
  await expect(line(page, 'l2_no_tsa')).toHaveText('No independent timestamp'); await expect(line(page, 'l2_tsa')).toHaveCount(0);
  await expect(page.locator('#app')).not.toContainText('DigiCert');
});
// P45 (scripts/make-tsa-fixtures.ts): real DigiCert tokens, but not exactly one over THIS signature. c2pa-web 0.15.3 reports neither
// timeStamp.validated nor a timeStamp failure for these (measured), so the page's own count + imprint check (tsa.ts) is the second line;
// it is mutation-proved in test/l2 with the reader stubbed to "validated".
for (const [f, what] of [['original_tsa_two.jpg', 'two tokens, the first a real DigiCert token over other data'],
  ['original_tsa_imprint.jpg', 'one real DigiCert token over other data (wrong imprint)']] as const)
  test(`P45: ${what} → no "confirmed by" line; the file itself is still read`, async ({ page }) => {
    await page.goto('./'); await pick(page, f);
    await expect(line(page, 'l2_signature_ok')).toBeVisible(); await expect(line(page, 'l2_qr_same_key')).toBeVisible();
    await expect(line(page, 'l2_no_tsa')).toHaveText('No independent timestamp'); await expect(line(page, 'l2_tsa')).toHaveCount(0);
    await expect(page.locator('#app')).not.toContainText('DigiCert');
  });
test('software attestation (API 24–27 / emulator shape): yellow "software key — lower trust", app and boot unknown', async ({ page }) => {
  await withFakeRoot(page); await page.goto('./'); await pick(page, 'original_sw.jpg');
  await expect(band(page)).toHaveAttribute('data-verdict', 'yellow');
  await expect(band(page)).toContainText('Software key — lower trust');
  await expect(line(page, 'l2_level_sw')).toContainText('lower trust');
  for (const k of ['l2_chain_bad', 'l2_app_unknown', 'l2_boot_unknown']) await expect(line(page, k), k).toBeVisible();
  await expect(line(page, 'l2_real_device')).toHaveCount(0);
});
test('our package with a signing digest the page does not know: "app signature not yet registered", never "real device"', async ({ page, browserName }) => {
  await withFakeRoot(page); await page.goto('./'); await pick(page, 'original_unreg.jpg');
  await expect(line(page, 'l2_app_unregistered')).toHaveText('App signature not yet registered on this page — not confirmed as the CameraStamp app');
  await expect(line(page, 'l2_app_unregistered')).toHaveAttribute('data-status', 'warn');
  if (ROUTABLE(browserName)) await expect(line(page, 'l2_chain_ok')).toBeVisible(); await expect(line(page, 'l2_level_hw')).toBeVisible();
  await expect(line(page, 'l2_real_device')).toHaveCount(0); await expect(line(page, 'l2_qr_link')).toHaveCount(0);
});
test('a certified chain for ANOTHER key on a file signed by the seal key: red, "signed by a different key"', async ({ page }) => {
  await withFakeRoot(page); await page.goto('./'); await pick(page, 'original_forged.jpg');
  await expect(band(page)).toHaveAttribute('data-verdict', 'red'); await expect(band(page)).toHaveText("The original file's seal can't be trusted");
  await expect(line(page, 'l2_binding_bad')).toBeVisible(); await expect(line(page, 'proves_l1')).toHaveCount(0);
});
test('a certificate in Google\'s revocation list (the daily status.json copy): red, "revoked"', async ({ page, browserName }) => {
  test.skip(!ROUTABLE(browserName), 'needs an injected revocation list (no routing on WebKit)');
  await withFakeRoot(page);
  await page.route('**/attestation/status.json', async r => { const j = await (await r.fetch()).json(); j.entries.fa4e0002 = { status: 'REVOKED', reason: 'KEY_COMPROMISE' }; await r.fulfill({ json: j }); });
  await page.goto('./'); await pick(page, 'original_hw.jpg');
  await expect(band(page)).toHaveAttribute('data-verdict', 'red'); await expect(line(page, 'l2_revoked')).toBeVisible();
  await expect(line(page, 'l2_chain_ok')).toHaveCount(0);
});
test('video original: the fields come from level 2 and the file binding makes it green (no picture to compare)', async ({ page, browserName }) => {
  await withFakeRoot(page); await page.goto('./'); await pick(page, 'original_video.mp4');
  await expect(band(page)).toHaveAttribute('data-verdict', ROUTABLE(browserName) ? 'green' : 'yellow');   // WebKit: no injected root → not certified
  await expect(line(page, 'check_content_c2pa')).toBeVisible(); await expect(line(page, 'l2_video')).toHaveText('Video: duration 3 s, data from its first second');
  await expect(page.locator('[data-field=time]')).toBeVisible();
});
test('c2pa-web is lazy: nothing of level 2 loads for the page or a plain photo; the wasm loads once an original is picked', async ({ page }) => {
  await page.goto('./'); await pick(page, 'sealed.jpg');
  expect(requested.filter(p => /l2\.html|level2|\.wasm/.test(p)), 'no level 2 for a plain photo').toEqual([]);
  await pick(page, 'original_hw.jpg');
  expect(requested.some(p => p.endsWith('l2.html'))).toBe(true); expect(requested.some(p => p.endsWith('.wasm'))).toBe(true);
});
test('a chat-compressed copy has no level 2 and still says so', async ({ page }) => {
  await page.goto('./'); await pick(page, 'sealed_1600_q70.jpg');
  await expect(line(page, 'device_unknown')).toHaveText('Real device not confirmed yet — needs the original file');
});
test('a browser that cannot run the reader (wasm blocked) says so, and level 1 still answers', async ({ page, browserName }) => {
  test.skip(!ROUTABLE(browserName), 'needs routing');
  await page.route('**/*.wasm', r => r.abort()); await page.goto('./'); await pick(page, 'original_hw.jpg');
  await expect(line(page, 'l2_error')).toHaveText("Couldn't read this file here — try another browser or a computer");
  await expect(line(page, 'check_image_match')).toBeVisible(); await expect(line(page, 'l2_signature_ok')).toHaveCount(0);
});
test('P30: a NO_FINGERPRINT seal on its own original file is green from the file binding, with the level-2 wording', async ({ page, browserName }) => {
  test.skip(!ROUTABLE(browserName), 'needs the injected fake root (no routing on WebKit)');
  await withFakeRoot(page); await page.goto('./'); await pick(page, 'original_dark.jpg');
  await expect(band(page)).toHaveAttribute('data-verdict', 'green');
  await expect(line(page, 'check_content_c2pa')).toHaveText("The original file's content is unchanged"); await expect(line(page, 'check_too_flat')).toHaveCount(0);
});
test('P30 needs THIS seal in the file: the same key\'s other seal in the file leaves the dark photo yellow', async ({ page }) => {
  await withFakeRoot(page); await page.goto('./'); await pick(page, 'original_dark_other.jpg');
  await expect(band(page)).toHaveAttribute('data-verdict', 'yellow'); await expect(line(page, 'check_too_flat')).toBeVisible();
  await expect(line(page, 'check_content_c2pa')).toHaveCount(0);
});
