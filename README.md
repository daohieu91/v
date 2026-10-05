# CameraStamp photo verifier

Public web verifier for photos sealed by the CameraStamp app: https://daohieu91.github.io/v/

## Permanent URL

**This repository must never be renamed, deleted or made private: every printed CameraStamp QR points here.**
The URL `https://daohieu91.github.io/v/` is permanent.

## Privacy

- Verification runs entirely in your browser. **Nothing is uploaded**: the photo and the QR data never leave your device.
- No server, no analytics, no cookies, no third-party scripts. A strict Content-Security-Policy `<meta>` in each HTML page enforces this (`connect-src 'self'`), and `test/csp.test.ts` pins it.
- The seal data in the URL is in the fragment (`#...`), which browsers never send to GitHub. It does stay in the browser's own history (with the coordinates), and the page says so.
- Google's Android attestation roots and revocation list are copied daily into `public/attestation/` by a GitHub Action, so the page itself never contacts Google. The page shows the date of the last copy (`meta.json`). The action validates the download (roots parse as X.509, `entries` is an object) and fails, keeping the old copy, if not. Its daily commit also stops GitHub disabling the schedule after 60 days of inactivity.

## Framing (clickjacking)

GitHub Pages cannot send response headers, and a `<meta>` Content-Security-Policy ignores `frame-ancestors`, so the page cannot forbid framing by CSP.
Instead `src/framing.ts` (an external script, compatible with the CSP) hides the page and navigates the top window to it **only when the top window is on another origin**. Same-origin framing, such as `index.html` embedding `l2.html`, is left alone.
This is a best-effort defence, not a guarantee.

## Level 1 (this page)

- Open `https://daohieu91.github.io/v/#<seal>` (the phone camera opens it from the QR): the seal is checked at once and the band is
  yellow, "seal is valid — photo not compared yet". Choose the received photo to compare its content: green, yellow or red.
- The verdict comes only from `checkSeal` (the key tag check). A level-1 green means "this photo and these details are unchanged since
  key <8-byte id> sealed them" (shown on green only). It does not prove which app or phone made the seal: that needs the original file (level 2, `l2.html`).
- Decode, QR search (full image, ~1600 and ~1000 px wide, bottom-right corner, bottom band) and the fingerprint run in a Web Worker.
  Files over 40 MB are refused. The size is read from the header (JPEG incl. EXIF orientation, PNG, WebP, GIF, BMP, HEIF/AVIF): above 4096 px
  the browser decodes straight at the bounded size, never at full size; a large file of unknown size is refused.
- 10 languages (`src/i18n/*.json`), the same terms as the app (`src/glossary.json`); `test/i18n.test.ts` enforces completeness.
- The entry chunk has no BigInt and checks the browser first; an old browser gets a "too old" note instead of a blank page.
- Budget: `npm run size` (< 100 KB gzipped for what one visitor downloads, and no level-2 code in level 1).

## Level 2 (the original file, `l2.html`)

- Runs in a same-origin iframe, the only page whose CSP allows `wasm-unsafe-eval`. The iframe and c2pa-web (pinned 0.15.3, its 9 MB wasm
  under SRI) load only when a picked file carries C2PA data. Videos up to 100 MB (checked by level 2 only), photos up to 40 MB.
- c2pa-web validates the file (any failure but `signingCredential.untrusted` is red; a `timeStamp.*` failure only drops the TSA line).
  `src/l2/jumbf.ts` reads the COSE signer and RFC 3161 token by slices; `src/l2/x509.ts` + `attestation.ts` check the Android attestation
  chain (links, CA issuers, KeyDescription in the leaf only, Google root by key, `public/attestation/status.json`); `device.ts` makes one
  line per condition. "Sealed by a key in the secure hardware of a real device" needs all of them, a REGISTERED release digest
  (`SIGNING_DIGESTS` in `src/config.ts`: the debug key is `dev`, any other digest is "not yet registered") and attested key = C2PA signer
  key = seal key (= the QR's key when there is one).
- Fixtures are synthetic: `npx tsx scripts/make-l2-fixtures.ts` (c2patool on PATH; the public test key; FAKE roots that e2e injects).
- WebKit + Playwright: any `page.route` breaks c2pa-web's blob: worker, so `e2e/level2.spec.ts` routes nothing on WebKit and skips the two
  tests that need an injected root or revocation list there.

## Develop and test

```
npm ci
npm test            # Vitest (includes the CSP privacy test)
npm run build       # type-check + production build into dist/
npm run size        # level-1 budget: < 100 KB gzipped, no level-2 code (run after build)
npx playwright install chromium webkit firefox
npm run e2e         # Playwright (Chromium, WebKit, Firefox, mobile Chrome), against `vite preview`
npm run verify-file -- photo.jpg   # the level-1 pipeline on one photo, from a shell
```

`verify-file` decodes with **sharp, pinned at exactly 0.35.5** (libjpeg-turbo, byte-identical to Chromium and Firefox; see
`scripts/decode-node.ts`). A bump of sharp (or its bundled libvips/mozjpeg) can change pixels: re-measure the browser pins in
`test/helpers/browser-rgba.ts` in real browsers (`npm run e2e`, the "byte-identical to this browser" test) before accepting it, and never
update the pins from node alone.

## Golden vectors

`test/vectors/` (JSON, `.sha256`, `fixtures/*.png`) is a byte-identical copy of the CameraStamp app repo's `docs/verify/`. Never edit or re-record it here: copy it with the procedure in the app's `docs/verify/README.md` and check it with the app's `scripts/check-vectors-sync.sh`.

## Deploy

Pushing to `main` runs `.github/workflows/deploy.yml` (tests, build, GitHub Pages via Actions).

## Licence

No licence has been chosen yet; the owner must choose one (until then, all rights are reserved by default).
