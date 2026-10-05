# CameraStamp photo verifier

Public web verifier for photos sealed by the CameraStamp app: https://daohieu91.github.io/v/

## Permanent URL

**This repository must never be renamed, deleted or made private: every printed CameraStamp QR points here.**
The URL `https://daohieu91.github.io/v/` is permanent.

## Privacy

- Verification runs entirely in your browser. **Nothing is uploaded**: the photo and the QR data never leave your device.
- No server, no analytics, no cookies, no third-party scripts. A strict Content-Security-Policy `<meta>` in each HTML page enforces this (`connect-src 'self'`), and `test/csp.test.ts` pins it.
- The seal data in the URL is in the fragment (`#...`), which browsers never send to GitHub.
- Google's Android attestation roots and revocation list are copied daily into `public/attestation/` by a GitHub Action, so the page itself never contacts Google. The page shows the date of the last copy (`meta.json`). The action validates the download (roots parse as X.509, `entries` is an object) and fails, keeping the old copy, if not. Its daily commit also stops GitHub disabling the schedule after 60 days of inactivity.

## Framing (clickjacking)

GitHub Pages cannot send response headers, and a `<meta>` Content-Security-Policy ignores `frame-ancestors`, so the page cannot forbid framing by CSP.
Instead `src/framing.ts` (an external script, compatible with the CSP) hides the page and navigates the top window to it **only when the top window is on another origin**. Same-origin framing, such as `index.html` embedding `l2.html`, is left alone.
This is a best-effort defence, not a guarantee.

## Develop and test

```
npm ci
npm test            # Vitest (includes the CSP privacy test)
npm run build       # type-check + production build into dist/
npm run size        # level-1 bundle size budget (run after build)
npx playwright install chromium webkit firefox
npm run e2e         # Playwright, against `vite preview`
```

## Golden vectors

`test/vectors/` (JSON, `.sha256`, `fixtures/*.png`) is a byte-identical copy of the CameraStamp app repo's `docs/verify/`. Never edit or re-record it here: copy it with the procedure in the app's `docs/verify/README.md` and check it with the app's `scripts/check-vectors-sync.sh`.

## Deploy

Pushing to `main` runs `.github/workflows/deploy.yml` (tests, build, GitHub Pages via Actions).

## Licence

No licence has been chosen yet; the owner must choose one (until then, all rights are reserved by default).
