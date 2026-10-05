# CameraStamp photo verifier

Public web verifier for photos sealed by the CameraStamp app: https://daohieu91.github.io/v/

## Permanent URL

**This repository must never be renamed, deleted or made private: every printed CameraStamp QR points here.**
The URL `https://daohieu91.github.io/v/` is permanent.

## Privacy

- Verification runs entirely in your browser. **Nothing is uploaded**: the photo and the QR data never leave your device.
- No server, no analytics, no cookies, no third-party scripts. A strict Content-Security-Policy `<meta>` in each HTML page enforces this (`connect-src 'self'`), and `test/csp.test.ts` pins it.
- The seal data in the URL is in the fragment (`#...`), which browsers never send to GitHub.
- Google's Android attestation roots and revocation list are copied daily into `public/attestation/` by a GitHub Action, so the page itself never contacts Google.

## Develop and test

```
npm ci
npm test            # Vitest (includes the CSP privacy test)
npm run build       # type-check + production build into dist/
npm run size        # level-1 bundle size budget (run after build)
npx playwright install chromium webkit firefox
npm run e2e         # Playwright, against `vite preview`
```

## Deploy

Pushing to `main` runs `.github/workflows/deploy.yml` (tests, build, GitHub Pages via Actions).

## Licence

No licence has been chosen yet; the owner must choose one.
