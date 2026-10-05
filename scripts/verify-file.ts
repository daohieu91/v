// Task 23: run the page's level-1 pipeline on a real photo from a shell, with the same modules (no browser).
// Usage: npm run verify-file -- <photo.jpg>   Prints one JSON line; no coordinates, no file name. Exit 2 = no code.
// Decode: scripts/decode-node.ts (libjpeg-turbo via sharp, byte-identical to Chromium/Firefox; the page's own size plan). Then the
// worker body itself (src/analyze.ts: QR plan P22, fingerprint or, for a NO_FINGERPRINT seal, the texture) and the page's verdict.
import { readFileSync } from 'node:fs';
import { analyze } from '../src/analyze'; import { checkSeal } from '../src/crypto'; import { payloadFromUrl } from '../src/payload';
import { verdict } from '../src/verdict'; import { decodeLikeThePage } from './decode-node';
const bytes = readFileSync(process.argv[2]);
const im = await decodeLikeThePage(new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.length));
const r = analyze(im);
if (!r.url) { console.log('NO_CODE'); process.exit(2); }
const p = payloadFromUrl(r.url); const seal = p ? checkSeal(p) : null;
const v = verdict({ payload: p, seal, hamming: p ? r.hamming : null, texture: p ? r.texture : null, level2: null });
console.log(JSON.stringify({ verdict: v.color, headline: v.headline, distance: r.hamming, texture: r.texture, noFingerprint: p?.fields.noFingerprint ?? null,
  time: p?.fields.epochSeconds ?? null, keyId: seal?.keyIdHex ?? null, size: [im.w, im.h], via: im.via }));
