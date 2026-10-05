import { PACKAGE_NAME, SIGNING_DIGESTS } from '../config';
import { checkSeal, recoverPublicKey } from '../crypto';
import { b64urlDecode, decodePayload, type SealPayload } from '../payload';
import type { Check, L2Summary } from '../verdict';
import { checkChain } from './attestation';
import { deviceLines, type Digest } from './device';
import { decodeCbor, type Cbor } from './cbor';
import { coseSigner, verifyClaimSignature } from './jumbf';
import { verifyTsaToken } from './tsa';
import { commonName, ecPoint, parseCert, type Cert } from './x509';
const norm = (refs: unknown, enc: (h: unknown) => string | null): string[] | null => {
  if (!Array.isArray(refs)) return null; const out: string[] = [];
  for (const r of refs) { const url = r instanceof Map ? r.get('url') : (r as any)?.url; const h = enc(r instanceof Map ? r.get('hash') : (r as any)?.hash);
    if (typeof url !== 'string' || !h) return null; out.push(url.slice(url.lastIndexOf('/') + 1) + '=' + h); }
  return out.sort();
};
const b64of = (h: unknown) => (h instanceof Uint8Array ? btoa(String.fromCharCode(...h)) : null);
const crB64 = (h: unknown) => (typeof h === 'string' ? (/^b64'(.*)'$/.exec(h)?.[1] ?? null) : null);
/**
 * The strongest tie c2pa-web 0.15.3 allows between OUR x5chain[0] and the signer it validated. Neither signature_info nor crJSON exposes
 * the certificate DER, its SPKI or the key (measured: signature_info = alg, issuer O, common_name, decimal serial, time; crJSON
 * certificateInfo = hex serial, issuer and subject CN/O, validity). So, all of:
 *  1. crJSON's certificateInfo for the ACTIVE manifest equals our certificate (serial, issuer CN/O, subject CN/O);
 *  2. our active claim's assertion references (url + hash, created and gathered) equal crJSON's for that manifest: the claim c2pa-web
 *     validated hashes the same assertions (incl. the hard binding over this file's bytes and our seal assertion) as the claim we read;
 *  3. our own ES256 check: the key we parsed signed the claim we read (COSE Sig_structure). A key that did not sign this file's validated
 *     claim cannot pass 1–3 together, even with a parser differential that picks another manifest or a lookalike certificate.
 */
async function tiedToValidatedClaim(i: L2Input, cert: Cert, key: Uint8Array): Promise<boolean> {
  try {
    if (!i.cose || !i.claim || i.cr == null) return false;
    const cr = typeof i.cr === 'string' ? JSON.parse(i.cr) : i.cr;
    const man = (Array.isArray(cr?.manifests) ? cr.manifests : []).find((x: any) => x?.label === i.store.active_manifest); if (!man) return false;
    const ci = man.signature?.certificateInfo; const name = (n: Uint8Array) => ({ CN: commonName(n), O: commonName(n, '2.5.4.10') });
    const same = (a: any, b: { CN: string | null; O: string | null }) => (a?.CN ?? null) === b.CN && (a?.O ?? null) === b.O;
    if (!ci || String(ci.serialNumber).toLowerCase().replace(/^0+/, '') !== cert.serial || !same(ci.issuer, name(cert.issuer)) || !same(ci.subject, name(cert.subject))) return false;
    const ours = decodeCbor(i.claim) as Map<Cbor, Cbor>; const theirs = man['claim.v2'] ?? man.claim; if (!(ours instanceof Map) || !theirs) return false;
    const a = norm([...((ours.get('created_assertions') as Cbor[]) ?? []), ...((ours.get('gathered_assertions') as Cbor[]) ?? []), ...((ours.get('assertions') as Cbor[]) ?? [])], b64of);
    const b = norm([...(theirs.created_assertions ?? []), ...(theirs.gathered_assertions ?? []), ...(theirs.assertions ?? [])], crB64);
    if (!a || !b || !a.length || a.join('|') !== b.join('|')) return false;
    return await verifyClaimSignature(i.cose, i.claim, key);
  } catch { return false; }
}
/** x5chain[0] is the certificate c2pa-web reports in signature_info (cert_serial_number is decimal; issuer is the issuer's O). */
export function sameSigner(c: Cert, info: any): boolean {
  if (!info || typeof info.cert_serial_number !== 'string') return false;
  let serial: string; try { serial = BigInt('0x' + c.serial).toString(); } catch { return false; }
  return serial === info.cert_serial_number && commonName(c.subject) === (info.common_name ?? null) && commonName(c.issuer, '2.5.4.10') === (info.issuer ?? null);
}
export const SEAL_LABEL = 'com.essenty.camerastamp.seal';
export interface L2Reply { summary: L2Summary; payload: SealPayload | null }
/** What level 2 gathered from the file: c2pa-web's manifest store (or null) and our own read of the active COSE_Sign1 (or null). */
export interface L2Input { store: any; cose: Uint8Array | null;
  /** The active manifest's claim bytes as WE read them, and c2pa-web's crJSON (its own read of the same store), for the signer tie. */
  claim?: Uint8Array | null; cr?: unknown; roots: string[]; status: { entries: Record<string, unknown> };
  qrKeyIdHex: string | null; digests?: readonly Digest[];
  /** Tests only: other pinned TSA roots (default: the app's, tsa-roots.ts). */
  tsaRoots?: readonly Cert[] }
const b64 = (s: string) => Uint8Array.from(atob(s), c => c.charCodeAt(0));
/**
 * Spec §5.2 checks 1–8, each its own line. c2pa-web's validation is the authority on the file (check 1): any failure except
 * `signingCredential.untrusted` (every phone has its own key) is l2_invalid; a `timeStamp.*` failure only drops the TSA line (check 7).
 */
export async function summarize(i: L2Input): Promise<L2Reply> {
  const lines: Check[] = [];
  const done = (kind: L2Summary['kind'], realDevice = false, bound = false, payload: SealPayload | null = null): L2Reply => ({ summary: { kind, lines, realDevice, bound }, payload });
  const error = (): L2Reply => { lines.splice(0, lines.length, { key: 'l2_error', status: 'info' }); return done('none'); };
  const store = i.store;
  if (!store?.active_manifest || !store.manifests?.[store.active_manifest]) { lines.push({ key: 'l2_none', status: 'info' }); return done('none'); }
  const vr = store.validation_results?.activeManifest;
  if (!vr || !Array.isArray(vr.failure) || !Array.isArray(vr.success)) return error();   // no validation report: never assume valid (fail closed)
  const failures: string[] = vr.failure.map((f: any) => String(f?.code));
  const successes: string[] = vr.success.map((f: any) => String(f?.code));
  const tsBroken = failures.some(c => c.startsWith('timeStamp.'));
  if (failures.some(c => c !== 'signingCredential.untrusted' && !c.startsWith('timeStamp.'))) { lines.push({ key: 'l2_invalid', status: 'fail' }); return done('invalid'); }
  lines.push({ key: 'l2_signature_ok', status: 'pass' }, { key: 'l2_untrusted_note', status: 'info' });
  const m = store.manifests[store.active_manifest];
  const seal = (Array.isArray(m.assertions) ? m.assertions : []).find((a: any) => a?.label === SEAL_LABEL)?.data;
  if (!seal || typeof seal !== 'object') { lines.push({ key: 'l2_no_seal', status: 'info' }); return done('ok'); }
  let payload: SealPayload | null = null;
  try { payload = typeof seal.payload === 'string' && seal.payload.length <= 200 ? decodePayload(b64urlDecode(seal.payload)) : null; } catch { payload = null; }
  if (seal.kind === 'video' && Number.isFinite(seal.durationMs) && seal.durationMs > 0) lines.push({ key: 'l2_video', status: 'info', params: { s: Math.round(seal.durationMs / 1000) } });
  let chainDer: Uint8Array[] = [];
  try { const a = seal.attestationChain; chainDer = Array.isArray(a) && a.length <= 10 && a.every((x: unknown) => typeof x === 'string' && x.length <= 16384) ? a.map(b64) : []; } catch { chainDer = []; }
  const chain = await checkChain(chainDer, i.roots, i.status);
  let signer: ReturnType<typeof coseSigner> | null = null; try { signer = i.cose ? coseSigner(i.cose) : null; } catch { signer = null; }
  // Our own read of the signer (x5chain[0]) must be the certificate c2pa-web validated (its signature_info: serial, issuer O, subject CN):
  // a store whose active manifest we did not find, a truncated read, or a second store, never ties a key to this file.
  let signerCert: Cert | null = null; try { signerCert = signer?.x5chain[0] ? parseCert(signer.x5chain[0]) : null; } catch { signerCert = null; }
  if (!signerCert || !sameSigner(signerCert, m.signature_info)) return error();
  const signerKey = ecPoint(signerCert);
  if (!signerKey || !(await tiedToValidatedClaim(i, signerCert, signerKey))) return error();
  const payloadKey = payload && checkSeal(payload).ok ? recoverPublicKey(payload) : null;
  const d = deviceLines({ chain, signerKey, payloadKey, qrKeyIdHex: i.qrKeyIdHex, packageName: PACKAGE_NAME, digests: i.digests ?? SIGNING_DIGESTS });
  lines.push(...d.lines);
  // "Confirmed by X" only when c2pa-web validated the time-stamp (0.15.3 emits timeStamp.validated; newer ones may say trusted) AND our
  // own check (I2, tsa.ts) chains the token's signer to a PINNED TSA root (the app's TsaTrust): c2pa-web's "validated" does not mean
  // trusted, and a self-made "DigiCert" certificate passes it (measured). X is that verified signer's CN. Anything else: no independent
  // time-stamp is claimed (l2_no_tsa), never a name.
  const tsOk = !tsBroken && successes.some(c => c === 'timeStamp.validated' || c === 'timeStamp.trusted');
  const tst = tsOk && signer?.tstTokens[0] ? await verifyTsaToken(signer.tstTokens[0], i.tsaRoots) : null;
  lines.push(tst?.tsaName ? { key: 'l2_tsa', status: 'pass', params: { time: tst.genTime, tsa: tst.tsaName.slice(0, 100) } } : { key: 'l2_no_tsa', status: 'info' });
  return done('ok', d.realDevice, d.contentBound, payload);
}
