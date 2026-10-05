import { PACKAGE_NAME, SIGNING_DIGESTS } from '../config';
import { checkSeal, recoverPublicKey } from '../crypto';
import { b64urlDecode, decodePayload, type SealPayload } from '../payload';
import type { Check, L2Summary } from '../verdict';
import { checkChain } from './attestation';
import { deviceLines, type Digest } from './device';
import { coseSigner, tstInfo } from './jumbf';
import { commonName, ecPoint, parseCert, type Cert } from './x509';
/** x5chain[0] is the certificate c2pa-web reports in signature_info (cert_serial_number is decimal; issuer is the issuer's O). */
export function sameSigner(c: Cert, info: any): boolean {
  if (!info || typeof info.cert_serial_number !== 'string') return false;
  let serial: string; try { serial = BigInt('0x' + c.serial).toString(); } catch { return false; }
  return serial === info.cert_serial_number && commonName(c.subject) === (info.common_name ?? null) && commonName(c.issuer, '2.5.4.10') === (info.issuer ?? null);
}
export const SEAL_LABEL = 'com.essenty.camerastamp.seal';
export interface L2Reply { summary: L2Summary; payload: SealPayload | null }
/** What level 2 gathered from the file: c2pa-web's manifest store (or null) and our own read of the active COSE_Sign1 (or null). */
export interface L2Input { store: any; cose: Uint8Array | null; roots: string[]; status: { entries: Record<string, unknown> };
  qrKeyIdHex: string | null; digests?: readonly Digest[] }
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
  const payloadKey = payload && checkSeal(payload).ok ? recoverPublicKey(payload) : null;
  const d = deviceLines({ chain, signerKey, payloadKey, qrKeyIdHex: i.qrKeyIdHex, packageName: PACKAGE_NAME, digests: i.digests ?? SIGNING_DIGESTS });
  lines.push(...d.lines);
  // "Confirmed by X" only when c2pa-web validated the time-stamp (0.15.3 emits timeStamp.validated; newer ones may say trusted), and X is
  // the token's signer certificate (tstInfo). Anything else: no independent time-stamp is claimed.
  const tsOk = !tsBroken && successes.some(c => c === 'timeStamp.validated' || c === 'timeStamp.trusted');
  const tst = tsOk && signer?.tstTokens[0] ? tstInfo(signer.tstTokens[0]) : null;
  lines.push(tst?.tsaName ? { key: 'l2_tsa', status: 'pass', params: { time: tst.genTime, tsa: tst.tsaName.slice(0, 100) } } : { key: 'l2_no_tsa', status: 'info' });
  return done('ok', d.realDevice, d.contentBound, payload);
}
