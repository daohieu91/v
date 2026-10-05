import { PACKAGE_NAME, SIGNING_DIGESTS } from '../config';
import { checkSeal, recoverPublicKey } from '../crypto';
import { b64urlDecode, decodePayload, type SealPayload } from '../payload';
import type { Check, L2Summary } from '../verdict';
import { checkChain } from './attestation';
import { deviceLines, type Digest } from './device';
import { coseSigner, tstInfo } from './jumbf';
import { ecPoint, parseCert } from './x509';
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
  const store = i.store;
  if (!store?.active_manifest || !store.manifests?.[store.active_manifest]) { lines.push({ key: 'l2_none', status: 'info' }); return done('none'); }
  const failures: string[] = (store.validation_results?.activeManifest?.failure ?? []).map((f: any) => String(f?.code));
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
  let signerKey: Uint8Array | null = null; try { signerKey = signer?.x5chain[0] ? ecPoint(parseCert(signer.x5chain[0])) : null; } catch { signerKey = null; }
  const payloadKey = payload && checkSeal(payload).ok ? recoverPublicKey(payload) : null;
  const d = deviceLines({ chain, signerKey, payloadKey, qrKeyIdHex: i.qrKeyIdHex, packageName: PACKAGE_NAME, digests: i.digests ?? SIGNING_DIGESTS });
  lines.push(...d.lines);
  const tst = !tsBroken && signer?.tstTokens[0] ? tstInfo(signer.tstTokens[0]) : null;
  lines.push(tst ? { key: 'l2_tsa', status: 'pass', params: { time: tst.genTime, tsa: (tst.tsaName ?? '?').slice(0, 100) } } : { key: 'l2_no_tsa', status: 'info' });
  return done('ok', d.realDevice, d.contentBound, payload);
}
