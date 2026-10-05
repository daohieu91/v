import { hex, int, kids, readDer, type Der } from './der';
import { ecPoint, isCa, parseCert, pemToDer, sameKey, signedBy, type Cert } from './x509';
/**
 * Android key attestation (https://source.android.com/docs/security/features/keystore/attestation), checked in the browser.
 * securityLevel = attestationSecurityLevel (field 1), keySecurityLevel = keyMint/keymasterSecurityLevel (field 3): 0 Software,
 * 1 TrustedEnvironment, 2 StrongBox. The root of trust is read from hardwareEnforced only when the attestation is hardware (a software
 * list is written by Android, not the TEE); a software attestation may carry it in softwareEnforced (API 35 emulator).
 */
export interface KeyDescription { securityLevel: 0 | 1 | 2; keySecurityLevel: 0 | 1 | 2; packages: string[]; signatureDigests: string[];
  verifiedBootState: number | null; deviceLocked: boolean | null }
export interface ChainCheck { chainOk: boolean; revoked: boolean; leaf: KeyDescription | null; leafKey: Uint8Array | null /* 65-byte point */ }
export const OID_KEY_DESC = '1.3.6.1.4.1.11129.2.1.17';
const ctx = (list: Der | undefined, t: number) => (list ? kids(list).find(k => k.cls === 2 && k.tag === t) : undefined);
const level = (n: number): 0 | 1 | 2 => (n === 1 || n === 2 ? n : 0);
/** KeyDescription: version, attestationSecurityLevel, version, keySecurityLevel, challenge, uniqueId, softwareEnforced, hardwareEnforced. Tags: [704] rootOfTrust, [709] attestationApplicationId. */
export function parseKeyDescription(ext: Uint8Array): KeyDescription {
  const f = kids(readDer(ext)); const sw = f[6], hw = f[7];
  if (!sw || !hw || sw.tag !== 16 || hw.tag !== 16) throw new Error('key description');
  const securityLevel = level(int(f[1])), keySecurityLevel = level(int(f[3]));
  const rot = ctx(hw, 704) ?? (securityLevel === 0 ? ctx(sw, 704) : undefined);
  let boot: number | null = null, locked: boolean | null = null;
  if (rot) { const r = kids(kids(rot)[0]); locked = r[1].tag === 1 && r[1].content[0] !== 0; boot = int(r[2]); }
  const aid = ctx(sw, 709) ?? ctx(hw, 709);
  const packages: string[] = [], digests: string[] = [];
  if (aid) { const seq = readDer(kids(aid)[0].content); const [infos, sigs] = kids(seq);
    for (const p of kids(infos)) packages.push(new TextDecoder().decode(kids(p)[0].content));
    for (const s of kids(sigs)) digests.push(hex(s.content)); }
  return { securityLevel, keySecurityLevel, packages, signatureDigests: digests, verifiedBootState: boot, deviceLocked: locked };
}
/**
 * chainOk = every certificate is signed by the next one, every issuer is a CA, only the leaf carries a KeyDescription (else a
 * hardware-attested key could sign a fake "leaf" with any extension it likes), the last certificate's public key is one of Google's
 * roots, and no serial is in Google's status list (any entry — REVOKED or SUSPENDED — is not trusted). Never throws.
 */
export async function checkChain(chainDer: Uint8Array[], rootsPem: string[], status: { entries: Record<string, unknown> }): Promise<ChainCheck> {
  const none: ChainCheck = { chainOk: false, revoked: false, leaf: null, leafKey: null };
  if (!chainDer.length || chainDer.length > 10) return none;
  let certs: Cert[]; try { certs = chainDer.map(parseCert); } catch { return none; }
  let links = true;
  for (let i = 0; i + 1 < certs.length; i++) links = links && isCa(certs[i + 1]) && !certs[i + 1].ext.has(OID_KEY_DESC) && await signedBy(certs[i], certs[i + 1]);
  let roots: Cert[] = []; try { roots = rootsPem.flatMap(pemToDer).map(parseCert); } catch { roots = []; }
  const last = certs[certs.length - 1];
  const toGoogle = roots.some(r => sameKey(r, last)) && await signedBy(last, last);
  const revoked = certs.some(c => Object.prototype.hasOwnProperty.call(status?.entries ?? {}, c.serial));
  const ext = certs[0].ext.get(OID_KEY_DESC);
  let leaf: KeyDescription | null = null; try { leaf = ext ? parseKeyDescription(ext.value) : null; } catch { leaf = null; }
  return { chainOk: links && toGoogle && !revoked && !!leaf, revoked, leaf, leafKey: ecPoint(certs[0]) };
}
