import { keyIdOf } from '../crypto';
import type { Check } from '../verdict';
import type { ChainCheck } from './attestation';
import { eq, hex } from './der';
export interface Digest { hex: string; dev: boolean }
export interface DeviceInput {
  chain: ChainCheck;
  /** P-256 points (65 bytes): the C2PA x5chain leaf's key, and the key recovered from the seal payload (only if checkSeal passed). */
  signerKey: Uint8Array | null; payloadKey: Uint8Array | null;
  /** The level-1 QR's 8-byte key id, when the picked file also carried a valid QR seal. */
  qrKeyIdHex: string | null;
  packageName: string; digests: readonly Digest[];
}
/**
 * Spec §5.2, one line per condition. "Sealed by a key in a real device's secure hardware" (l2_real_device) needs ALL of: a chain to a
 * Google root, unrevoked; a hardware attestation of a hardware key (TEE or StrongBox; API 24–27 and emulators are software, P11);
 * verified boot and a locked bootloader; our package with a REGISTERED release digest (a dev digest is a test build, an unknown one is
 * "not registered yet": neither is ever "real device"); the attested key = the C2PA signer key = the seal payload's key; and, when the
 * file's picture carried a QR seal, that QR's key id = the attested key's id.
 * `contentBound` (signer key = payload key) is what lets a file-level check stand for the seal's content (P30).
 */
export function deviceLines(i: DeviceInput): { lines: Check[]; realDevice: boolean; contentBound: boolean } {
  const lines: Check[] = []; const { chain, signerKey, payloadKey } = i; const leaf = chain.leaf;
  lines.push(chain.revoked ? { key: 'l2_revoked', status: 'fail' } : chain.chainOk ? { key: 'l2_chain_ok', status: 'pass' } : { key: 'l2_chain_bad', status: 'fail' });
  let digest: Digest | undefined; let hw = false;
  if (leaf) {   // no readable KeyDescription (or no chain): "not certified" above says it all; no per-condition guesses
    const ours = leaf.packages.includes(i.packageName);
    digest = ours ? i.digests.find(d => leaf.signatureDigests.includes(d.hex.toLowerCase())) : undefined;
    // No attestationApplicationId at all (API 24's software attestation, measured in the spike) names no app: unknown, not "another app".
    // M8: once a release digest is registered (Part 4: the Play App Signing certificate), OUR package signed by any unknown certificate
    // is a re-packaged app (same package name, another key): "not made by the app" (red with a certified chain), never "not yet registered".
    const released = i.digests.some(d => !d.dev);
    lines.push(!leaf.packages.length ? { key: 'l2_app_unknown', status: 'warn' } : !ours ? { key: 'l2_app_bad', status: 'fail' }
      : !digest ? (released ? { key: 'l2_app_bad', status: 'fail' } : { key: 'l2_app_unregistered', status: 'warn' })
      : digest.dev ? { key: 'l2_app_dev', status: 'warn' } : { key: 'l2_app_ok', status: 'pass' });
    hw = leaf.securityLevel >= 1 && leaf.keySecurityLevel >= 1;
    lines.push(hw ? { key: 'l2_level_hw', status: 'pass' } : { key: 'l2_level_sw', status: 'warn' });
    if (leaf.verifiedBootState === null && leaf.deviceLocked === null) lines.push({ key: 'l2_boot_unknown', status: 'info' });   // no root of trust attested
    else {
      lines.push(leaf.verifiedBootState === 0 ? { key: 'l2_boot_ok', status: 'pass' } : { key: 'l2_boot_bad', status: 'fail' });
      lines.push(leaf.deviceLocked === true ? { key: 'l2_locked_ok', status: 'pass' } : { key: 'l2_locked_bad', status: 'fail' });
    }
  }
  const contentBound = !!(signerKey && payloadKey && eq(signerKey, payloadKey));
  // No attestation at all (an empty chain) is "not certified", not a forgery; an attested key that is NOT the signer's is.
  const deviceBound = !!(chain.leafKey && signerKey && eq(chain.leafKey, signerKey));
  if (!contentBound || (chain.leafKey && !deviceBound)) lines.push({ key: 'l2_binding_bad', status: 'fail' });
  const qrOk = i.qrKeyIdHex === null || (!!chain.leafKey && hex(keyIdOf(chain.leafKey)) === i.qrKeyIdHex);
  const realDevice = chain.chainOk && !chain.revoked && !!leaf && hw && leaf.verifiedBootState === 0 && leaf.deviceLocked === true
    && !!digest && !digest.dev && contentBound && deviceBound && qrOk;
  if (realDevice) lines.push({ key: 'l2_real_device', status: 'pass' });
  const fileKey = chain.leafKey ?? signerKey;                    // without an attestation, the QR is compared with the file's signer
  if (i.qrKeyIdHex !== null && fileKey)
    lines.push(hex(keyIdOf(fileKey)) === i.qrKeyIdHex ? (realDevice ? { key: 'l2_qr_link', status: 'pass' } : { key: 'l2_qr_same_key', status: 'info' }) : { key: 'l2_qr_other_key', status: 'fail' });
  return { lines, realDevice, contentBound };
}
