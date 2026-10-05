import { eq, hex, kids, oid, readDer, type Der } from './der';
/**
 * The few X.509 facts level 2 needs (RFC 5280 §4.1), read with our DER reader, and a signature check through WebCrypto. No certificate
 * library: @peculiar/x509 2.x needs a global Reflect-metadata polyfill and ~100 KB for what is ~80 lines here.
 */
export interface Cert {
  der: Uint8Array; tbs: Uint8Array; sigAlg: string; signature: Uint8Array;
  /** Lowercase hex, no leading zeros: the form of Google's status.json keys. */
  serial: string;
  spki: Uint8Array; keyAlg: string; curve: string | null;
  issuer: Uint8Array; subject: Uint8Array;
  ext: Map<string, { critical: boolean; value: Uint8Array }>;
}
const ECDSA: Record<string, string> = { '1.2.840.10045.4.3.2': 'SHA-256', '1.2.840.10045.4.3.3': 'SHA-384', '1.2.840.10045.4.3.4': 'SHA-512' };
const RSA: Record<string, string> = { '1.2.840.113549.1.1.11': 'SHA-256', '1.2.840.113549.1.1.12': 'SHA-384', '1.2.840.113549.1.1.13': 'SHA-512' };
const CURVES: Record<string, [string, number]> = { '1.2.840.10045.3.1.7': ['P-256', 32], '1.3.132.0.34': ['P-384', 48], '1.3.132.0.35': ['P-521', 66] };
export const OID_EC = '1.2.840.10045.2.1', OID_RSA = '1.2.840.113549.1.1.1';

export function parseCert(der: Uint8Array): Cert {
  const top = readDer(der); if (top.tag !== 16 || top.end !== der.length) throw new Error('cert');
  const [tbsN, algN, sigN] = kids(top); if (!tbsN || !algN || !sigN || sigN.tag !== 3) throw new Error('cert');
  const t = kids(tbsN); let k = 0;
  if (t[0].cls === 2 && t[0].tag === 0) k = 1;                                          // [0] EXPLICIT version
  const serialN = t[k], issuerN = t[k + 2], subjectN = t[k + 4], spkiN = t[k + 5];
  if (!serialN || serialN.tag !== 2 || !spkiN || spkiN.tag !== 16) throw new Error('cert');
  const [spkiAlg] = kids(spkiN); const algParts = kids(spkiAlg);
  const keyAlg = oid(algParts[0].content); const curve = keyAlg === OID_EC && algParts[1]?.tag === 6 ? oid(algParts[1].content) : null;
  const ext = new Map<string, { critical: boolean; value: Uint8Array }>();
  const extN = t.find(x => x.cls === 2 && x.tag === 3);
  if (extN) for (const e of kids(kids(extN)[0])) { const p = kids(e); const critical = p.length === 3 && p[1].tag === 1 && p[1].content[0] !== 0;
    const id = oid(p[0].content); if (ext.has(id)) throw new Error('duplicate extension'); ext.set(id, { critical, value: p[p.length - 1].content }); }
  const serial = hex(serialN.content).replace(/^0+/, '') || '0';
  return { der, tbs: slice(tbsN, tbsN.content), sigAlg: oid(kids(algN)[0].content), signature: sigN.content.subarray(1), serial,
    spki: slice(spkiN, spkiN.content), keyAlg, curve, issuer: slice(issuerN, issuerN.content), subject: slice(subjectN, subjectN.content), ext };
}
/** The whole TLV (header included) of node `n`, given its content view. */
function slice(n: Der, content: Uint8Array): Uint8Array {
  const hdr = n.end - n.start - content.length; return new Uint8Array(content.buffer, content.byteOffset - hdr, hdr + content.length);
}
/** The uncompressed EC point of a P-256 SPKI (65 bytes, 04‖X‖Y), or null for any other key. */
export function ecPoint(c: Cert): Uint8Array | null {
  if (c.keyAlg !== OID_EC || c.curve !== '1.2.840.10045.3.1.7') return null;
  const bits = kids(readDer(c.spki))[1].content; const p = bits.subarray(1);
  return p.length === 65 && p[0] === 4 && bits[0] === 0 ? p : null;
}
/** DER ECDSA-Sig-Value → raw r‖s of n bytes each (WebCrypto's format). */
export function rawSig(der: Uint8Array, n: number): Uint8Array {
  const [r, s] = kids(readDer(der)); const out = new Uint8Array(2 * n);
  for (const [v, at] of [[r.content, 0], [s.content, n]] as const) { const x = v[0] === 0 ? v.subarray(1) : v; if (x.length > n) throw new Error('sig'); out.set(x, at + n - x.length); }
  return out;
}
/** Verifies `data` was signed with `sig` by the key in `spkiOf` (a Cert), algorithm `alg` (an X.509 signature OID). Never throws. */
export async function verifyWith(spkiOf: Cert, alg: string, data: Uint8Array, sig: Uint8Array): Promise<boolean> {
  try {
    const s = crypto.subtle; const buf = (u: Uint8Array) => u.slice().buffer;
    if (ECDSA[alg] && spkiOf.keyAlg === OID_EC && spkiOf.curve && CURVES[spkiOf.curve]) {
      const [namedCurve, n] = CURVES[spkiOf.curve];
      const key = await s.importKey('spki', buf(spkiOf.spki), { name: 'ECDSA', namedCurve }, false, ['verify']);
      return await s.verify({ name: 'ECDSA', hash: ECDSA[alg] }, key, buf(rawSig(sig, n)), buf(data));
    }
    if (RSA[alg] && spkiOf.keyAlg === OID_RSA) {
      const key = await s.importKey('spki', buf(spkiOf.spki), { name: 'RSASSA-PKCS1-v1_5', hash: RSA[alg] }, false, ['verify']);
      return await s.verify('RSASSA-PKCS1-v1_5', key, buf(sig), buf(data));
    }
    return false;
  } catch { return false; }
}
/** `child` carries a valid signature by `issuer`'s key. */
export const signedBy = (child: Cert, issuer: Cert) => verifyWith(issuer, child.sigAlg, child.tbs, child.signature);
/** basicConstraints cA = TRUE. */
export function isCa(c: Cert): boolean {
  const e = c.ext.get('2.5.29.19'); if (!e) return false;
  const seq = kids(readDer(e.value)); return seq[0]?.tag === 1 && seq[0].content[0] !== 0;
}
/** The first attribute `type` of a Name (CN 2.5.4.3 by default; O is 2.5.4.10), or null. */
export function commonName(name: Uint8Array, type = '2.5.4.3'): string | null {
  try { for (const rdn of kids(readDer(name))) for (const atv of kids(rdn)) { const [t, v] = kids(atv); if (oid(t.content) === type) return new TextDecoder().decode(v.content); } } catch { /* none */ }
  return null;
}
/** extendedKeyUsage contains `purpose`. */
export function hasEku(c: Cert, purpose: string): boolean {
  const e = c.ext.get('2.5.29.37'); if (!e) return false;
  try { return kids(readDer(e.value)).some(k => oid(k.content) === purpose); } catch { return false; }
}
export const sameKey = (a: Cert, b: Cert) => eq(a.spki, b.spki);
export function pemToDer(pem: string): Uint8Array[] {
  return [...pem.matchAll(/-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----/g)].map(m => Uint8Array.from(atob(m[1].replace(/\s/g, '')), c => c.charCodeAt(0)));
}
