import { eq, kids, oid, readDer, type Der } from './der';
import { counterSignToBeSigned, formatGenTime } from './jumbf';
import { TSA_ROOTS_B64 } from './tsa-roots';
import { commonName, derTime, hasEku, isCa, parseCert, signedBy, verifyWith, type Cert } from './x509';
/**
 * I2: our OWN check of an RFC 3161 time-stamp token before the page says "confirmed by <TSA>". c2pa-web's `timeStamp.validated` means
 * the token's signature and imprint check out, NOT that its signer is a TSA anyone trusts: a self-made certificate named "DigiCert …"
 * would pass that. A port of the app's Rfc3161.verifyToken (RFC 5652 §5.4/§5.6, RFC 3161 §2.4.2, RFC 5816), rule for rule:
 *  - one SignerInfo with signed attributes; contentType = id-ct-TSTInfo; messageDigest = digest(TSTInfo);
 *  - an ESS signing-certificate attribute (v2, else v1) whose hash is the signer certificate's;
 *  - the signature over the DER SET of the signed attributes verifies with the signer's key;
 *  - the signer has the timeStamping EKU and chains, through the token's own certificates, to one of the PINNED roots (tsa-roots.ts,
 *    the app's TsaTrust), every link signed by the next, every issuer a CA, every certificate valid at genTime (no revocation, as the app).
 * Returns the time and the signer's CN, or null on anything else. Never throws.
 */
const SIGNED_DATA = '1.2.840.113549.1.7.2', TST_INFO = '1.2.840.113549.1.9.16.1.4';
const ATTR_CONTENT_TYPE = '1.2.840.113549.1.9.3', ATTR_MESSAGE_DIGEST = '1.2.840.113549.1.9.4';
const ATTR_SIGNING_CERT = '1.2.840.113549.1.9.16.2.12', ATTR_SIGNING_CERT_V2 = '1.2.840.113549.1.9.16.2.47';
const EKU_TIME_STAMPING = '1.3.6.1.5.5.7.3.8';
const MAX_CERTS = 8;
const DIGESTS: Record<string, string> = { '1.3.14.3.2.26': 'SHA-1', '2.16.840.1.101.3.4.2.1': 'SHA-256', '2.16.840.1.101.3.4.2.2': 'SHA-384', '2.16.840.1.101.3.4.2.3': 'SHA-512' };
/** The app's jcaSignature: rsaEncryption takes the SignerInfo's digest; the rest name their own (as X.509 signature OIDs, for verifyWith). */
const RSA_WITH: Record<string, string> = { 'SHA-256': '1.2.840.113549.1.1.11', 'SHA-384': '1.2.840.113549.1.1.12', 'SHA-512': '1.2.840.113549.1.1.13' };
const SIG_ALGS = new Set(['1.2.840.113549.1.1.11', '1.2.840.113549.1.1.12', '1.2.840.113549.1.1.13', '1.2.840.10045.4.3.2', '1.2.840.10045.4.3.3', '1.2.840.10045.4.3.4']);

let anchors: Cert[] | null = null;
const roots = () => (anchors ??= TSA_ROOTS_B64.map(b => parseCert(Uint8Array.from(atob(b), c => c.charCodeAt(0)))));
const isOid = (n: Der | undefined, dotted: string) => !!n && n.cls === 0 && n.tag === 6 && oid(n.content) === dotted;
const raw = (parent: Der, n: Der) => parent.content.subarray(n.start, n.end);
const digest = async (alg: string, data: Uint8Array) => new Uint8Array(await crypto.subtle.digest(alg, data.slice().buffer));
function digestOf(algId: Der): string { const a = kids(algId)[0]; const d = a && a.tag === 6 ? DIGESTS[oid(a.content)] : undefined; if (!d || d === 'SHA-1') throw new Error('tsa: digest'); return d; }

export async function verifyTsaToken(token: Uint8Array, pinned: readonly Cert[] = roots()): Promise<{ genTime: string; tsaName: string } | null> {
  try {
    const ci = readDer(token); if (ci.tag !== 16 || ci.end !== token.length) return null;
    const top = kids(ci); if (top.length !== 2 || !isOid(top[0], SIGNED_DATA) || top[1].cls !== 2 || top[1].tag !== 0) return null;
    const sdN = kids(top[1]); if (sdN.length !== 1) return null; const sd = kids(sdN[0]);
    if (sd.length < 4 || sd[sd.length - 1].tag !== 17) return null;
    const eci = kids(sd[2]); if (eci.length !== 2 || !isOid(eci[0], TST_INFO) || eci[1].cls !== 2 || eci[1].tag !== 0) return null;
    const eContent = kids(eci[1]); if (eContent.length !== 1 || eContent[0].tag !== 4) return null;
    const tst = eContent[0].content;
    const tstFields = kids(readDer(tst)); const gt = tstFields[4]; if (!gt || gt.tag !== 24) return null;
    const genMs = derTime(gt); if (!Number.isFinite(genMs)) return null;
    const certsN = sd.slice(3, -1).find(n => n.cls === 2 && n.tag === 0);
    const certNodes = certsN ? kids(certsN) : []; if (certNodes.length > MAX_CERTS) return null;
    const certs = certNodes.map(c => parseCert(raw(certsN!, c).slice()));
    const infos = kids(sd[sd.length - 1]); if (infos.length !== 1) return null;
    const si = kids(infos[0]); if (si.length < 6 || si[3].cls !== 2 || si[3].tag !== 0) return null;
    const sid = si[1];
    const signer = certs.find(c => identifies(sid, c)); if (!signer) return null;
    const md = digestOf(si[2]);
    const attrs = new Map<string, Der>();
    for (const a of kids(si[3])) { const c = kids(a); if (c.length !== 2 || c[0].tag !== 6) return null; const vals = kids(c[1]); if (vals.length !== 1) return null;
      const k = oid(c[0].content); if (attrs.has(k)) return null; attrs.set(k, vals[0]); }
    if (!isOid(attrs.get(ATTR_CONTENT_TYPE), TST_INFO)) return null;
    const mdAttr = attrs.get(ATTR_MESSAGE_DIGEST); if (!mdAttr || mdAttr.tag !== 4 || !eq(mdAttr.content, await digest(md, tst))) return null;
    const v2 = attrs.get(ATTR_SIGNING_CERT_V2), v1 = attrs.get(ATTR_SIGNING_CERT);
    if (v2) { const id = kids(kids(kids(v2)[0])[0]);                                                 // SigningCertificateV2 → certs → ESSCertIDv2
      const alg = id[0].tag === 16 ? (DIGESTS[oid(kids(id[0])[0].content)] ?? '') : 'SHA-256'; const hash = id.find(n => n.tag === 4);
      if (!alg || !hash || !eq(await digest(alg, signer.der), hash.content)) return null; }
    else if (v1) { const hash = kids(kids(kids(v1)[0])[0])[0];                                        // SigningCertificate → certs → ESSCertID.certHash
      if (!hash || hash.tag !== 4 || !eq(await digest('SHA-1', signer.der), hash.content)) return null; }
    else return null;
    const signedAttrs = raw(infos[0], si[3]).slice(); signedAttrs[0] = 0x31;                       // [0] IMPLICIT → SET OF (RFC 5652 §5.4)
    const sigAlg = oid(kids(si[4])[0].content); const alg = sigAlg === '1.2.840.113549.1.1.1' ? RSA_WITH[md] : SIG_ALGS.has(sigAlg) ? sigAlg : undefined;
    if (!alg || si[5].tag !== 4 || !(await verifyWith(signer, alg, signedAttrs, si[5].content))) return null;
    if (!hasEku(signer, EKU_TIME_STAMPING)) return null;
    if (!(await chainsToPinned(signer, certs, pinned, genMs))) return null;
    const name = commonName(signer.subject); if (!name) return null;
    return { genTime: formatGenTime(new TextDecoder().decode(gt.content)), tsaName: name };
  } catch { return null; }
}
/** TSTInfo.messageImprint (RFC 3161 §2.4.2) of a token: its hash algorithm OID and hashedMessage; null when unreadable. Never throws. */
export function tstImprint(token: Uint8Array): { alg: string; hash: Uint8Array } | null {
  try {
    const sd = kids(kids(kids(readDer(token))[1])[0]); const tst = kids(kids(sd[2])[1])[0]; if (tst.tag !== 4) return null;
    const mi = kids(kids(readDer(tst.content))[2]); const alg = kids(mi[0])[0];
    if (mi.length !== 2 || !alg || alg.tag !== 6 || mi[1].tag !== 4) return null;
    return { alg: oid(alg.content), hash: mi[1].content };
  } catch { return null; }
}
/**
 * P45: the time-stamp of one COSE signature, as the app's C2paReader (§10.3.2.5): EXACTLY one token (none, or two or more → null: no
 * "confirmed by"), whose messageImprint is SHA-256 of OUR counterSignToBeSigned(protected, signature) — checked here, not taken from
 * c2pa-web — and which then passes verifyTsaToken (pinned roots). Its algorithm OID is not compared, as the app: 32 equal bytes are SHA-256. A real token over other data (an old one, another file's) is refused.
 */
export async function verifyCoseTimeStamp(sig: { protected: Uint8Array; signature: Uint8Array; tstTokens: readonly Uint8Array[] },
  pinned: readonly Cert[] = roots()): Promise<{ genTime: string; tsaName: string } | null> {
  try {
    if (sig.tstTokens.length !== 1) return null;
    const token = sig.tstTokens[0]; const imprint = tstImprint(token);
    if (!imprint || !eq(imprint.hash, await digest('SHA-256', counterSignToBeSigned(sig.protected, sig.signature)))) return null;
    return await verifyTsaToken(token, pinned);
  } catch { return null; }
}
/** RFC 5652 §5.3: issuerAndSerialNumber, or [0] subjectKeyIdentifier. */
function identifies(sid: Der, c: Cert): boolean {
  if (sid.cls === 0 && sid.tag === 16) { const [iss, ser] = kids(sid); return eq(sid.content.subarray(iss.start, iss.end), c.issuer) && (Array.from(ser.content, x => x.toString(16).padStart(2, '0')).join('').replace(/^0+/, '') || '0') === c.serial; }
  if (sid.cls === 2 && sid.tag === 0) { const e = c.ext.get('2.5.29.14'); try { return !!e && eq(readDer(e.value).content, sid.content); } catch { return false; } }
  return false;
}
const within = (c: Cert, t: number) => c.notBefore <= t && t <= c.notAfter;
/** The app's path building (issuer name → a bag certificate, until a pinned root names the issuer), then a PKIX-like check at genTime. */
async function chainsToPinned(signer: Cert, bag: Cert[], pinned: readonly Cert[], at: number): Promise<boolean> {
  const path = [signer]; let cur = signer;
  while (!pinned.some(a => eq(a.subject, cur.issuer))) {
    if (path.length >= MAX_CERTS) return false;
    const next = bag.find(c => eq(c.subject, cur.issuer) && !eq(c.subject, c.issuer) && !path.includes(c)); if (!next) return false;
    path.push(next); cur = next;
  }
  for (let i = 0; i < path.length; i++) {
    if (!within(path[i], at)) return false;
    if (i > 0 && !isCa(path[i])) return false;
    if (i + 1 < path.length && !(await signedBy(path[i], path[i + 1]))) return false;
  }
  for (const a of pinned) if (eq(a.subject, cur.issuer) && (await signedBy(cur, a))) return true;
  return false;
}
