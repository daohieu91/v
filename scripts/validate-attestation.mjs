// Strict validation of the copied Google attestation data. Throws on anything unexpected.
import { X509Certificate } from 'node:crypto';
export function validateRoots(text) {
  let r; try { r = JSON.parse(text); } catch { throw new Error('roots: not JSON'); }
  if (!Array.isArray(r) || r.length === 0) throw new Error('roots: not a non-empty array');
  for (const p of r) {
    if (typeof p !== 'string' || !p.includes('BEGIN CERTIFICATE')) throw new Error('roots: entry is not a PEM certificate');
    const c = new X509Certificate(p); // throws if the DER does not parse as X.509
    if (!c.subject) throw new Error('roots: certificate without subject');
  }
  return r.length;
}
export function validateStatus(text) {
  let s; try { s = JSON.parse(text); } catch { throw new Error('status: not JSON'); }
  if (s === null || typeof s !== 'object' || s.entries === null || typeof s.entries !== 'object' || Array.isArray(s.entries))
    throw new Error('status: entries is not an object');
  return Object.keys(s.entries).length;
}
export function validateMeta(text) {
  let m; try { m = JSON.parse(text); } catch { throw new Error('meta: not JSON'); }
  if (!m || typeof m.checkedAt !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(m.checkedAt)) throw new Error('meta: bad checkedAt');
  return m.checkedAt;
}
if (process.argv[1]?.endsWith('validate-attestation.mjs')) {
  const [roots, status] = process.argv.slice(2);
  const { readFileSync } = await import('node:fs');
  console.log('roots:', validateRoots(readFileSync(roots, 'utf8')), 'status entries:', validateStatus(readFileSync(status, 'utf8')));
}
