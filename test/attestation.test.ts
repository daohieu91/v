import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
// @ts-expect-error plain .mjs
import { validateMeta, validateRoots, validateStatus } from '../scripts/validate-attestation.mjs';
const rd = (f: string) => readFileSync('public/attestation/' + f, 'utf8');
describe('committed attestation copy', () => {
  it('roots parse as X.509', () => expect(validateRoots(rd('roots.json'))).toBeGreaterThan(0));
  it('status has an entries object', () => expect(validateStatus(rd('status.json'))).toBeGreaterThan(0));
  it('meta has a date', () => expect(validateMeta(rd('meta.json'))).toMatch(/^\d{4}-\d{2}-\d{2}$/));
});
describe('validators reject bad input', () => {
  it('roots', () => {
    for (const bad of ['', 'null', '[]', '{}', '["x"]', '["-----BEGIN CERTIFICATE-----\\nAAAA\\n-----END CERTIFICATE-----"]'])
      expect(() => validateRoots(bad), bad).toThrow();
  });
  it('status', () => {
    for (const bad of ['', 'null', '{}', '{"entries":null}', '{"entries":[]}', '{"entries":3}'])
      expect(() => validateStatus(bad), bad).toThrow(/status/);
  });
  it('meta', () => {
    for (const bad of ['', 'null', '{}', '{"checkedAt":"yesterday"}', '{"checkedAt":"x2026-10-05"}', '{"checkedAt":"2026-10-05x"}']) expect(() => validateMeta(bad), bad).toThrow();
  });
});
