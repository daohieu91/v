import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

describe('shared glossary pin (byte-identical to the app docs/verify/glossary.json)', () => {
  it('src/glossary.json matches its recorded SHA-256', () => {
    const rec = readFileSync('src/glossary.json.sha256', 'utf8');
    expect(rec).toMatch(/^[0-9a-f]{64}  glossary\.json\n$/);
    const actual = createHash('sha256').update(readFileSync('src/glossary.json')).digest('hex');
    expect(actual).toBe(rec.slice(0, 64));
  });
});
