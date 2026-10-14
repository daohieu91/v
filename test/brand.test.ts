import { readdirSync, readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
const files = readdirSync('src/i18n').filter(f => f.endsWith('.json'));
describe('brand', () => {
  it('has all eleven locale files', () => { expect(files.length).toBe(11); });
  for (const f of files) it(`${f}: brand is MapStamp and no value still says CameraStamp`, () => {
    const j = JSON.parse(readFileSync(`src/i18n/${f}`, 'utf8')) as Record<string, string>;
    expect(j.brand).toBe('MapStamp');
    expect(Object.entries(j).filter(([, v]) => String(v).includes('CameraStamp')).map(([k]) => k)).toEqual([]);
  });
});
