import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { line } from '../src/ui';
const en = JSON.parse(readFileSync('src/i18n/en.json', 'utf8')) as Record<string, string>;
describe('ui line text', () => {
  it('a key the dictionary does not know shows the generic line, never the raw key', () => {
    expect(line(en, 'l2_from_the_future')).toBe('Unrecognised check result');
    expect(line(en, 'check_image_match', { d: 3 })).toBe('The photo matches its seal (difference 3/64)');
  });
});
