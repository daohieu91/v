import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { validJob, validL2Reply, validReply } from '../src/messages';
import { b64urlDecode, decodePayload } from '../src/payload';
const V = JSON.parse(readFileSync('test/vectors/verify-vectors.json', 'utf8'));
const P0 = () => decodePayload(b64urlDecode(V.payloads[0].base64url));
describe('postMessage validation', () => {
  it('worker job: pixels must be exactly w·h·4 bytes; a Blob is fine; fragments are bounded', () => {
    expect(validJob({ data: new ArrayBuffer(16), w: 2, h: 2, fallback: null })).not.toBeNull();
    expect(validJob({ data: new ArrayBuffer(15), w: 2, h: 2, fallback: null })).toBeNull();
    expect(validJob({ data: new ArrayBuffer(16), w: 2.5, h: 2, fallback: null })).toBeNull();
    expect(validJob({ data: new ArrayBuffer(16), w: 2, h: 2, fallback: 'x'.repeat(141) })).toBeNull();
    expect(validJob({ data: new ArrayBuffer(16), w: 2, h: 2, fallback: 'x'.repeat(140) })).not.toBeNull();   // a full v1 fragment (105 B)
    expect(validJob({ file: new Blob(['x']), fallback: 'abc' })).not.toBeNull();
    expect(validJob('nope')).toBeNull(); expect(validJob(null)).toBeNull();
  });
  it('worker reply: only our URL, hamming 0..64, known decode path', () => {
    const ok = { ok: true, r: { url: V.payloads[0].url, hamming: 3, texture: null, qrInPicture: true, geometry: 'ok' }, dec: { w: 10, h: 10, via: 'plain' } };
    expect(validReply(ok)).toEqual(ok);
    const flat = { ...ok, r: { ...ok.r, hamming: null, texture: 2 ** 36 - 1 } };   // P26: Step 7 texture, an exact integer < 2³⁶
    expect(validReply(flat)).toEqual(flat);
    for (const texture of [-1, 2 ** 36, 1.5, '7', undefined]) expect(validReply({ ...ok, r: { ...ok.r, texture } }), String(texture)).toBeNull();
    expect(validReply({ ...ok, r: { ...ok.r, url: 'https://evil.example/#x' } })).toBeNull();
    for (const bad of [{ qrInPicture: 'yes' }, { qrInPicture: undefined }, { geometry: 'cropped' }, { geometry: undefined }])
      expect(validReply({ ...ok, r: { ...ok.r, ...bad } }), JSON.stringify(bad)).toBeNull();
    expect(validReply({ ...ok, r: { ...ok.r, qrInPicture: false, geometry: null } })).not.toBeNull();
    expect(V.payloads[0].url).toHaveLength(171);
    expect(validReply({ ...ok, r: { ...ok.r, url: V.payloads[0].url + 'A' } }), 'longer than a v1 URL').toBeNull();
    expect(validReply({ ...ok, r: { ...ok.r, url: null, hamming: 65 } })).toBeNull();
    expect(validReply({ ...ok, dec: { w: 10, h: 10, via: 'magic' } })).toBeNull();
    expect(validReply({ ok: false, need: 'pixels' })).toEqual({ ok: false, need: 'pixels' });
    expect(validReply({ ok: false, err: 'oversize' })).toEqual({ ok: false, err: 'oversize' });
    expect(validReply({ ok: 'yes' })).toBeNull();
  });
  it('level-2 reply: lines are checked, and a payload whose signed bytes are not its own fields is refused', () => {
    const sum = { kind: 'ok', lines: [{ key: 'l2_signature_ok', status: 'pass' }], realDevice: true, bound: true };
    expect(validL2Reply({ summary: sum, payload: null })?.summary.kind).toBe('ok');
    expect(validL2Reply({ summary: { ...sum, kind: 'great' }, payload: null })).toBeNull();
    expect(validL2Reply({ summary: { ...sum, bound: 'yes' }, payload: null }), 'bound must be a boolean').toBeNull();
    expect(validL2Reply({ summary: { kind: 'ok', lines: [], realDevice: false } , payload: null }), 'bound is required').toBeNull();
    expect(validL2Reply({ summary: { ...sum, bound: false }, payload: null }), 'real device on an unbound file').toBeNull();
    expect(validL2Reply({ summary: { ...sum, kind: 'invalid' }, payload: null }), 'real device on an invalid file').toBeNull();
    expect(validL2Reply({ summary: { ...sum, realDevice: false, bound: false }, payload: null })?.summary.bound).toBe(false);
    expect(validL2Reply({ summary: { ...sum, lines: [{ key: '<b>x</b>', status: 'pass' }] }, payload: null })).toBeNull();
    expect(validL2Reply({ summary: { ...sum, lines: [{ key: 'l2_tsa', status: 'pass', params: { time: {} } }] }, payload: null })).toBeNull();
    expect(validL2Reply({ summary: sum, payload: P0() })?.payload).not.toBeNull();
    const forged = P0(); forged.fields = { ...forged.fields, epochSeconds: forged.fields.epochSeconds + 3600 };
    expect(validL2Reply({ summary: sum, payload: forged })).toBeNull();
  });
});
