import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  canonicalJson,
  rawIntegerNumber,
} from './verify-certificate/canonical-json.js';

// Repo convention: tsconfig builds to CommonJS (no "type": "module" in
// package.json). __dirname is the CJS global and resolves to this test
// file's directory at runtime.
const fixturesDir = join(__dirname, 'verify-certificate', '__fixtures__');

describe('canonicalJson — port of pkg/veil/canonical.go', () => {
  it('sorts keys alphabetically at the top level', () => {
    const bytes = canonicalJson({ b: 'x', a: 'y' });
    expect(new TextDecoder().decode(bytes)).toBe('{"a":"y","b":"x"}');
  });

  it('sorts keys recursively inside nested maps', () => {
    const bytes = canonicalJson({ z: { y: 'b', x: 'a' }, a: 'c' });
    expect(new TextDecoder().decode(bytes)).toBe('{"a":"c","z":{"x":"a","y":"b"}}');
  });

  it('preserves array order', () => {
    const bytes = canonicalJson({ list: ['c', 'a', 'b'] });
    expect(new TextDecoder().decode(bytes)).toBe('{"list":["c","a","b"]}');
  });

  it('emits rawIntegerNumber() values as unquoted JSON integers', () => {
    const bytes = canonicalJson({ n: rawIntegerNumber(1), s: '1' });
    expect(new TextDecoder().decode(bytes)).toBe('{"n":1,"s":"1"}');
  });

  it('throws on naked JS numbers at the canonical-JSON boundary', () => {
    // Intentional: the signable set is integer-only; wrapping via
    // rawIntegerNumber keeps integer encoding explicit and prevents a
    // future contributor from passing a float that silently diverges
    // from Go's float encoding.
    expect(() => canonicalJson({ n: 1 })).toThrow(TypeError);
  });

  // B1 — Go-parity HTML escaping. Go's json.Marshal applies HTML-safe
  // escaping by default; TS JSON.stringify does not. This test asserts
  // the port produces the exact lowercase-hex \u escapes Go emits.
  it('escapes <, >, &, U+2028, U+2029 in lowercase hex to match Go json.Marshal', () => {
    const bytes = canonicalJson({ k: '<>&\u2028\u2029' });
    // Go emits: {"k":"\u003c\u003e\u0026\u2028\u2029"}
    // Case (lowercase hex) is load-bearing — Go uses lowercase.
    expect(new TextDecoder().decode(bytes)).toBe(
      '{"k":"\\u003c\\u003e\\u0026\\u2028\\u2029"}',
    );
  });

  it('does not double-escape quotes or backslashes (JSON.stringify defaults)', () => {
    const bytes = canonicalJson({ k: '"\\' });
    expect(new TextDecoder().decode(bytes)).toBe('{"k":"\\"\\\\"}');
  });

  it('reproduces the Veil signed-subset shape byte-for-byte', () => {
    const input = {
      certificate_id: 'veil_abc',
      request_id: 'req_123',
      protocol_version: rawIntegerNumber(2),
      claim_ids: ['clm_1', 'clm_2'],
      issued_at: '2026-04-20T05:24:12.710321721Z',
      overall_verdict: rawIntegerNumber(1),
      witness_key_id: 'witness_v1',
    };
    const bytes = canonicalJson(input);
    expect(new TextDecoder().decode(bytes)).toBe(
      '{"certificate_id":"veil_abc","claim_ids":["clm_1","clm_2"],"issued_at":"2026-04-20T05:24:12.710321721Z","overall_verdict":1,"protocol_version":2,"request_id":"req_123","witness_key_id":"witness_v1"}',
    );
  });

  it('handles empty maps and arrays', () => {
    expect(new TextDecoder().decode(canonicalJson({}))).toBe('{}');
    expect(new TextDecoder().decode(canonicalJson({ a: [] }))).toBe('{"a":[]}');
  });

  it('throws on circular references in objects', () => {
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    expect(() => canonicalJson(cyclic)).toThrow(TypeError);
  });

  it('throws on circular references in arrays', () => {
    const arr: unknown[] = [];
    arr.push(arr);
    expect(() => canonicalJson({ a: arr })).toThrow(TypeError);
  });

  it('rawIntegerNumber rejects non-safe-integer inputs', () => {
    expect(() => rawIntegerNumber(1.5)).toThrow(TypeError);
    expect(() => rawIntegerNumber(Number.NaN)).toThrow(TypeError);
    expect(() => rawIntegerNumber(Number.POSITIVE_INFINITY)).toThrow(TypeError);
    expect(() => rawIntegerNumber(Number.MAX_SAFE_INTEGER + 1)).toThrow(TypeError);
  });

  // C8 — golden cross-check against Go reference output. The hex bytes in
  // the .hex fixture are the raw output of
  // dual-sandbox-architecture/pkg/veil/canonical.go run on the same input
  // (with $rawInt markers revived as json.Number). This is the authoritative
  // faithfulness assertion — without it, the TS port proves only
  // self-consistency. Regeneration steps live in the plan at
  // docs/superpowers/plans/2026-04-20-session-2b-cert-verify.md Task 4.5.
  it('matches Go reference hex output (byte-for-byte cross-check)', () => {
    const expectedHex = readFileSync(
      join(fixturesDir, 'canonical-json-go-reference.hex'),
      'utf8',
    ).trim();
    const rawInput = JSON.parse(
      readFileSync(
        join(fixturesDir, 'canonical-json-go-reference-input.json'),
        'utf8',
      ),
    );
    const revived = reviveRawIntegers(rawInput);
    const bytes = canonicalJson(revived);
    const actualHex = Buffer.from(bytes).toString('hex');
    expect(actualHex).toBe(expectedHex);
  });
});

// Fixture JSON can't represent RawIntegerNumber natively, so we encode
// integer leaves as { $rawInt: N } and revive on load. Keeps the input
// fixture human-readable.
function reviveRawIntegers(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(reviveRawIntegers);
  if (v !== null && typeof v === 'object') {
    const obj = v as Record<string, unknown>;
    if (typeof obj.$rawInt === 'number' && Object.keys(obj).length === 1) {
      return rawIntegerNumber(obj.$rawInt);
    }
    const result: Record<string, unknown> = {};
    for (const [k, val] of Object.entries(obj)) result[k] = reviveRawIntegers(val);
    return result;
  }
  return v;
}
