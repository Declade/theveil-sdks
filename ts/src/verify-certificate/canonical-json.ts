// Port of dual-sandbox-architecture/pkg/veil/canonical.go.
//
// TODO(proxy-sync): keep in lockstep with
//   dual-sandbox-architecture/pkg/veil/canonical.go
// Contract-drift-detector enforcement: any change to the Go source must land
// here in the same arc. The related gateway invariant
//   cert.request_id === cert.claims[0].request_id
// is enforced defensively in ./signable.ts — if the gateway ever breaks that
// invariant, both files need review.
//
// This is NOT RFC 8785 JCS. It is the witness's signing algorithm:
//   - recursive sorted keys at every map depth (Go sort.Strings, byte-wise
//     over UTF-8; TS Array.prototype.sort on string keys matches for ASCII)
//   - leaves through JSON.stringify, then HTML-safe post-processing to match
//     Go's default json.Marshal HTML escaping
//   - integers-as-integers via the rawIntegerNumber branded type; naked JS
//     numbers throw at the boundary
// Output: zero whitespace, no trailing newline, UTF-8 bytes.
//
// Array-of-maps behaviour (N-new-5 probe in canonical-json-go-reference.hex):
// Go's marshalSorted does NOT recurse into arrays — arrays delegate to
// json.Marshal. json.Marshal's default behaviour on map[string]any IS to
// sort keys alphabetically (documented since Go 1.12), so Go and TS both
// produce identical bytes for arrays-of-maps even though the TS port
// reaches sorted-keys through explicit recursion. The probe in the
// golden-hex fixture locks this agreement in: if Go's behaviour ever
// changes (or the TS recursion is removed), the test fires.

const RAW_INT_BRAND = Symbol('RawIntegerNumber');

export interface RawIntegerNumber {
  readonly [RAW_INT_BRAND]: true;
  readonly value: string;
}

/**
 * Narrow helper: emit a JS integer as a raw JSON number (unquoted). Matches
 * Go's json.Marshal(int) output for integers. Rejects non-finite, non-integer,
 * and values outside the JS-safe-integer range.
 *
 * This is the only such helper the SDK exposes. Floats were intentionally
 * excluded — Go's json.Marshal float formatting diverges from JS's for many
 * values, and the Veil signed subset carries no floats.
 */
export function rawIntegerNumber(n: number): RawIntegerNumber {
  if (!Number.isSafeInteger(n)) {
    // Number.isSafeInteger implies Number.isInteger and rejects NaN/Infinity.
    throw new TypeError(`rawIntegerNumber: not a safe integer: ${n}`);
  }
  return { [RAW_INT_BRAND]: true, value: String(n) };
}

function isRawIntegerNumber(v: unknown): v is RawIntegerNumber {
  return (
    typeof v === 'object' &&
    v !== null &&
    (v as Record<symbol, unknown>)[RAW_INT_BRAND] === true
  );
}

export function canonicalJson(value: unknown): Uint8Array {
  const seen = new WeakSet<object>();
  const s = marshalSorted(value, seen);
  return new TextEncoder().encode(s);
}

// HTML-safe escape to match Go's default json.Marshal. Lowercase hex —
// case and exact char set are load-bearing.
function escapeHtmlSafe(jsonString: string): string {
  return jsonString
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/&/g, '\\u0026')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
}

function stringifyLeaf(s: string): string {
  return escapeHtmlSafe(JSON.stringify(s));
}

function marshalSorted(v: unknown, seen: WeakSet<object>): string {
  if (isRawIntegerNumber(v)) return v.value;
  if (v === null) return 'null';
  if (typeof v === 'boolean') return v ? 'true' : 'false';
  if (typeof v === 'number') {
    // Defensive: refuse raw JS numbers at the canonical-JSON boundary. All
    // integer leaves must use rawIntegerNumber; all strings stay strings.
    // This prevents accidental float-encoding divergence between JS and Go.
    throw new TypeError(
      `canonicalJson: raw number ${v} — wrap with rawIntegerNumber() for integers, or pass as string`,
    );
  }
  if (typeof v === 'string') return stringifyLeaf(v);
  if (Array.isArray(v)) {
    if (seen.has(v)) {
      throw new TypeError('canonicalJson: circular reference in array');
    }
    seen.add(v);
    const parts = v.map((item) => marshalSorted(item, seen));
    seen.delete(v);
    return `[${parts.join(',')}]`;
  }
  if (typeof v === 'object') {
    if (seen.has(v as object)) {
      throw new TypeError('canonicalJson: circular reference in object');
    }
    seen.add(v as object);
    const obj = v as Record<string, unknown>;
    // Byte-wise string sort matches Go sort.Strings for ASCII keys. The
    // 7-field Veil signable set is ASCII-only; a future signed field with
    // non-ASCII keys would require switching to a bytewise-UTF-8 sort.
    const keys = Object.keys(obj).sort();
    const parts = keys.map(
      (k) => `${stringifyLeaf(k)}:${marshalSorted(obj[k], seen)}`,
    );
    seen.delete(v as object);
    return `{${parts.join(',')}}`;
  }
  throw new TypeError(`canonicalJson: unsupported value type ${typeof v}`);
}
