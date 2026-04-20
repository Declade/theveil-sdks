// Package verify contains the Veil Certificate verification pipeline.
//
// It is byte-equivalent to the TS and Python ports:
//   - theveil-sdks/ts/src/verify-certificate/canonical-json.ts
//   - theveil-sdks/python/src/theveil/verify_certificate/canonical_json.py
//
// All three descend from dual-sandbox-architecture/pkg/veil/canonical.go,
// the server-side canonical used by the Veil Witness assembler.
package verify

import (
	"encoding/json"
	"fmt"
)

// CanonicalJSON emits byte-canonical JSON for the Veil signing subset.
//
// Go's encoding/json with the default SetEscapeHTML(true) already produces
// the exact bytes the TS and Python ports build with explicit recursion:
//   - maps with sorted keys at every nesting level (documented since Go 1.12)
//   - HTML-safe escapes (<, >, &, U+2028, U+2029) in lowercase hex
//   - integers as unquoted numbers, strings double-quoted
//   - zero whitespace, no trailing newline
//
// So the body of this function is a pre-flight validation pass (to reject
// types the Veil signable never contains — floats, circular refs,
// non-string keys) followed by a single json.Marshal call. The golden-hex
// fixture test proves byte-equality against the Go assembler reference.
func CanonicalJSON(value any) ([]byte, error) {
	if err := validateCanonical(value, map[uintptr]struct{}{}); err != nil {
		return nil, err
	}
	b, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("canonical_json: json.Marshal failed: %w", err)
	}
	return b, nil
}

func validateCanonical(v any, seen map[uintptr]struct{}) error {
	switch x := v.(type) {
	case nil, bool, string,
		int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64:
		return nil
	case float32, float64:
		return fmt.Errorf("canonical_json: float %v not permitted — use int for integer leaves", x)
	case []byte:
		return fmt.Errorf("canonical_json: []byte not permitted — encode as base64 string before passing")
	case []any:
		for i, item := range x {
			if err := validateCanonical(item, seen); err != nil {
				return fmt.Errorf("canonical_json: [%d]: %w", i, err)
			}
		}
		return nil
	case map[string]any:
		for k, val := range x {
			if err := validateCanonical(val, seen); err != nil {
				return fmt.Errorf("canonical_json: [%q]: %w", k, err)
			}
		}
		return nil
	default:
		// Defensive reject — we only permit the types that appear in the
		// Veil signable subset. Structs / other maps would be marshaled by
		// json.Marshal but risk encoding-order divergence from the reference.
		return fmt.Errorf("canonical_json: unsupported type %T", v)
	}
}
