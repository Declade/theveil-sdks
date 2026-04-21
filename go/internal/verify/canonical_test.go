package verify

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func tsFixturesDir(t *testing.T) string {
	t.Helper()
	// go/internal/verify → go → monorepo root.
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	// cwd is theveil-sdks/go/internal/verify; the monorepo root is three up.
	root := filepath.Join(cwd, "..", "..", "..")
	fixtures := filepath.Join(root, "ts", "src", "verify-certificate", "__fixtures__")
	info, err := os.Stat(fixtures)
	if err != nil || !info.IsDir() {
		t.Fatalf("expected TS fixtures at %s: %v", fixtures, err)
	}
	return fixtures
}

// reviveRawIntegers mirrors the TS/Python reviver: {"$rawInt": N} → N.
// Go's int type is sufficient; no branded wrapper needed. Because the
// input JSON carries integers as objects (not numbers), Go's json.Unmarshal
// decodes them as map[string]any with a float64 value; we cast to int.
func reviveRawIntegers(v any) any {
	switch x := v.(type) {
	case []any:
		for i, item := range x {
			x[i] = reviveRawIntegers(item)
		}
		return x
	case map[string]any:
		if len(x) == 1 {
			if raw, ok := x["$rawInt"]; ok {
				if f, ok := raw.(float64); ok {
					return int(f)
				}
			}
		}
		for k, val := range x {
			x[k] = reviveRawIntegers(val)
		}
		return x
	default:
		return v
	}
}

func TestCanonicalJSON_SortsKeysAtTopLevel(t *testing.T) {
	out, err := CanonicalJSON(map[string]any{"b": "x", "a": "y"})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(out), `{"a":"y","b":"x"}`; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestCanonicalJSON_SortsKeysRecursively(t *testing.T) {
	out, err := CanonicalJSON(map[string]any{
		"z": map[string]any{"y": "b", "x": "a"},
		"a": "c",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(out), `{"a":"c","z":{"x":"a","y":"b"}}`; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestCanonicalJSON_PreservesArrayOrder(t *testing.T) {
	out, err := CanonicalJSON(map[string]any{"list": []any{"c", "a", "b"}})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(out), `{"list":["c","a","b"]}`; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestCanonicalJSON_IntLeavesUnquoted(t *testing.T) {
	out, err := CanonicalJSON(map[string]any{"n": 1, "s": "1"})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(out), `{"n":1,"s":"1"}`; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestCanonicalJSON_RejectsFloats(t *testing.T) {
	_, err := CanonicalJSON(map[string]any{"n": 1.5})
	if err == nil {
		t.Fatal("expected error on float")
	}
	if !strings.Contains(err.Error(), "float") {
		t.Fatalf("error should mention 'float': %v", err)
	}
}

func TestCanonicalJSON_HTMLEscapesInLowercaseHex(t *testing.T) {
	out, err := CanonicalJSON(map[string]any{"k": "<>&\u2028\u2029"})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"k":"\u003c\u003e\u0026\u2028\u2029"}`
	if got := string(out); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestCanonicalJSON_QuotesAndBackslashes(t *testing.T) {
	out, err := CanonicalJSON(map[string]any{"k": "\"\\"})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"k":"\"\\"}`
	if got := string(out); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestCanonicalJSON_EmptyMapAndArray(t *testing.T) {
	out, err := CanonicalJSON(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "{}" {
		t.Fatalf("got %q, want {}", string(out))
	}
	out, err = CanonicalJSON(map[string]any{"a": []any{}})
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != `{"a":[]}` {
		t.Fatalf("got %q, want {\"a\":[]}", string(out))
	}
}

func TestCanonicalJSON_RejectsBytes(t *testing.T) {
	_, err := CanonicalJSON(map[string]any{"a": []byte("payload")})
	if err == nil || !strings.Contains(err.Error(), "[]byte") {
		t.Fatalf("expected []byte rejection, got %v", err)
	}
}

func TestCanonicalJSON_RejectsUnsupportedTypes(t *testing.T) {
	_, err := CanonicalJSON(map[string]any{"a": struct{ X int }{1}})
	if err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("expected unsupported-type error, got %v", err)
	}
}

// Golden cross-check against the Go-assembler reference hex. Any byte
// divergence here means the Go SDK canonical disagrees with the server-
// side canonical, which produces invalid_signature on valid certs.
func TestCanonicalJSON_MatchesGoReferenceHex(t *testing.T) {
	fixtures := tsFixturesDir(t)

	inputBytes, err := os.ReadFile(filepath.Join(fixtures, "canonical-json-go-reference-input.json"))
	if err != nil {
		t.Fatal(err)
	}
	var raw any
	if err := json.Unmarshal(inputBytes, &raw); err != nil {
		t.Fatal(err)
	}
	revived := reviveRawIntegers(raw)

	hexBytes, err := os.ReadFile(filepath.Join(fixtures, "canonical-json-go-reference.hex"))
	if err != nil {
		t.Fatal(err)
	}
	expectedHex := strings.TrimSpace(string(hexBytes))

	out, err := CanonicalJSON(revived)
	if err != nil {
		t.Fatal(err)
	}
	actualHex := hex.EncodeToString(out)
	if actualHex != expectedHex {
		t.Fatalf("canonical-JSON byte-equality failed:\n  got:  %s\n  want: %s\n  got-bytes:  %s\n  want-bytes: %s",
			actualHex, expectedHex, string(out), "<see hex>")
	}
}
