//go:build ignore
// Go cert oracle — produces a VeilCertificate JSON fixture with a
// witness_signature computed via the ACTUAL Go assembler's signable
// construction + veil.CanonicalJSON. The TS verifyCertificate is expected
// to successfully verify this fixture using the committed test public key.
//
// Usage:
//
//	cd /path/to/dual-sandbox-architecture
//	go run /path/to/theveil-sdks/ts/src/verify-certificate/__fixtures__/gen-cert-oracle.go
//
// Exits with "DETERMINISM MISMATCH" and non-zero status if running the
// canonical JSON + signing pipeline twice on identical input produces
// byte-different output. This is an in-process assertion — not manual.
// If it fires, do NOT paper over with a regeneration; root-cause.
//
// Why this fixture exists (N-new-5b lesson, recorded 2026-04-20): the
// earlier canonical-json golden fixture tested canonicalJson in isolation
// on synthetic input. The TS side signed its own test fixtures via the
// same buggy signable.ts, forming a closed TS→TS loop that agreed with
// itself while disagreeing with Go on the overall_verdict encoding (Go
// signs a short-form string; TS was signing an int). Only an oracle that
// runs the actual Go assembler logic catches that class of bug.
//
// This file is build-tagged `ignore` so it never compiles into a Go build.
// It mirrors assembler.go:117-125 and depends on pkg/veil.
package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/Declade/dual-sandbox-architecture/pkg/veil"
)

// The input fixture encodes the fields the signable needs plus the cert
// envelope to be emitted. Synthetic test data only.
type oracleInput struct {
	CertificateID   string   `json:"certificate_id"`
	RequestID       string   `json:"request_id"`
	ProtocolVersion int      `json:"protocol_version"`
	ClaimIDs        []string `json:"claim_ids"`
	IssuedAt        string   `json:"issued_at"`
	OverallVerdict  string   `json:"overall_verdict"` // short form, e.g. "VERIFIED"
	WitnessKeyID    string   `json:"witness_key_id"`
}

// deriveSignedBytes mirrors services/veil-witness/internal/assembler/
// assembler.go:117-125. If that assembler ever changes, this oracle must
// be updated in lockstep.
func deriveSignedBytes(in *oracleInput) []byte {
	signable := map[string]any{
		"certificate_id":   in.CertificateID,
		"request_id":       in.RequestID,
		"protocol_version": in.ProtocolVersion,
		"claim_ids":        in.ClaimIDs,
		"issued_at":        in.IssuedAt,
		"overall_verdict":  in.OverallVerdict,
		"witness_key_id":   in.WitnessKeyID,
	}
	out, err := veil.CanonicalJSON(signable)
	if err != nil {
		fatalf("canonicalize: %v", err)
	}
	return out
}

type testKeypair struct {
	PublicKey  string `json:"publicKey"`
	PrivateKey string `json:"privateKey"`
}

func main() {
	_, thisFile, _, _ := runtime.Caller(0)
	dir := filepath.Dir(thisFile)

	inputPath := filepath.Join(dir, "cert-oracle-input.json")
	keypairPath := filepath.Join(dir, "test-witness-keypair.json")
	outputPath := filepath.Join(dir, "cert-go-signed-reference.json")

	var in oracleInput
	must(readJSON(inputPath, &in), "read cert-oracle-input.json")

	var kp testKeypair
	must(readJSON(keypairPath, &kp), "read test-witness-keypair.json")

	privBytes, err := base64.StdEncoding.DecodeString(kp.PrivateKey)
	if err != nil || len(privBytes) != ed25519.PrivateKeySize {
		fatalf("invalid test private key: err=%v len=%d", err, len(privBytes))
	}
	priv := ed25519.PrivateKey(privBytes)

	// Determinism check: derive+sign twice, assert byte-identical. Ed25519
	// signing is deterministic per RFC 8032 so this should never fail with
	// stable input + stable key; if it does, it means veil.CanonicalJSON
	// grew a non-deterministic code path (e.g., map iteration on a type
	// it now pretends to handle).
	sig1 := ed25519.Sign(priv, deriveSignedBytes(&in))
	sig2 := ed25519.Sign(priv, deriveSignedBytes(&in))
	if !bytes.Equal(sig1, sig2) {
		fatalf("DETERMINISM MISMATCH: two runs of derive+sign produced different bytes. Root-cause before regenerating.")
	}

	// Also produce a second canonical-JSON byte slice for a sanity hex
	// dump in the fixture — useful when debugging future TS drift.
	canonical1 := deriveSignedBytes(&in)
	canonical2 := deriveSignedBytes(&in)
	if !bytes.Equal(canonical1, canonical2) {
		fatalf("DETERMINISM MISMATCH on canonical JSON output")
	}

	// Build a minimal VeilCertificate protojson-shaped object for the
	// fixture. Only the fields the TS verifier reads are populated; the
	// rest can be filled in as opaque nulls or minimal values. If future
	// TS verifier reads grow, this shape must too.
	claims := make([]map[string]any, len(in.ClaimIDs))
	for i, id := range in.ClaimIDs {
		claims[i] = map[string]any{
			"claim_id":          id,
			"request_id":        in.RequestID,
			"service_id":        "dsa-test",
			"claim_type":        "CLAIM_TYPE_UNSPECIFIED",
			"data_seen":         []string{},
			"data_not_seen":     []string{},
			"canonical_payload": base64.StdEncoding.EncodeToString([]byte("{}")),
			"timestamp":         in.IssuedAt,
			"signature":         base64.StdEncoding.EncodeToString(make([]byte, 64)),
		}
	}

	cert := map[string]any{
		"certificate_id":   in.CertificateID,
		"request_id":       in.RequestID,
		"protocol_version": in.ProtocolVersion,
		"claims":           claims,
		"verification": map[string]any{
			"signatures_valid":            true,
			"completeness":                "COMPLETENESS_FULL",
			"missing_services":            []string{},
			"temporal_consistent":         true,
			"data_visibility_consistent":  true,
			"isolation_verified":          true,
			"qi_score":                    nil,
			"overall_verdict":             shortToFullName(in.OverallVerdict),
		},
		"issued_at":           in.IssuedAt,
		"formal_verification": nil,
		"audit_integrity":     nil,
		"privacy_budget":      nil,
		"witness_signature":   base64.StdEncoding.EncodeToString(sig1),
		"witness_key_id":      in.WitnessKeyID,
		"attestation": map[string]any{
			"timestamp":        nil,
			"transparency_log": nil,
			"notary": map[string]any{
				"provider":              "dsa-veil-witness",
				"notary_signature":      base64.StdEncoding.EncodeToString(sig1),
				"notary_public_key_id":  in.WitnessKeyID,
				"checks_performed":      []string{"canonical_json_signing"},
				"attested_at":           nil,
			},
		},
		"anchor_status": map[string]any{
			"status":      "ANCHOR_STATUS_ANCHORED",
			"attempts":    1,
			"last_error":  "",
			"human_note":  "",
		},
	}

	// Include a debug probe so future drift investigations can see exactly
	// what bytes were signed, without re-running the oracle.
	cert["_debug_signed_canonical"] = base64.StdEncoding.EncodeToString(canonical1)

	f, err := os.Create(outputPath)
	must(err, "create output")
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	// Don't HTML-escape the JSON output; we're writing a plain file.
	enc.SetEscapeHTML(false)
	must(enc.Encode(cert), "encode output JSON")

	fmt.Fprintf(os.Stderr, "wrote %s (signature %d bytes, canonical %d bytes)\n",
		outputPath, len(sig1), len(canonical1))
}

// shortToFullName converts the Go verifier's short-form string to the
// gateway's full-name protojson enum form (what the SDK receives on the
// wire). Mirrors protojson's default enum serialization.
func shortToFullName(short string) string {
	switch short {
	case "VERIFIED":
		return "VERDICT_VERIFIED"
	case "PARTIAL":
		return "VERDICT_PARTIAL"
	case "FAILED":
		return "VERDICT_FAILED"
	case "UNSPECIFIED":
		return "VERDICT_UNSPECIFIED"
	default:
		fatalf("unknown verdict short-form: %q", short)
		return ""
	}
}

func readJSON(path string, out any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	raw, err := io.ReadAll(f)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

func must(err error, what string) {
	if err != nil {
		fatalf("%s: %v", what, err)
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "gen-cert-oracle: "+format+"\n", args...)
	os.Exit(1)
}
