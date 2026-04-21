package verify

// Derive the exact byte sequence the witness signs.
//
// Port of
//   dual-sandbox-architecture/services/veil-witness/internal/assembler/assembler.go:117-132
//
// CRITICAL ENCODING NOTE (resolved 2026-04-20 after contract-drift-detector
// caught it in the TS port):
//
// The Go assembler signs vr.OverallVerdict (verifier.go:56 — type string)
// DIRECTLY. vr.OverallVerdict holds short-form strings like "VERIFIED",
// NOT the proto enum integer and NOT the full-name protojson form
// "VERDICT_VERIFIED". The signable emits a JSON string (quoted) via
// canonical JSON's default string path — NOT an integer.
//
// Protojson → Go short-form mapping: the gateway emits full-name
// VERDICT_* literals on the wire (UseProtoNames + default enum
// serialization); the witness signs the short-form. The SDK must convert.

// SignableProtocolVersion is the wire protocol the signable subset is
// built against. Mirrors pipeline.SupportedProtocolVersion; these two
// constants must update in lockstep. Lifting the literal out prevents
// a future contributor from bumping one without the other.
const SignableProtocolVersion = 2

// verdictFullToShort maps the protojson full-name verdict to the Go
// assembler's short-form. Unknown values are rejected upstream as
// malformed.
var verdictFullToShort = map[string]string{
	"VERDICT_UNSPECIFIED": "UNSPECIFIED",
	"VERDICT_VERIFIED":    "VERIFIED",
	"VERDICT_PARTIAL":     "PARTIAL",
	"VERDICT_FAILED":      "FAILED",
}

// DeriveSignedBytes returns the exact byte sequence the witness signs
// over for the given certificate shape. Returns a non-nil malformed
// error if any structural / invariant constraint is violated.
//
// The pipeline.go orchestrator translates malformed errors into typed
// CertificateError with ReasonMalformed; the caller should surface them
// to users via that path.
type DeriveSignedBytesInput struct {
	CertificateID          string
	RequestID              string
	ClaimRequestIDs        []string // one per claim, in order
	ClaimIDs               []string // one per claim, in order
	IssuedAt               string
	OverallVerdictFullName string // e.g. "VERDICT_VERIFIED"
	WitnessKeyID           string
}

// MalformedError is the narrow error returned by DeriveSignedBytes on
// structural issues. The orchestrator wraps it as a CertificateError with
// ReasonMalformed.
type MalformedError struct {
	Reason string
}

func (e *MalformedError) Error() string { return e.Reason }

// DeriveSignedBytes builds the exact byte sequence the witness signs.
func DeriveSignedBytes(in DeriveSignedBytesInput) ([]byte, error) {
	if len(in.ClaimRequestIDs) == 0 || len(in.ClaimIDs) == 0 {
		return nil, &MalformedError{
			Reason: "cert.claims is empty — certificate must contain at least one claim",
		}
	}
	if len(in.ClaimRequestIDs) != len(in.ClaimIDs) {
		return nil, &MalformedError{
			Reason: "cert.claims length mismatch between request_ids and claim_ids — SDK bug",
		}
	}
	if in.ClaimRequestIDs[0] != in.RequestID {
		return nil, &MalformedError{
			Reason: "cert.request_id does not match cert.claims[0].request_id (gateway invariant violated)",
		}
	}
	goShortForm, ok := verdictFullToShort[in.OverallVerdictFullName]
	if !ok {
		return nil, &MalformedError{
			Reason: "unknown verification.overall_verdict literal: " + in.OverallVerdictFullName +
				" — SDK may be out of date",
		}
	}

	// The signable map mirrors assembler.go:117-125 field-for-field.
	// protocol_version: Go int 2 → JSON integer 2.
	// overall_verdict: Go short string → JSON quoted string (default path).
	// All other fields are strings or string arrays, pass-through.
	claimIDsAny := make([]any, len(in.ClaimIDs))
	for i, id := range in.ClaimIDs {
		claimIDsAny[i] = id
	}
	signable := map[string]any{
		"certificate_id":   in.CertificateID,
		"request_id":       in.RequestID,
		"protocol_version": SignableProtocolVersion,
		"claim_ids":        claimIDsAny,
		"issued_at":        in.IssuedAt,
		"overall_verdict":  goShortForm,
		"witness_key_id":   in.WitnessKeyID,
	}
	return CanonicalJSON(signable)
}
