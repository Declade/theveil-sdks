package verify

import (
	"encoding/base64"
	"fmt"
)

// NormalizeEd25519PublicKey accepts a raw 32-byte key ([]byte) or a base64
// string encoding those 32 bytes. Rejects PEM SPKI, hex, and other formats.
// The caller wraps the returned error as a CertificateError with
// ReasonInvalidSignature so a malformed key still surfaces as a typed
// SDK error.
func NormalizeEd25519PublicKey(input any) ([]byte, error) {
	var raw []byte
	switch v := input.(type) {
	case []byte:
		raw = v
	case string:
		b, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, fmt.Errorf("ed25519 public key base64 decode failed: %w", err)
		}
		raw = b
	case nil:
		return nil, fmt.Errorf("ed25519 public key is nil")
	default:
		return nil, fmt.Errorf("ed25519 public key must be []byte or base64 string, got %T", input)
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("ed25519 public key must be 32 bytes, got %d", len(raw))
	}
	return raw, nil
}
