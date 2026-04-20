package verify

import (
	"crypto/ed25519"
)

// VerifyEd25519 returns true on valid signature, false on invalid.
// Returns a normalization error if publicKey is malformed; the caller
// wraps it as a CertificateError with ReasonInvalidSignature.
func VerifyEd25519(message, signature []byte, publicKey any) (bool, error) {
	raw, err := NormalizeEd25519PublicKey(publicKey)
	if err != nil {
		return false, err
	}
	if len(signature) != ed25519.SignatureSize {
		// ed25519.Verify returns false silently on wrong-length signatures;
		// surface the precondition explicitly so tests lock in the invariant.
		return false, nil
	}
	return ed25519.Verify(ed25519.PublicKey(raw), message, signature), nil
}
