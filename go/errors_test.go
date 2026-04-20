package theveil

import (
	"errors"
	"strings"
	"testing"
)

func TestConfigError_Error(t *testing.T) {
	err := &ConfigError{Message: "bad"}
	if !strings.HasPrefix(err.Error(), "theveil: ") {
		t.Errorf("Error() must prefix with 'theveil: ', got %q", err.Error())
	}
}

func TestHTTPError_StatusAndBody(t *testing.T) {
	err := &HTTPError{Status: 401, Body: map[string]any{"code": "nope"}, Message: "unauthorized"}
	if err.Status != 401 {
		t.Errorf("status = %d, want 401", err.Status)
	}
	if _, ok := err.Body.(map[string]any); !ok {
		t.Errorf("body should be map[string]any, got %T", err.Body)
	}
}

func TestHTTPError_Unwrap(t *testing.T) {
	inner := errors.New("inner")
	err := &HTTPError{Status: 500, Err: inner}
	if !errors.Is(err, inner) {
		t.Errorf("errors.Is should unwrap to inner")
	}
}

func TestCertificateError_Error_WithID(t *testing.T) {
	err := &CertificateError{
		Reason:        ReasonInvalidSignature,
		CertificateID: "veil_xyz",
		Message:       "bad",
	}
	msg := err.Error()
	if !strings.Contains(msg, "invalid_signature") {
		t.Errorf("message should include reason: %q", msg)
	}
	if !strings.Contains(msg, "veil_xyz") {
		t.Errorf("message should include certificate_id: %q", msg)
	}
}

func TestCertificateError_Error_WithoutID(t *testing.T) {
	err := &CertificateError{
		Reason:  ReasonMalformed,
		Message: "bad",
	}
	msg := err.Error()
	if !strings.Contains(msg, "malformed") {
		t.Errorf("message should include reason: %q", msg)
	}
	if strings.Contains(msg, "certificate_id=") {
		t.Errorf("message should not include empty certificate_id: %q", msg)
	}
}

func TestTimeoutError_Unwrap(t *testing.T) {
	inner := errors.New("deadline")
	err := &TimeoutError{Message: "slow", Err: inner}
	if !errors.Is(err, inner) {
		t.Errorf("errors.Is should unwrap to inner")
	}
}

func TestAllErrorsSatisfyErrorInterface(t *testing.T) {
	var _ Error = &ConfigError{}
	var _ Error = &HTTPError{}
	var _ Error = &TimeoutError{}
	var _ Error = &NetworkError{}
	var _ Error = &CertificateError{}
}

func TestErrorsAs_HTTPError(t *testing.T) {
	err := error(&HTTPError{Status: 401, Message: "nope"})
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("errors.As should succeed")
	}
	if httpErr.Status != 401 {
		t.Errorf("status = %d, want 401", httpErr.Status)
	}
}

func TestErrorsAs_CertificateError(t *testing.T) {
	err := error(&CertificateError{Reason: ReasonMalformed, Message: "bad"})
	var certErr *CertificateError
	if !errors.As(err, &certErr) {
		t.Fatalf("errors.As should succeed")
	}
	if certErr.Reason != ReasonMalformed {
		t.Errorf("reason = %q, want malformed", certErr.Reason)
	}
}
