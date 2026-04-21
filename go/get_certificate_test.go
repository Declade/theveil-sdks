package theveil

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newMockedClient returns a client whose baseURL points at httptest.Server's
// URL. Use the returned cleanup func via defer.
func newMockedClient(t *testing.T, handler http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(handler)
	c, err := New(validAPIKey, WithBaseURL(server.URL))
	if err != nil {
		server.Close()
		t.Fatalf("New: %v", err)
	}
	return c, server
}

// -- Happy path ----------------------------------------------------------

func TestGetCertificate_HappyPath(t *testing.T) {
	cert := loadFixture(t, "cert-valid-anchored.json")
	requestID := cert["request_id"].(string)

	handler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %q, want GET", r.Method)
		}
		if r.URL.Path != "/api/v1/veil/certificate/"+requestID {
			t.Errorf("path = %q", r.URL.Path)
		}
		if r.Header.Get("x-api-key") != validAPIKey {
			t.Errorf("x-api-key missing or wrong")
		}
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(cert)
	}

	c, server := newMockedClient(t, handler)
	defer server.Close()

	got, err := c.GetCertificate(context.Background(), requestID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.CertificateID != cert["certificate_id"].(string) {
		t.Errorf("CertificateID = %q", got.CertificateID)
	}
	if got.WitnessKeyID != "witness_v1" {
		t.Errorf("WitnessKeyID = %q", got.WitnessKeyID)
	}
}

// -- 202 pending ---------------------------------------------------------

func TestGetCertificate_PendingRaisesHTTPErrorWith202(t *testing.T) {
	pendingBody := map[string]any{
		"status":              "pending",
		"request_id":          "req_pending_0001",
		"message":             "Veil certificate is not ready yet.",
		"retry_after_seconds": 30,
	}
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(pendingBody)
	}
	c, server := newMockedClient(t, handler)
	defer server.Close()

	_, err := c.GetCertificate(context.Background(), "req_pending_0001")
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("want HTTPError, got %T (%v)", err, err)
	}
	if httpErr.Status != 202 {
		t.Errorf("status = %d, want 202", httpErr.Status)
	}
	body, ok := httpErr.Body.(map[string]any)
	if !ok {
		t.Fatalf("body type = %T, want map[string]any", httpErr.Body)
	}
	if s, _ := body["status"].(string); s != "pending" {
		t.Errorf("body.status = %v", body["status"])
	}
	if r, _ := body["retry_after_seconds"].(float64); r != 30 {
		t.Errorf("body.retry_after_seconds = %v", body["retry_after_seconds"])
	}
}

// -- HTTP error mapping --------------------------------------------------

func TestGetCertificate_MapsStatusAndCode(t *testing.T) {
	cases := []struct {
		status int
		code   string
	}{
		{401, "missing_api_key"},
		{401, "invalid_api_key"},
		{403, "tier_insufficient"},
		{404, "veil_not_configured"},
		{502, "upstream_error"},
	}
	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			body := map[string]any{
				"error": map[string]any{
					"code":    tc.code,
					"message": "test " + tc.code,
				},
			}
			handler := func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("content-type", "application/json")
				w.WriteHeader(tc.status)
				_ = json.NewEncoder(w).Encode(body)
			}
			c, server := newMockedClient(t, handler)
			defer server.Close()

			_, err := c.GetCertificate(context.Background(), "req_err_0001")
			var httpErr *HTTPError
			if !errors.As(err, &httpErr) {
				t.Fatalf("want HTTPError, got %T", err)
			}
			if httpErr.Status != tc.status {
				t.Errorf("status = %d, want %d", httpErr.Status, tc.status)
			}
			b, _ := httpErr.Body.(map[string]any)
			e, _ := b["error"].(map[string]any)
			if e["code"] != tc.code {
				t.Errorf("body.error.code = %v", e["code"])
			}
		})
	}
}

func TestGetCertificate_503_RetryAfterInBody(t *testing.T) {
	body := map[string]any{
		"error": map[string]any{
			"code":                "veil_unavailable",
			"message":             "Veil Witness is temporarily unavailable.",
			"retry_after_seconds": 30,
		},
	}
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(503)
		_ = json.NewEncoder(w).Encode(body)
	}
	c, server := newMockedClient(t, handler)
	defer server.Close()

	_, err := c.GetCertificate(context.Background(), "req_unavail")
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("want HTTPError, got %T", err)
	}
	if httpErr.Status != 503 {
		t.Errorf("status = %d", httpErr.Status)
	}
	b, _ := httpErr.Body.(map[string]any)
	e, _ := b["error"].(map[string]any)
	if r, _ := e["retry_after_seconds"].(float64); r != 30 {
		t.Errorf("retry_after_seconds = %v", e["retry_after_seconds"])
	}
}

// -- Transport errors ----------------------------------------------------

func TestGetCertificate_NetworkErrorWrapsToNetworkError(t *testing.T) {
	// Closed server → connection refused.
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := server.URL
	server.Close()

	c, err := New(validAPIKey, WithBaseURL(url))
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.GetCertificate(context.Background(), "req_network_0001")
	var netErr *NetworkError
	if !errors.As(err, &netErr) {
		t.Fatalf("want NetworkError, got %T (%v)", err, err)
	}
	// Should NOT also be an HTTPError.
	var httpErr *HTTPError
	if errors.As(err, &httpErr) {
		t.Error("should not also be HTTPError")
	}
}

// -- Timeout + cancellation ---------------------------------------------

func TestGetCertificate_PerCallTimeout(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		// Bounded wait — r.Context() cancellation propagation can lag due
		// to keep-alive/transport pooling; the client-side deadline fires
		// well before this bound.
		select {
		case <-r.Context().Done():
		case <-time.After(500 * time.Millisecond):
		}
	}
	c, server := newMockedClient(t, handler)
	defer server.Close()

	_, err := c.GetCertificate(
		context.Background(),
		"req_slow_0001",
		WithCallTimeout(10*time.Millisecond),
	)
	var timeoutErr *TimeoutError
	if !errors.As(err, &timeoutErr) {
		t.Fatalf("want TimeoutError, got %T (%v)", err, err)
	}
}

func TestGetCertificate_CallerCancelPropagates(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(500 * time.Millisecond):
		}
	}
	c, server := newMockedClient(t, handler)
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel

	_, err := c.GetCertificate(ctx, "req_cancel_0001")
	// Caller cancel surfaces as NetworkError with ctx.Canceled unwrapped.
	var netErr *NetworkError
	if !errors.As(err, &netErr) {
		t.Fatalf("want NetworkError, got %T", err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("errors.Is(err, context.Canceled) should be true")
	}
}

// -- Path encoding ------------------------------------------------------

func TestGetCertificate_PercentEncodesReservedChars(t *testing.T) {
	cert := loadFixture(t, "cert-valid-anchored.json")
	var observedPath string
	handler := func(w http.ResponseWriter, r *http.Request) {
		// Grab the raw request URI to see the encoded form (r.URL.Path is
		// decoded by net/http's mux). RawPath preserves encoding.
		observedPath = r.URL.EscapedPath()
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(cert)
	}
	c, server := newMockedClient(t, handler)
	defer server.Close()

	_, err := c.GetCertificate(context.Background(), "req/weird id?")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(observedPath, "%2F") || !strings.Contains(observedPath, "%20") {
		t.Errorf("encoded path missing %%2F / %%20: %q", observedPath)
	}
	if strings.Contains(observedPath, "req/weird id?") {
		t.Errorf("encoded path should not contain raw form: %q", observedPath)
	}
}

func TestGetCertificate_RejectsEmptyRequestID(t *testing.T) {
	c, err := New(validAPIKey)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.GetCertificate(context.Background(), "")
	var cfgErr *ConfigError
	if !errors.As(err, &cfgErr) {
		t.Fatalf("want ConfigError, got %T", err)
	}
}

// -- MaxResponseBytes enforcement ---------------------------------------

func TestGetCertificate_ResponseLargerThanCap_RaisesHTTPError(t *testing.T) {
	big := strings.Repeat("x", 1024)
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "text/plain")
		_, _ = w.Write([]byte(big))
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()
	c, err := New(
		validAPIKey,
		WithBaseURL(server.URL),
		WithMaxResponseBytes(256), // deliberately small
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.GetCertificate(context.Background(), "req_big")
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("want HTTPError, got %T (%v)", err, err)
	}
	if !strings.Contains(httpErr.Message, "MaxResponseBytes") {
		t.Errorf("message should mention cap: %q", httpErr.Message)
	}
}

func TestGetCertificate_ResponseUnderCap_Accepted(t *testing.T) {
	cert := loadFixture(t, "cert-valid-anchored.json")
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(cert)
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()
	c, err := New(
		validAPIKey,
		WithBaseURL(server.URL),
		WithMaxResponseBytes(1024*1024), // 1 MiB, ample
	)
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.GetCertificate(context.Background(), cert["request_id"].(string))
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if got.CertificateID != cert["certificate_id"].(string) {
		t.Errorf("CertificateID mismatch")
	}
}

// -- Header merge (SDK-owned keys win) ----------------------------------

func TestGetCertificate_CallerHeadersMerged_SDKKeysWin(t *testing.T) {
	cert := loadFixture(t, "cert-valid-anchored.json")
	var observedAPIKey, observedCorr, observedContentType string
	handler := func(w http.ResponseWriter, r *http.Request) {
		observedAPIKey = r.Header.Get("x-api-key")
		observedCorr = r.Header.Get("x-correlation-id")
		observedContentType = r.Header.Get("content-type")
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(cert)
	}
	c, server := newMockedClient(t, handler)
	defer server.Close()

	_, err := c.GetCertificate(
		context.Background(),
		"req_headers",
		WithCallHeader("x-correlation-id", "corr_abc"),
		WithCallHeader("x-api-key", "dsa_"+strings.Repeat("f", 32)),
		WithCallHeader("content-type", "text/plain"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if observedCorr != "corr_abc" {
		t.Errorf("x-correlation-id = %q", observedCorr)
	}
	if observedAPIKey != validAPIKey {
		t.Errorf("x-api-key = %q, want SDK-owned %q", observedAPIKey, validAPIKey)
	}
	if observedContentType != "application/json" {
		t.Errorf("content-type = %q, want SDK-owned", observedContentType)
	}
}

// -- Malformed 200 body -------------------------------------------------

func TestGetCertificate_Malformed200_NonJSON(t *testing.T) {
	// Non-JSON 2xx body fails decodeInto (json.Marshal + Unmarshal round
	// trip chokes on a non-JSON string) and surfaces via the dedicated
	// *ResponseValidationError — NOT *HTTPError, which is reserved for
	// non-2xx transport failures.
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "text/plain")
		_, _ = w.Write([]byte("not json at all"))
	}
	c, server := newMockedClient(t, handler)
	defer server.Close()

	_, err := c.GetCertificate(context.Background(), "req_malformed_0001")
	var vErr *ResponseValidationError
	if !errors.As(err, &vErr) {
		t.Fatalf("want *ResponseValidationError, got %T (%v)", err, err)
	}
	if string(vErr.Body) != "not json at all" {
		t.Errorf("body = %q", string(vErr.Body))
	}
	// Invariant: must NOT also be an *HTTPError — semantic distinction.
	var httpErr *HTTPError
	if errors.As(err, &httpErr) {
		t.Errorf("should not also be *HTTPError: %v", httpErr)
	}
	// Still satisfies the base Error interface so callers doing blanket
	// theveil.Error type switches still catch it.
	var base Error
	if !errors.As(err, &base) {
		t.Errorf("should satisfy theveil.Error interface")
	}
	// Underlying json error preserved via Unwrap.
	if vErr.Err == nil {
		t.Errorf("Err should wrap the underlying json error")
	}
}

func TestGetCertificate_Non2xx_UsesHTTPErrorNotResponseValidation(t *testing.T) {
	// Invariant: non-2xx MUST still raise *HTTPError, not
	// *ResponseValidationError. The new class must never fire for
	// transport-level failures.
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(404)
		_, _ = w.Write([]byte(`{"error": {"code": "veil_not_configured"}}`))
	}
	c, server := newMockedClient(t, handler)
	defer server.Close()

	_, err := c.GetCertificate(context.Background(), "req_missing")
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("want *HTTPError, got %T", err)
	}
	if httpErr.Status != 404 {
		t.Errorf("status = %d", httpErr.Status)
	}
	var vErr *ResponseValidationError
	if errors.As(err, &vErr) {
		t.Errorf("should not also be *ResponseValidationError")
	}
}

func TestGetCertificate_Malformed200_MissingRequiredFields(t *testing.T) {
	// Go's json.Unmarshal is permissive on missing fields (zero-values
	// them) — so the decode itself succeeds on a valid JSON object that
	// happens to lack required cert fields. This documents the current
	// behaviour: no *ResponseValidationError fires here because the
	// underlying json.Unmarshal didn't fail. The caller's subsequent
	// VerifyCertificate call rejects the zero-valued result with
	// ReasonMalformed, per the thin-transport contract.
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"not_a_cert": true}`))
	}
	c, server := newMockedClient(t, handler)
	defer server.Close()

	cert, err := c.GetCertificate(context.Background(), "req_partial_0001")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Fields default to zero-values. This is intentional — thin transport.
	if cert.CertificateID != "" {
		t.Errorf("expected empty CertificateID, got %q", cert.CertificateID)
	}
	// Downstream VerifyCertificate would reject this with Reason=Malformed.
	// We assert that here for clarity.
	_, verifyErr := VerifyCertificate(cert, VerifyCertificateKeys{
		WitnessKeyID:     "witness_v1",
		WitnessPublicKey: make([]byte, 32),
	})
	var certErr *CertificateError
	if !errors.As(verifyErr, &certErr) {
		t.Fatalf("downstream verify should reject: %v", verifyErr)
	}
	if certErr.Reason != ReasonMalformed {
		t.Errorf("downstream reason = %q", certErr.Reason)
	}
}
