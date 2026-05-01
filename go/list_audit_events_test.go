package lucairn

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

// ListAuditEvents corresponds to GET /api/v1/audit/export. The handler
// at dual-sandbox-architecture/services/gateway/internal/api/
// audit_export.go:58-99 enforces:
//   - x-api-key Pro+ tier (Solo Free → 403 ErrTierInsufficient)
//   - days in [1,90] (default 30; HTTP 400 on out-of-range)
//   - optional type=<event_type> filter
//
// Response shape per audit_export.go:91-99 maps onto our typed
// AuditExportResponse.

func TestListAuditEvents_HappyPath(t *testing.T) {
	stubBody := map[string]any{
		"customer_id": "cust_alpha",
		"tier":        "pro",
		"period":      "2026-04-01 to 2026-05-01",
		"events": []map[string]any{
			{
				"timestamp":  "2026-04-30T12:00:00Z",
				"event_type": "veil.certificate.issued",
				"actor":      "cust_alpha",
				"details":    `{"request_id":"req_001"}`,
				"request_id": "req_001",
			},
		},
		"total_events": 1,
		"source":       "memory_buffer",
	}

	handler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %q, want GET", r.Method)
		}
		if !strings.HasPrefix(r.URL.Path, "/api/v1/audit/export") {
			t.Errorf("path = %q", r.URL.Path)
		}
		if r.Header.Get("x-api-key") != validAPIKey {
			t.Errorf("x-api-key missing or wrong")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(stubBody)
	}

	c, server := newMockedClient(t, handler)
	defer server.Close()

	resp, err := c.ListAuditEvents(context.Background(), AuditExportOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.CustomerID != "cust_alpha" {
		t.Errorf("CustomerID = %q", resp.CustomerID)
	}
	if resp.TotalEvents != 1 {
		t.Errorf("TotalEvents = %d", resp.TotalEvents)
	}
	if resp.Source != "memory_buffer" {
		t.Errorf("Source = %q", resp.Source)
	}
	if len(resp.Events) != 1 {
		t.Fatalf("Events length = %d", len(resp.Events))
	}
	got := resp.Events[0]
	want, _ := time.Parse(time.RFC3339, "2026-04-30T12:00:00Z")
	if !got.Timestamp.Equal(want) {
		t.Errorf("Timestamp = %v, want %v", got.Timestamp, want)
	}
	if got.EventType != "veil.certificate.issued" {
		t.Errorf("EventType = %q", got.EventType)
	}
	if got.RequestID != "req_001" {
		t.Errorf("RequestID = %q", got.RequestID)
	}
}

func TestListAuditEvents_QueryParamsBuiltCorrectly(t *testing.T) {
	var seenQuery string

	handler := func(w http.ResponseWriter, r *http.Request) {
		seenQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"customer_id": "x", "tier": "pro", "period": "x", "events": []any{}, "total_events": 0, "source": "none",
		})
	}

	c, server := newMockedClient(t, handler)
	defer server.Close()

	_, err := c.ListAuditEvents(context.Background(), AuditExportOptions{
		Days:      45,
		EventType: "veil.certificate.issued",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(seenQuery, "days=45") {
		t.Errorf("query %q missing days=45", seenQuery)
	}
	if !strings.Contains(seenQuery, "type=veil.certificate.issued") {
		t.Errorf("query %q missing type=veil.certificate.issued", seenQuery)
	}
}

func TestListAuditEvents_DefaultsOmitDaysParam(t *testing.T) {
	// Days=0 in opts means "let the gateway pick its default" — the
	// SDK omits the days query param entirely so the gateway sees no
	// parsed "days" value and applies defaultExportDays at
	// audit_export.go:174-188.
	var seenQuery string

	handler := func(w http.ResponseWriter, r *http.Request) {
		seenQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"customer_id": "x", "tier": "pro", "period": "x", "events": []any{}, "total_events": 0, "source": "none",
		})
	}

	c, server := newMockedClient(t, handler)
	defer server.Close()

	_, err := c.ListAuditEvents(context.Background(), AuditExportOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(seenQuery, "days=") {
		t.Errorf("query %q unexpectedly carries days=", seenQuery)
	}
	if strings.Contains(seenQuery, "type=") {
		t.Errorf("query %q unexpectedly carries type=", seenQuery)
	}
}

func TestListAuditEvents_RejectsNegativeDays(t *testing.T) {
	c, err := New(validAPIKey)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.ListAuditEvents(context.Background(), AuditExportOptions{Days: -1})
	var cfgErr *ConfigError
	if !errors.As(err, &cfgErr) {
		t.Fatalf("want *ConfigError, got %T (%v)", err, err)
	}
}

func TestListAuditEvents_403FreeTier(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"code":"tier_insufficient","message":"Audit export requires the pro tier."}`))
	}

	c, server := newMockedClient(t, handler)
	defer server.Close()

	_, err := c.ListAuditEvents(context.Background(), AuditExportOptions{Days: 7})
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("want *HTTPError, got %T (%v)", err, err)
	}
	if httpErr.Status != http.StatusForbidden {
		t.Errorf("status = %d, want 403", httpErr.Status)
	}
}

func TestListAuditEvents_503Unavailable(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"code":"audit_export_unavailable","message":"Audit export unavailable. Try again shortly."}`))
	}

	c, server := newMockedClient(t, handler)
	defer server.Close()

	_, err := c.ListAuditEvents(context.Background(), AuditExportOptions{Days: 30})
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("want *HTTPError, got %T (%v)", err, err)
	}
	if httpErr.Status != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", httpErr.Status)
	}
}

func TestListAuditEvents_DecodeFailureIsResponseValidationError(t *testing.T) {
	// Gateway returns 200 with a body that doesn't shape-match
	// AuditExportResponse — surface as *ResponseValidationError, not
	// silent zero-valued struct.
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// total_events as a string instead of int → decodeInto fails.
		_, _ = w.Write([]byte(`{"customer_id":"x","tier":"pro","period":"x","events":[],"total_events":"not-a-number","source":"none"}`))
	}

	c, server := newMockedClient(t, handler)
	defer server.Close()

	_, err := c.ListAuditEvents(context.Background(), AuditExportOptions{})
	var valErr *ResponseValidationError
	if !errors.As(err, &valErr) {
		t.Fatalf("want *ResponseValidationError, got %T (%v)", err, err)
	}
}
