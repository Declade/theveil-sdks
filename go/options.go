package theveil

import (
	"net/http"
	"time"
)

// Option configures a *Client at construction time. Options compose;
// last-write-wins on conflict.
type Option func(*clientConfig)

type clientConfig struct {
	baseURL string
	timeout time.Duration
	http    *http.Client
}

// WithBaseURL sets an explicit gateway base URL. Enterprise self-hosters
// use this to point at their own gateway deployment. Must be http:// or
// https://. Trailing slashes are stripped.
func WithBaseURL(url string) Option {
	return func(c *clientConfig) { c.baseURL = url }
}

// WithTimeout sets the default per-call timeout. Zero or negative
// durations are rejected at New() time. Callers can override per call
// with WithCallTimeout.
func WithTimeout(d time.Duration) Option {
	return func(c *clientConfig) { c.timeout = d }
}

// WithHTTPClient substitutes the underlying *http.Client. Useful for
// testing (httptest) or when the caller needs a custom transport
// (mTLS, corporate proxy, connection pooling tuned). The Client will
// apply its timeout and context on top of whatever the custom HTTP
// client does.
func WithHTTPClient(h *http.Client) Option {
	return func(c *clientConfig) { c.http = h }
}

// CallOption configures a single Messages / GetCertificate call.
type CallOption func(*callConfig)

type callConfig struct {
	timeout time.Duration
	headers map[string]string
}

// WithCallTimeout overrides the client-default timeout for a single call.
// Must be positive.
func WithCallTimeout(d time.Duration) CallOption {
	return func(c *callConfig) { c.timeout = d }
}

// WithCallHeader adds a per-call header. SDK-owned headers (x-api-key,
// content-type) still win over caller-supplied values with the same key.
// Call multiple times to set multiple headers.
func WithCallHeader(key, value string) CallOption {
	return func(c *callConfig) {
		if c.headers == nil {
			c.headers = make(map[string]string, 1)
		}
		c.headers[key] = value
	}
}
