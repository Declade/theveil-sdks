# theveil — Go SDK

Client for **The Veil** — privacy-preserving AI infrastructure.

## Status

Pre-1.0 (v0.1.0). Ships alongside the TypeScript SDK's `0.2.0` and behaves
identically at the observable level. See the [monorepo
README](../README.md) for the full SDK index.

## Install

```bash
go get github.com/declade/theveil-sdks/go@latest
```

Requires Go 1.22+.

## Quickstart

```go
package main

import (
	"context"
	"fmt"

	theveil "github.com/declade/theveil-sdks/go"
)

func main() {
	client, err := theveil.New("dsa_...")
	if err != nil {
		panic(err)
	}

	ctx := context.Background()

	// Proxy a prompt through the Veil gateway (split-knowledge routing).
	maxTokens := 256
	resp, err := client.Messages(ctx, theveil.MessagesRequest{
		PromptTemplate: "Summarize the following: {text}",
		Context:        map[string]string{"text": "Long input..."},
		Model:          "claude-opus-4-7",
		MaxTokens:      &maxTokens,
	})
	if err != nil {
		panic(err)
	}
	switch r := resp.(type) {
	case *theveil.ProxySyncResponse:
		fmt.Println("sync result:", r.Status, r.ModelUsed)
	case *theveil.ProxyAcceptedResponse:
		fmt.Println("async — poll:", r.StatusURL)
	}

	// Fetch a Veil Certificate for a known request_id (Pro+/Enterprise).
	cert, err := client.GetCertificate(ctx, "req_abc123")
	if err != nil {
		panic(err)
	}

	// Verify the witness Ed25519 signature against pinned trust-root keys.
	result, err := client.VerifyCertificate(cert, theveil.VerifyCertificateKeys{
		WitnessKeyID:     "witness_v1",
		WitnessPublicKey: "<base64 of raw 32-byte Ed25519 public key>",
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(result.OverallVerdict, result.AnchorStatus)
}
```

## Public API

### `theveil.New(apiKey string, opts ...Option) (*Client, error)`

Constructor validates every input up front:

- `apiKey` must match `^dsa_[0-9a-f]{32}$`.
- `WithBaseURL(url)` must be `http://` or `https://`; default is
  `https://gateway.dsaveil.io`.
- `WithTimeout(d)` must be a positive `time.Duration`; default `30s`.
- `WithHTTPClient(c)` lets you substitute a custom `*http.Client` (for
  mTLS, corporate proxies, custom transports).

### `(*Client).Messages(ctx, req, ...CallOption) (MessagesResponse, error)`

POST to `/api/v1/proxy/messages`. Returns the `MessagesResponse` tagged
union — discriminate via a type switch:

```go
switch r := resp.(type) {
case *theveil.ProxySyncResponse:
	// 200 terminal result — inspect r.Status for COMPLETED / FAILED
case *theveil.ProxyAcceptedResponse:
	// 202 processing receipt — poll r.StatusURL until completion
}
```

### `(*Client).GetCertificate(ctx, requestID, ...CallOption) (*VeilCertificate, error)`

GET `/api/v1/veil/certificate/{requestID}`. Happy-path returns
`*VeilCertificate`. Gateway-side pending (certificate not yet assembled,
or unknown requestID — the gateway does not distinguish) surfaces as
`*HTTPError` with `Status=202` and `Body` holding the pending wrapper:

```go
cert, err := client.GetCertificate(ctx, "req_abc")
var httpErr *theveil.HTTPError
if errors.As(err, &httpErr) && httpErr.Status == 202 {
	body := httpErr.Body.(map[string]any)
	retryAfter := body["retry_after_seconds"]
	// poll later
}
```

No auto-verification — chain `VerifyCertificate` explicitly.

### `theveil.VerifyCertificate(cert, keys)` / `(*Client).VerifyCertificate(cert, keys)`

Verify a certificate's witness Ed25519 signature. Accepts cert as
`*VeilCertificate`, `map[string]any`, `[]byte`, or `json.RawMessage`.
Returns `*VerifyCertificateResult` on success, `*CertificateError` on
failure with one of five reasons:

| Reason                                    | Condition                                                |
|-------------------------------------------|----------------------------------------------------------|
| `ReasonMalformed`                         | cert shape invalid / gateway invariant / unknown verdict |
| `ReasonUnsupportedProtocolVersion`        | `ProtocolVersion != 2`                                   |
| `ReasonWitnessMismatch`                   | key ID mismatch                                          |
| `ReasonWitnessSignatureMissing`           | empty or whitespace-only signature                       |
| `ReasonInvalidSignature`                  | Ed25519 verify failed, or key input malformed            |

External RFC 3161 timestamp + Sigstore Rekor transparency-log
verification are out of scope for this release (pending upstream gateway
fixes).

## Per-call options

Options compose; last-write-wins on conflict:

```go
client.GetCertificate(ctx, "req_abc",
	theveil.WithCallTimeout(5*time.Second),
	theveil.WithCallHeader("x-correlation-id", "corr_xyz"),
)
```

SDK-owned headers (`x-api-key`, `content-type`) always win over
caller-supplied values with the same key.

## Error taxonomy

All SDK errors satisfy the `theveil.Error` interface. Concrete types:

- `*ConfigError` — caller input invalid.
- `*HTTPError` — gateway returned non-2xx (or 202 from `GetCertificate`);
  fields `Status int`, `Body any`, `Message string`, `Err error` (wrapped).
- `*ResponseValidationError` — gateway returned 2xx but the body couldn't
  be deserialized into the declared response type (typically a gateway
  bug or version skew); fields `Body []byte`, `Message string`,
  `Err error` (wrapped decode error). **Distinct from `*HTTPError`** so
  callers can branch cleanly on "transport failed" vs "body shape
  wrong."
- `*TimeoutError` — request exceeded timeout; wraps `context.DeadlineExceeded`.
- `*NetworkError` — connection failures, caller-cancel, transport errors;
  wraps the underlying error (use `errors.Is(err, context.Canceled)` to
  detect caller cancel specifically).
- `*CertificateError` — `VerifyCertificate` failed; fields `Reason`,
  `CertificateID`, `Message`, `Err`.

Use `errors.As(err, &concreteType)` to inspect typed fields.

## Behavioural parity with TS / Python

This SDK is cross-language byte-equivalent to the TS and Python SDKs for
canonical JSON and `VerifyCertificate`. The Go-assembler-signed cert
fixture (`cert-go-signed-reference.json`) verifies identically in all
three. The `internal/verify` canonical serializer uses Go's native
`encoding/json` with default HTML-escape on — which produces the exact
bytes the TS/Python ports build with explicit escape passes.

Intentional idiomatic divergences from the other two SDKs:

- **Cancellation via `context.Context`**, not `AbortSignal` / cancel
  tokens. Pass a `ctx` with deadline / cancel; caller-cancel produces
  a `*NetworkError` wrapping `context.Canceled`.
- **Error taxonomy** satisfies the `theveil.Error` interface. No deep
  inheritance chain.
- **Functional options** (`WithBaseURL`, `WithTimeout`, `WithHTTPClient`,
  `WithCallTimeout`, `WithCallHeader`, `WithMaxResponseBytes`) for
  constructor + per-call config.
- **PascalCase exports** per Go convention: `GetCertificate`, `Messages`,
  `VerifyCertificate`.
- **Malformed 2xx body**: TS passes through as raw bytes typed as
  `VeilCertificate` (thin transport); Go follows Go-SDK precedent
  (aws-sdk-go-v2's `*smithy.DeserializationError`,
  kubernetes/client-go's runtime-decode errors) and returns
  `(nil, *ResponseValidationError)` on any decode failure. `*HTTPError`
  is reserved for non-2xx transport failures — an HTTP 200 is not an
  HTTP error. The same applies uniformly across `GetCertificate`,
  `Messages`, and any other 2xx-decode path.
  Note: a 2xx JSON object missing required fields still
  returns `(*VeilCertificate, nil)` (or `(*ProxySyncResponse, nil)` for
  `Messages`) with zero-valued fields, because Go's `json.Unmarshal` is
  permissive on field presence — the decode itself does not fail. This
  matches TS thin-transport behaviour for the value-present path.
  Downstream `VerifyCertificate` rejects such a zero-valued struct with
  `ReasonMalformed`.

## Release

Versions are tagged as a pair against the same commit (see
`publish-go.yml`):

- `v0.1.0` — canonical monorepo tag (shared with TS + Python).
- `go/v0.1.0` — Go submodule tag required by Go's module path
  conventions for subdirectory modules. Publishing = pushing the
  `go/v*` tag and warming `proxy.golang.org`; no registry credentials.

## Development

```bash
cd go
go test ./... -race
go vet ./...
```

Tests include a byte-for-byte cross-check of Go canonical-JSON output
against the Go assembler's reference hex, and end-to-end verification
of a real Go-assembler-signed certificate. If either fails, the SDK's
Ed25519 verify will silently produce `invalid_signature` on valid
certs — do not skip or soft-fail those tests.

## License

MIT — see [LICENSE](../LICENSE).
