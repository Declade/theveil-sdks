export interface TheVeilConfig {
  apiKey: string;
  baseUrl?: string;
  timeoutMs?: number;
}

// Mirror of gateway proxyPIIAnnotation (ground-truth annotation for proving_ground mode).
// TODO(proxy-sync): keep in lockstep with
//   dual-sandbox-architecture/services/gateway/internal/api/proxy.go:35 (proxyPIIAnnotation).
export interface PIIAnnotation {
  type: string;
  value: string;
  start: number;
  end: number;
}

// Mirror of gateway proxyRequest — the split-knowledge /api/v1/proxy/messages payload.
// TODO(proxy-sync): keep in lockstep with
//   dual-sandbox-architecture/services/gateway/internal/api/proxy.go:46 (proxyRequest).
export interface ProxyRequest {
  prompt_template: string;
  context: Record<string, string>;
  model?: string;
  max_tokens?: number;
  temperature?: number;
  stream?: boolean;
  relink_response?: boolean;
  mode?: 'live' | 'proving_ground';
  activity_id?: string;
  ground_truth?: Record<string, PIIAnnotation[]>;
}

// MessagesRequest narrows ProxyRequest: streaming is not supported by the
// messages() method, so `stream: true` is a compile-time error until a future
// arc ships the SSE code path.
export type MessagesRequest = Omit<ProxyRequest, 'stream'> & {
  stream?: false;
};

// Per-call knobs for messages(). All optional; compose with the client's
// defaults at request time.
export interface MessagesOptions {
  // Caller-owned abort signal. If it fires, the caller's abort reason is
  // rethrown verbatim (not wrapped in TheVeilTimeoutError).
  signal?: AbortSignal;
  // Per-call timeout in milliseconds. Overrides the client default for this
  // call only.
  timeoutMs?: number;
  // Per-call headers merged on top of client defaults. SDK-owned headers
  // (x-api-key, content-type) still win — this mirrors the Session 1 header
  // merge behaviour.
  headers?: Record<string, string>;
}

// Minimal typed subset of the /api/v1/proxy/messages response. The gateway
// emits map[string]interface{} so extra keys (tracevault, veil_evidence,
// ground_truth_evaluation, etc.) may appear — the index signature keeps them
// reachable without forcing SDK releases for every gateway addition.
// TODO(proxy-sync): response assembly lives at
//   dual-sandbox-architecture/services/gateway/internal/api/proxy.go:740 onward.
export interface ProxyResponse {
  status: string;
  model_used: string;
  latency_ms: number;
  result?: unknown;
  dlp_redacted?: boolean;
  relinked?: boolean;
  error_message?: string;
  // Present only for pro/enterprise tiers when Veil hints are enabled on the
  // gateway. The value is the Bridge token-request scoped ID, not the
  // gateway's internal per-call request UUID used in audit/log lines.
  request_id?: string;
  compliance_trace?: Record<string, unknown>;
  ground_truth_evaluation?: Record<string, unknown>;
  veil?: Record<string, string>;
  veil_evidence?: Record<string, unknown>;
  tracevault?: Record<string, unknown>;
  [key: string]: unknown;
}
