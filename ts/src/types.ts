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

// Sandbox B terminal job statuses that the gateway forwards on the sync path.
// The set is small and stable — proxy.go only emits these two after
// pollForResult returns a completed job.
// TODO(proxy-sync): observed at
//   dual-sandbox-architecture/services/gateway/internal/api/proxy.go:713 and :931.
export type ProxyJobStatus = 'JOB_STATUS_COMPLETED' | 'JOB_STATUS_FAILED';

// Shared veil-receipt sub-object carried on both sync and async responses
// when the customer is pro/enterprise tier and veil hints are enabled. The
// inner `status` value differs between paths but the surface is identical.
// TODO(proxy-sync):
//   sync  — proxy.go:921 (status="available")
//   async — proxy_async.go:137 (status="pending")
export interface ProxyVeilReceipt {
  status: 'available' | 'pending';
  certificate_url: string;
  summary_url: string;
}

// Sync (200 OK) response — pollForResult returned a terminal job result and
// writeProxyResult assembled the body.
// TODO(proxy-sync): response assembly lives at
//   dual-sandbox-architecture/services/gateway/internal/api/proxy.go:740 onward.
export interface ProxySyncResponse {
  status: ProxyJobStatus;
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
  veil?: ProxyVeilReceipt;
  veil_evidence?: Record<string, unknown>;
  tracevault?: Record<string, unknown>;
}

// Async (202 Accepted) response — pollForResult timed out; the job is still
// running. Callers must poll `status_url` until the job completes.
// TODO(proxy-sync): mirrors asyncProcessingResponse at
//   dual-sandbox-architecture/services/gateway/internal/api/proxy_async.go:128.
export interface ProxyAcceptedResponse {
  status: 'processing';
  job_id: string;
  request_id: string;
  status_url: string;
  veil?: ProxyVeilReceipt;
}

// Discriminated on `status`: the literal 'processing' is the async branch;
// a ProxyJobStatus is the sync branch. Narrow with a check on response.status.
export type ProxyResponse = ProxySyncResponse | ProxyAcceptedResponse;
