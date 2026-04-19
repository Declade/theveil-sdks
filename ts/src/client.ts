import {
  TheVeilConfigError,
  TheVeilError,
  TheVeilHttpError,
  TheVeilTimeoutError,
} from './errors.js';
import type {
  MessagesOptions,
  MessagesRequest,
  ProxyResponse,
  TheVeilConfig,
} from './types.js';

const API_KEY_PATTERN = /^dsa_[0-9a-f]{32}$/;

// Default points at the hosted gateway for solo-dev tier.
// Enterprise self-hosters must pass baseUrl explicitly.
const DEFAULT_BASE_URL = 'https://gateway.dsaveil.io';

const DEFAULT_TIMEOUT_MS = 30_000;

function normalizeBaseUrl(raw: string): string {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new TheVeilConfigError(`Invalid baseUrl: ${raw}`);
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new TheVeilConfigError(
      `baseUrl must use http or https, got: ${parsed.protocol}`,
    );
  }
  return raw.replace(/\/+$/, '');
}

// Shared validator so constructor-level and per-call timeouts reject the same
// set of inputs. Returns the validated number; throws TheVeilConfigError on
// 0, negative, NaN, or Infinity.
function validateTimeoutMs(value: number, source: string): number {
  if (!Number.isFinite(value) || value <= 0) {
    throw new TheVeilConfigError(
      `Invalid ${source}: ${value} — must be a positive finite number`,
    );
  }
  return value;
}

export class TheVeil {
  public readonly apiKey: string;
  public readonly baseUrl: string;
  public readonly timeoutMs: number;

  constructor(config: TheVeilConfig) {
    if (!config || typeof config.apiKey !== 'string' || !API_KEY_PATTERN.test(config.apiKey)) {
      throw new TheVeilConfigError(
        'Invalid apiKey — expected format "dsa_" followed by 32 lowercase hex characters',
      );
    }

    // Defense in depth: validate and normalize both the default and any caller override.
    const rawBaseUrl = config.baseUrl ?? DEFAULT_BASE_URL;
    const baseUrl = normalizeBaseUrl(rawBaseUrl);

    const timeoutMs =
      config.timeoutMs === undefined
        ? DEFAULT_TIMEOUT_MS
        : validateTimeoutMs(config.timeoutMs, 'timeoutMs');

    this.apiKey = config.apiKey;
    this.baseUrl = baseUrl;
    this.timeoutMs = timeoutMs;
  }

  // Public entry point for /api/v1/proxy/messages.
  async messages(params: MessagesRequest, options?: MessagesOptions): Promise<ProxyResponse> {
    return this.request<ProxyResponse>(
      '/api/v1/proxy/messages',
      {
        method: 'POST',
        body: JSON.stringify(params),
        headers: options?.headers,
      },
      {
        timeoutMs: options?.timeoutMs,
        signal: options?.signal,
      },
    );
  }

  private async request<T>(
    path: string,
    init: RequestInit,
    opts?: { timeoutMs?: number; signal?: AbortSignal },
  ): Promise<T> {
    const url = `${this.baseUrl}${path.startsWith('/') ? path : `/${path}`}`;
    const callerSignal = opts?.signal;
    // Per-call timeoutMs is validated with the same strictness as the
    // constructor — 0, negative, NaN, and Infinity all throw instead of
    // silently falling back to the client default.
    const timeoutMs =
      opts?.timeoutMs === undefined
        ? this.timeoutMs
        : validateTimeoutMs(opts.timeoutMs, 'options.timeoutMs');

    // Fail fast on an already-aborted caller signal so we don't spend a fetch
    // round-trip just to throw the same reason.
    if (callerSignal?.aborted) {
      throw callerSignal.reason;
    }

    const timeoutController = new AbortController();
    const timer = setTimeout(() => timeoutController.abort(), timeoutMs);
    // AbortSignal.any (Node 20.3+) propagates whichever signal aborts first.
    // Its `.reason` is locked to the first source's reason and never changes,
    // which is how we distinguish caller-initiated aborts from timeouts below.
    const composedSignal: AbortSignal = callerSignal
      ? AbortSignal.any([callerSignal, timeoutController.signal])
      : timeoutController.signal;

    // Normalize caller headers via the Headers API — this lowercases all header
    // names per the fetch spec, so the SDK-owned keys below unambiguously win.
    const callerHeaders: Record<string, string> = {};
    if (init.headers !== undefined) {
      const h = new Headers(init.headers);
      h.forEach((value, key) => {
        callerHeaders[key] = value;
      });
    }
    const mergedHeaders: Record<string, string> = {
      ...callerHeaders,
      'x-api-key': this.apiKey,
      'content-type': 'application/json',
    };

    try {
      const response = await fetch(url, {
        ...init,
        headers: mergedHeaders,
        signal: composedSignal,
      });

      const text = await response.text();
      let body: unknown = text;
      if (text.length > 0) {
        try {
          body = JSON.parse(text);
        } catch {
          // non-JSON body — keep raw text
        }
      }

      if (!response.ok) {
        throw new TheVeilHttpError(
          `TheVeil request failed: ${response.status} ${response.statusText}`,
          response.status,
          body,
        );
      }
      return body as T;
    } catch (err) {
      if (err instanceof TheVeilError) {
        throw err;
      }
      // Abort path: if our composed signal fired, identity-compare its reason
      // against the caller's to learn which source aborted FIRST (not "who
      // ended up aborted by catch-time"). AbortSignal.any locks `.reason` to
      // the first source at composite-abort time and never updates it, so a
      // late caller abort after a timeout cannot misattribute blame.
      if (composedSignal.aborted) {
        if (callerSignal && composedSignal.reason === callerSignal.reason) {
          // Rethrow the caller's reason verbatim so they see the same value
          // they passed to controller.abort(reason).
          throw callerSignal.reason;
        }
        throw new TheVeilTimeoutError(
          `Request timed out after ${timeoutMs}ms`,
          { cause: err },
        );
      }
      throw new TheVeilError('Request failed', { cause: err });
    } finally {
      clearTimeout(timer);
    }
  }
}
