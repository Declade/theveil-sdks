import {
  TheVeilConfigError,
  TheVeilError,
  TheVeilHttpError,
  TheVeilTimeoutError,
} from './errors.js';
import type { TheVeilConfig } from './types.js';

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

    let timeoutMs = DEFAULT_TIMEOUT_MS;
    if (config.timeoutMs !== undefined) {
      if (!Number.isFinite(config.timeoutMs) || config.timeoutMs <= 0) {
        throw new TheVeilConfigError(
          `Invalid timeoutMs: ${config.timeoutMs} — must be a positive finite number`,
        );
      }
      timeoutMs = config.timeoutMs;
    }

    this.apiKey = config.apiKey;
    this.baseUrl = baseUrl;
    this.timeoutMs = timeoutMs;
  }

  private async request<T>(path: string, init: RequestInit): Promise<T> {
    const url = `${this.baseUrl}${path.startsWith('/') ? path : `/${path}`}`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

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
        signal: controller.signal,
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
      if (err instanceof Error && err.name === 'AbortError') {
        throw new TheVeilTimeoutError(
          `Request timed out after ${this.timeoutMs}ms`,
          { cause: err },
        );
      }
      throw new TheVeilError('Request failed', { cause: err });
    } finally {
      clearTimeout(timer);
    }
  }
}
