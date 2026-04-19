import { TheVeilConfigError, TheVeilHttpError } from './errors.js';
import type { TheVeilConfig } from './types.js';

const API_KEY_PATTERN = /^dsa_[0-9a-f]{32}$/;
const DEFAULT_BASE_URL = 'https://vault.dsaveil.io';
const DEFAULT_TIMEOUT_MS = 30_000;

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

    let baseUrl = DEFAULT_BASE_URL;
    if (config.baseUrl !== undefined) {
      try {
        new URL(config.baseUrl);
      } catch {
        throw new TheVeilConfigError(`Invalid baseUrl: ${config.baseUrl}`);
      }
      baseUrl = config.baseUrl.replace(/\/+$/, '');
    }

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

    const mergedHeaders: Record<string, string> = {
      'x-api-key': this.apiKey,
      'content-type': 'application/json',
      ...(init.headers as Record<string, string> | undefined),
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
    } finally {
      clearTimeout(timer);
    }
  }
}
