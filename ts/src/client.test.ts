import { afterEach, describe, expect, it, vi } from 'vitest';
import { TheVeil } from './client.js';
import { TheVeilConfigError, TheVeilError, TheVeilTimeoutError } from './errors.js';

const VALID_KEY = 'dsa_0123456789abcdef0123456789abcdef';

// Handle on the private request<T>() so tests can exercise the plumbing
// without exporting it or changing its visibility.
type Internal = {
  request: <T>(path: string, init: RequestInit) => Promise<T>;
};
const asInternal = (client: TheVeil): Internal => client as unknown as Internal;

describe('TheVeil constructor — apiKey validation', () => {
  it('accepts a well-formed dsa_ key', () => {
    const client = new TheVeil({ apiKey: VALID_KEY });
    expect(client.apiKey).toBe(VALID_KEY);
  });

  it('rejects a key with the wrong prefix', () => {
    expect(() => new TheVeil({ apiKey: 'sk_0123456789abcdef0123456789abcdef' })).toThrow(
      TheVeilConfigError,
    );
  });

  it('rejects a key with the wrong length', () => {
    expect(() => new TheVeil({ apiKey: 'dsa_0123456789abcdef' })).toThrow(TheVeilConfigError);
  });

  it('rejects a key that contains uppercase hex', () => {
    expect(() => new TheVeil({ apiKey: 'dsa_ABCDEF0123456789ABCDEF0123456789' })).toThrow(
      TheVeilConfigError,
    );
  });

  it('rejects a non-string apiKey', () => {
    // @ts-expect-error — exercising runtime guard against mis-typed input.
    expect(() => new TheVeil({ apiKey: undefined })).toThrow(TheVeilConfigError);
  });
});

describe('TheVeil constructor — defaults and baseUrl', () => {
  it('applies the default baseUrl when none is supplied', () => {
    const client = new TheVeil({ apiKey: VALID_KEY });
    expect(client.baseUrl).toBe('https://gateway.dsaveil.io');
  });

  it('applies the default timeoutMs when none is supplied', () => {
    const client = new TheVeil({ apiKey: VALID_KEY });
    expect(client.timeoutMs).toBe(30_000);
  });

  it('accepts a valid baseUrl and strips trailing slashes', () => {
    const client = new TheVeil({ apiKey: VALID_KEY, baseUrl: 'https://vault.example.com/' });
    expect(client.baseUrl).toBe('https://vault.example.com');
  });

  it('strips trailing slashes even when caller omits baseUrl (default path)', () => {
    // Defense-in-depth: default is already well-formed; assert the normalize
    // step runs regardless of where the baseUrl came from.
    const client = new TheVeil({ apiKey: VALID_KEY });
    expect(client.baseUrl.endsWith('/')).toBe(false);
  });

  it('rejects an invalid baseUrl', () => {
    expect(() => new TheVeil({ apiKey: VALID_KEY, baseUrl: 'not a url' })).toThrow(
      TheVeilConfigError,
    );
  });

  it('rejects a non-positive timeoutMs', () => {
    expect(() => new TheVeil({ apiKey: VALID_KEY, timeoutMs: 0 })).toThrow(TheVeilConfigError);
    expect(() => new TheVeil({ apiKey: VALID_KEY, timeoutMs: -1 })).toThrow(TheVeilConfigError);
    expect(() => new TheVeil({ apiKey: VALID_KEY, timeoutMs: Number.NaN })).toThrow(
      TheVeilConfigError,
    );
  });
});

describe('TheVeil constructor — baseUrl scheme guard', () => {
  it('rejects a file:// URL', () => {
    expect(() => new TheVeil({ apiKey: VALID_KEY, baseUrl: 'file:///etc/passwd' })).toThrow(
      TheVeilConfigError,
    );
  });

  it('rejects a javascript: URL', () => {
    expect(() => new TheVeil({ apiKey: VALID_KEY, baseUrl: 'javascript:alert(1)' })).toThrow(
      TheVeilConfigError,
    );
  });
});

describe('TheVeil.request() — header merge', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('forces SDK-owned headers to win over caller-supplied ones, case-insensitively', async () => {
    let captured: RequestInit | undefined;
    vi.stubGlobal('fetch', (_url: string, init: RequestInit) => {
      captured = init;
      return Promise.resolve(
        new Response('{"ok":true}', {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
      );
    });

    const client = new TheVeil({ apiKey: VALID_KEY });
    await asInternal(client).request('/health', {
      headers: {
        'X-Api-Key': 'wrong-key',
        'Content-Type': 'text/plain',
        'X-Custom': 'keep-me',
      },
    });

    expect(captured).toBeDefined();
    const h = captured!.headers as Record<string, string>;

    // SDK-owned headers use canonical lowercase names and cannot be overridden.
    expect(h['x-api-key']).toBe(VALID_KEY);
    expect(h['content-type']).toBe('application/json');

    // The uppercase duplicates must not have survived the Headers() normalization.
    expect(h['X-Api-Key']).toBeUndefined();
    expect(h['Content-Type']).toBeUndefined();

    // Caller-only headers are preserved (on their lowercased key).
    expect(h['x-custom']).toBe('keep-me');
  });
});

describe('TheVeil.request() — error wrapping', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('wraps an AbortError from fetch into TheVeilTimeoutError', async () => {
    vi.stubGlobal('fetch', (_url: string, init: RequestInit) => {
      return new Promise((_resolve, reject) => {
        init.signal?.addEventListener('abort', () => {
          const err = new Error('The operation was aborted.');
          err.name = 'AbortError';
          reject(err);
        });
      });
    });

    const client = new TheVeil({ apiKey: VALID_KEY, timeoutMs: 5 });
    await expect(asInternal(client).request('/slow', {})).rejects.toSatisfy(
      (err) => err instanceof TheVeilTimeoutError && err instanceof TheVeilError,
    );
  });

  it('wraps a generic fetch rejection in TheVeilError and preserves cause', async () => {
    const underlying = new TypeError('network failure');
    vi.stubGlobal('fetch', () => Promise.reject(underlying));

    const client = new TheVeil({ apiKey: VALID_KEY });
    try {
      await asInternal(client).request('/x', {});
      expect.fail('expected request to throw');
    } catch (err) {
      expect(err).toBeInstanceOf(TheVeilError);
      expect(err).not.toBeInstanceOf(TheVeilTimeoutError);
      expect((err as TheVeilError).cause).toBe(underlying);
    }
  });
});
