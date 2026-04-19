import { delay, http, HttpResponse } from 'msw';
import { describe, expect, it } from 'vitest';
import { TheVeil } from './client.js';
import {
  TheVeilConfigError,
  TheVeilError,
  TheVeilHttpError,
  TheVeilTimeoutError,
} from './errors.js';
import { server } from './test-server.js';
import type { MessagesRequest } from './types.js';

// Obviously-fake identifiers — no real keys, names, or PII.
const VALID_KEY = 'dsa_0123456789abcdef0123456789abcdef';
const MESSAGES_URL = 'https://gateway.dsaveil.io/api/v1/proxy/messages';

// Minimal valid request body reused across tests.
const BASIC_REQUEST: MessagesRequest = {
  prompt_template: 'Hello {name}',
  context: { name: 'Example Person' },
  model: 'claude-sonnet-4-5',
  max_tokens: 1024,
};

describe('TheVeil.messages() — happy path', () => {
  it('returns a typed ProxyResponse on 200', async () => {
    server.use(
      http.post(MESSAGES_URL, () =>
        HttpResponse.json({
          status: 'completed',
          model_used: 'claude-sonnet-4-5',
          latency_ms: 142,
          result: { content: [{ type: 'text', text: 'Hello [PERSON_1]' }] },
          relinked: true,
          request_id: 'req_test_0001',
        }),
      ),
    );

    const client = new TheVeil({ apiKey: VALID_KEY });
    const response = await client.messages(BASIC_REQUEST);

    expect(response.status).toBe('completed');
    expect(response.model_used).toBe('claude-sonnet-4-5');
    expect(response.latency_ms).toBe(142);
    expect(response.request_id).toBe('req_test_0001');
    expect(response.relinked).toBe(true);
  });

  it('sends the request body and SDK-owned headers', async () => {
    let capturedBody: unknown;
    const capturedHeaders: Record<string, string> = {};
    server.use(
      http.post(MESSAGES_URL, async ({ request }) => {
        capturedBody = await request.json();
        request.headers.forEach((value, key) => {
          capturedHeaders[key] = value;
        });
        return HttpResponse.json({
          status: 'completed',
          model_used: 'claude-sonnet-4-5',
          latency_ms: 1,
        });
      }),
    );

    const client = new TheVeil({ apiKey: VALID_KEY });
    await client.messages(BASIC_REQUEST);

    expect(capturedBody).toEqual(BASIC_REQUEST);
    expect(capturedHeaders['x-api-key']).toBe(VALID_KEY);
    expect(capturedHeaders['content-type']).toBe('application/json');
  });
});

describe('TheVeil.messages() — HTTP error mapping', () => {
  const cases: Array<{ status: number; label: string; body: Record<string, unknown> }> = [
    { status: 400, label: 'bad request', body: { error: 'invalid_request', message: 'missing prompt_template' } },
    { status: 401, label: 'unauthorized', body: { error: 'invalid_api_key' } },
    { status: 429, label: 'rate limit', body: { error: 'rate_limit_exceeded', retry_after: 30 } },
    { status: 500, label: 'server error', body: { error: 'internal' } },
  ];

  for (const { status, label, body } of cases) {
    it(`maps ${status} ${label} to TheVeilHttpError with .status=${status} and parsed body`, async () => {
      server.use(
        http.post(MESSAGES_URL, () => HttpResponse.json(body, { status })),
      );

      const client = new TheVeil({ apiKey: VALID_KEY });
      try {
        await client.messages(BASIC_REQUEST);
        expect.fail(`expected ${status} to throw TheVeilHttpError`);
      } catch (err) {
        expect(err).toBeInstanceOf(TheVeilHttpError);
        expect(err).toBeInstanceOf(TheVeilError);
        const httpErr = err as TheVeilHttpError;
        expect(httpErr.status).toBe(status);
        expect(httpErr.body).toEqual(body);
      }
    });
  }
});

describe('TheVeil.messages() — transport errors', () => {
  it('wraps a network failure in TheVeilError (not TheVeilHttpError)', async () => {
    server.use(http.post(MESSAGES_URL, () => HttpResponse.error()));

    const client = new TheVeil({ apiKey: VALID_KEY });
    try {
      await client.messages(BASIC_REQUEST);
      expect.fail('expected network failure to throw');
    } catch (err) {
      expect(err).toBeInstanceOf(TheVeilError);
      expect(err).not.toBeInstanceOf(TheVeilHttpError);
    }
  });
});

describe('TheVeil.messages() — timeout', () => {
  it('fires TheVeilTimeoutError when the per-call timeout elapses', async () => {
    server.use(
      http.post(MESSAGES_URL, async () => {
        await delay(500);
        return HttpResponse.json({ status: 'completed', model_used: 'x', latency_ms: 500 });
      }),
    );

    const client = new TheVeil({ apiKey: VALID_KEY });
    try {
      await client.messages(BASIC_REQUEST, { timeoutMs: 50 });
      expect.fail('expected timeout to throw');
    } catch (err) {
      expect(err).toBeInstanceOf(TheVeilTimeoutError);
      expect((err as TheVeilTimeoutError).message).toContain('50ms');
    }
  });

  it('uses the client-level timeout when no per-call override is given', async () => {
    server.use(
      http.post(MESSAGES_URL, async () => {
        await delay(500);
        return HttpResponse.json({ status: 'completed', model_used: 'x', latency_ms: 500 });
      }),
    );

    const client = new TheVeil({ apiKey: VALID_KEY, timeoutMs: 60 });
    try {
      await client.messages(BASIC_REQUEST);
      expect.fail('expected client-level timeout to throw');
    } catch (err) {
      expect(err).toBeInstanceOf(TheVeilTimeoutError);
      expect((err as TheVeilTimeoutError).message).toContain('60ms');
    }
  });
});

describe('TheVeil.messages() — per-call timeoutMs validation', () => {
  // Mirrors the constructor's rejection set so callers can't silently slip
  // invalid values past the per-call path.
  it.each([
    ['zero', 0],
    ['negative', -1],
    ['NaN', Number.NaN],
    ['Infinity', Number.POSITIVE_INFINITY],
  ])('rejects %s timeoutMs with TheVeilConfigError', async (_label, value) => {
    const client = new TheVeil({ apiKey: VALID_KEY });
    await expect(
      client.messages(BASIC_REQUEST, { timeoutMs: value }),
    ).rejects.toBeInstanceOf(TheVeilConfigError);
  });
});

describe('TheVeil.messages() — caller abort', () => {
  it('rethrows the caller-supplied abort reason verbatim', async () => {
    server.use(
      http.post(MESSAGES_URL, async () => {
        await delay(500);
        return HttpResponse.json({ status: 'completed', model_used: 'x', latency_ms: 500 });
      }),
    );

    const client = new TheVeil({ apiKey: VALID_KEY });
    const controller = new AbortController();
    const reason = new Error('caller cancelled');

    // Abort shortly after the fetch is in-flight.
    const promise = client.messages(BASIC_REQUEST, { signal: controller.signal });
    setTimeout(() => controller.abort(reason), 20);

    try {
      await promise;
      expect.fail('expected caller abort to throw');
    } catch (err) {
      expect(err).toBe(reason);
      expect(err).not.toBeInstanceOf(TheVeilTimeoutError);
    }
  });

  it('rejects immediately without issuing fetch when caller signal is already aborted', async () => {
    // No MSW handler — onUnhandledRequest: 'error' would fire if fetch ran,
    // which is the behavioural proof that we short-circuit before fetch().
    const client = new TheVeil({ apiKey: VALID_KEY });
    const controller = new AbortController();
    const reason = new Error('pre-aborted');
    controller.abort(reason);

    await expect(
      client.messages(BASIC_REQUEST, { signal: controller.signal }),
    ).rejects.toBe(reason);
  });
});

describe('TheVeil.messages() — composed signal (caller + timeout)', () => {
  it("caller aborts before timeout → caller's reason wins", async () => {
    server.use(
      http.post(MESSAGES_URL, async () => {
        await delay(500);
        return HttpResponse.json({ status: 'completed', model_used: 'x', latency_ms: 500 });
      }),
    );

    const client = new TheVeil({ apiKey: VALID_KEY });
    const controller = new AbortController();
    const reason = new Error('caller wins');

    const promise = client.messages(BASIC_REQUEST, {
      signal: controller.signal,
      timeoutMs: 300, // caller aborts first at ~20ms
    });
    setTimeout(() => controller.abort(reason), 20);

    try {
      await promise;
      expect.fail('expected caller abort to win');
    } catch (err) {
      expect(err).toBe(reason);
      expect(err).not.toBeInstanceOf(TheVeilTimeoutError);
    }
  });

  it('timeout fires before caller aborts → TheVeilTimeoutError wins', async () => {
    server.use(
      http.post(MESSAGES_URL, async () => {
        await delay(500);
        return HttpResponse.json({ status: 'completed', model_used: 'x', latency_ms: 500 });
      }),
    );

    const client = new TheVeil({ apiKey: VALID_KEY });
    const controller = new AbortController(); // never fired

    try {
      await client.messages(BASIC_REQUEST, {
        signal: controller.signal,
        timeoutMs: 50,
      });
      expect.fail('expected timeout to win');
    } catch (err) {
      expect(err).toBeInstanceOf(TheVeilTimeoutError);
      expect((err as TheVeilTimeoutError).message).toContain('50ms');
    }
  });
});

describe('MessagesRequest — compile-time typing', () => {
  it('rejects stream: true (type-level only; runtime is not exercised)', () => {
    // If the Omit/narrow on MessagesRequest regresses, the suppression
    // below will become unused and typecheck will fail — that is the point.
    const streamTrueRejected: MessagesRequest = {
      prompt_template: 'x',
      context: {},
      // @ts-expect-error streaming not supported this session.
      stream: true,
    };

    // stream: false is explicitly allowed.
    const streamFalseAllowed: MessagesRequest = {
      prompt_template: 'x',
      context: {},
      stream: false,
    };

    // Omitting stream entirely is allowed (it's optional).
    const streamOmittedAllowed: MessagesRequest = {
      prompt_template: 'x',
      context: {},
    };

    expect([streamTrueRejected, streamFalseAllowed, streamOmittedAllowed]).toHaveLength(3);
  });
});

describe('TheVeil.messages() — per-call header merge', () => {
  it('preserves caller custom headers but keeps SDK-owned headers SDK-owned', async () => {
    const captured: Record<string, string> = {};
    server.use(
      http.post(MESSAGES_URL, ({ request }) => {
        request.headers.forEach((value, key) => {
          captured[key] = value;
        });
        return HttpResponse.json({ status: 'completed', model_used: 'x', latency_ms: 1 });
      }),
    );

    const client = new TheVeil({ apiKey: VALID_KEY });
    await client.messages(BASIC_REQUEST, {
      headers: {
        'X-Request-ID': 'trace-abc-123',
        // These two must NOT override the SDK-owned values.
        'X-Api-Key': 'wrong-key',
        'Content-Type': 'text/plain',
      },
    });

    // SDK-owned: always the real key, always JSON.
    expect(captured['x-api-key']).toBe(VALID_KEY);
    expect(captured['content-type']).toBe('application/json');
    // Caller-only: preserved on its lowercased key.
    expect(captured['x-request-id']).toBe('trace-abc-123');
  });
});
