import { http, HttpResponse } from 'msw';
import { describe, expect, it } from 'vitest';
import { Lucairn } from './client.js';
import { LucairnError, LucairnHttpError } from './errors.js';
import { server } from './test-server.js';

// Obviously-fake API key — same shape as the rest of the suite.
const VALID_KEY = 'dsa_0123456789abcdef0123456789abcdef';
const BASE = 'https://gateway.lucairn.eu';
const SUMMARY_URL_PREFIX = `${BASE}/api/v1/veil/certificate/`;

const READY_HTML = '<!DOCTYPE html><html><head><title>Veil Certificate</title></head><body><h1>Verified</h1></body></html>';
const PENDING_HTML = '<!DOCTYPE html><html><head><title>Veil Certificate Pending</title></head><body><div class="pending">PENDING</div></body></html>';

describe('Lucairn.getCertificateSummary() — happy path (200 text/html)', () => {
  it('returns the rendered HTML body verbatim', async () => {
    server.use(
      http.get(`${SUMMARY_URL_PREFIX}:id/summary`, () =>
        new HttpResponse(READY_HTML, {
          status: 200,
          headers: { 'content-type': 'text/html; charset=utf-8' },
        }),
      ),
    );

    const client = new Lucairn({ apiKey: VALID_KEY });
    const html = await client.getCertificateSummary('req_test_0000000000000001');
    expect(html).toBe(READY_HTML);
  });

  it('sends x-api-key header and targets the summary path', async () => {
    let capturedUrl = '';
    const capturedHeaders: Record<string, string> = {};
    server.use(
      http.get(`${SUMMARY_URL_PREFIX}:id/summary`, ({ request }) => {
        capturedUrl = request.url;
        request.headers.forEach((value, key) => {
          capturedHeaders[key] = value;
        });
        return new HttpResponse(READY_HTML, {
          status: 200,
          headers: { 'content-type': 'text/html; charset=utf-8' },
        });
      }),
    );

    const client = new Lucairn({ apiKey: VALID_KEY });
    await client.getCertificateSummary('req_test_0000000000000001');

    expect(capturedUrl).toBe(`${SUMMARY_URL_PREFIX}req_test_0000000000000001/summary`);
    expect(capturedHeaders['x-api-key']).toBe(VALID_KEY);
  });

  it('percent-encodes reserved characters in requestId', async () => {
    let capturedUrl = '';
    server.use(
      http.get(`${SUMMARY_URL_PREFIX}:id/summary`, ({ request }) => {
        capturedUrl = request.url;
        return new HttpResponse(READY_HTML, {
          status: 200,
          headers: { 'content-type': 'text/html; charset=utf-8' },
        });
      }),
    );

    const client = new Lucairn({ apiKey: VALID_KEY });
    await client.getCertificateSummary('req/weird id?');

    expect(capturedUrl).toBe(`${SUMMARY_URL_PREFIX}req%2Fweird%20id%3F/summary`);
  });
});

describe('Lucairn.getCertificateSummary() — 202 pending', () => {
  it('throws LucairnHttpError with .status=202 and the pending HTML body', async () => {
    server.use(
      http.get(`${SUMMARY_URL_PREFIX}:id/summary`, () =>
        new HttpResponse(PENDING_HTML, {
          status: 202,
          headers: { 'content-type': 'text/html; charset=utf-8' },
        }),
      ),
    );

    const client = new Lucairn({ apiKey: VALID_KEY });
    try {
      await client.getCertificateSummary('req_pending_0001');
      expect.fail('expected 202 pending to throw LucairnHttpError');
    } catch (err) {
      expect(err).toBeInstanceOf(LucairnHttpError);
      const httpErr = err as LucairnHttpError;
      expect(httpErr.status).toBe(202);
      expect(httpErr.body).toBe(PENDING_HTML);
    }
  });
});

describe('Lucairn.getCertificateSummary() — HTTP error mapping', () => {
  it('maps 401 missing_api_key to LucairnHttpError with JSON error body', async () => {
    const errBody = { error: { code: 'missing_api_key', message: 'API key is required.' } };
    server.use(
      http.get(`${SUMMARY_URL_PREFIX}:id/summary`, () =>
        HttpResponse.json(errBody, { status: 401 }),
      ),
    );

    const client = new Lucairn({ apiKey: VALID_KEY });
    try {
      await client.getCertificateSummary('req_err_0001');
      expect.fail('expected 401 to throw');
    } catch (err) {
      expect(err).toBeInstanceOf(LucairnHttpError);
      expect(err).toBeInstanceOf(LucairnError);
      const httpErr = err as LucairnHttpError;
      expect(httpErr.status).toBe(401);
      expect(httpErr.body).toEqual(errBody);
    }
  });

  it('maps 404 veil_not_configured to LucairnHttpError', async () => {
    const errBody = {
      error: { code: 'veil_not_configured', message: 'Veil Protocol is not enabled on this instance.' },
    };
    server.use(
      http.get(`${SUMMARY_URL_PREFIX}:id/summary`, () =>
        HttpResponse.json(errBody, { status: 404 }),
      ),
    );

    const client = new Lucairn({ apiKey: VALID_KEY });
    try {
      await client.getCertificateSummary('req_err_0002');
      expect.fail('expected 404 to throw');
    } catch (err) {
      expect(err).toBeInstanceOf(LucairnHttpError);
      const httpErr = err as LucairnHttpError;
      expect(httpErr.status).toBe(404);
      expect(httpErr.body).toEqual(errBody);
    }
  });
});
