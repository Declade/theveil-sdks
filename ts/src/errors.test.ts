import { describe, expect, it } from 'vitest';
import {
  TheVeilConfigError,
  TheVeilError,
  TheVeilHttpError,
  TheVeilTimeoutError,
} from './errors.js';

describe('TheVeilError hierarchy', () => {
  it('TheVeilError is an Error and preserves the message', () => {
    const err = new TheVeilError('boom');
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(TheVeilError);
    expect(err.name).toBe('TheVeilError');
    expect(err.message).toBe('boom');
  });

  it('TheVeilConfigError extends TheVeilError and Error', () => {
    const err = new TheVeilConfigError('bad config');
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(TheVeilError);
    expect(err).toBeInstanceOf(TheVeilConfigError);
    expect(err.name).toBe('TheVeilConfigError');
    expect(err.message).toBe('bad config');
  });

  it('TheVeilHttpError preserves status and body', () => {
    const err = new TheVeilHttpError('nope', 503, { reason: 'degraded' });
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(TheVeilError);
    expect(err).toBeInstanceOf(TheVeilHttpError);
    expect(err.name).toBe('TheVeilHttpError');
    expect(err.status).toBe(503);
    expect(err.body).toEqual({ reason: 'degraded' });
  });

  it('TheVeilHttpError keeps a non-object body verbatim', () => {
    const err = new TheVeilHttpError('plain', 502, 'upstream timeout');
    expect(err.body).toBe('upstream timeout');
  });

  it('TheVeilTimeoutError extends TheVeilError and preserves cause', () => {
    const underlying = new Error('aborted');
    underlying.name = 'AbortError';
    const err = new TheVeilTimeoutError('timeout', { cause: underlying });
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(TheVeilError);
    expect(err).toBeInstanceOf(TheVeilTimeoutError);
    expect(err.name).toBe('TheVeilTimeoutError');
    expect(err.cause).toBe(underlying);
  });
});
