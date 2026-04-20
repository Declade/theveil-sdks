import { describe, expect, it } from 'vitest';
import {
  TheVeilCertificateError,
  TheVeilConfigError,
  TheVeilError,
  TheVeilHttpError,
  TheVeilTimeoutError,
} from './errors.js';
import type { VerifyCertificateFailureReason } from './errors.js';

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

describe('TheVeilCertificateError', () => {
  it('extends TheVeilError and carries .reason + optional .certificateId', () => {
    const err = new TheVeilCertificateError('bad sig', {
      reason: 'invalid_signature',
      certificateId: 'veil_abc',
    });
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(TheVeilError);
    expect(err).toBeInstanceOf(TheVeilCertificateError);
    expect(err.name).toBe('TheVeilCertificateError');
    expect(err.reason).toBe('invalid_signature');
    expect(err.certificateId).toBe('veil_abc');
    expect(err.message).toBe('bad sig');
  });

  it('omits certificateId cleanly when unset', () => {
    const err = new TheVeilCertificateError('boom', { reason: 'malformed' });
    expect(err.certificateId).toBeUndefined();
  });

  it('preserves cause when passed via ErrorOptions', () => {
    const underlying = new TypeError('bad key length');
    const err = new TheVeilCertificateError('sig verify fail', {
      reason: 'invalid_signature',
      cause: underlying,
    });
    expect(err.cause).toBe(underlying);
  });

  it('throws cleanly (instanceof survives throw)', () => {
    expect(() => {
      throw new TheVeilCertificateError('x', { reason: 'witness_mismatch' });
    }).toThrow(TheVeilCertificateError);
  });

  it('reason union is exhaustive over the 5 v1 reasons (compile-time check)', () => {
    // Record<Reason, true> — missing a key is a compile error, catching any
    // future rename or accidental removal of a reason literal.
    const exhaustive: Record<VerifyCertificateFailureReason, true> = {
      malformed: true,
      unsupported_protocol_version: true,
      witness_mismatch: true,
      witness_signature_missing: true,
      invalid_signature: true,
    };
    expect(Object.keys(exhaustive)).toHaveLength(5);
  });
});
