import { describe, expect, it } from 'vitest';
import { TheVeil } from './client.js';
import { TheVeilConfigError } from './errors.js';

const VALID_KEY = 'dsa_0123456789abcdef0123456789abcdef';

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
    expect(client.baseUrl).toBe('https://vault.dsaveil.io');
  });

  it('applies the default timeoutMs when none is supplied', () => {
    const client = new TheVeil({ apiKey: VALID_KEY });
    expect(client.timeoutMs).toBe(30_000);
  });

  it('accepts a valid baseUrl and strips trailing slashes', () => {
    const client = new TheVeil({ apiKey: VALID_KEY, baseUrl: 'https://vault.example.com/' });
    expect(client.baseUrl).toBe('https://vault.example.com');
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
