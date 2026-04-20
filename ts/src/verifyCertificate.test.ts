import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { generateKeyPairSync, sign, type JsonWebKey } from 'node:crypto';
import { normalizeEd25519PublicKey } from './verify-certificate/keys.js';
import { verifyEd25519 } from './verify-certificate/signature.js';
import type { VeilCertificate } from './types.js';

const fixturesDir = join(__dirname, 'verify-certificate', '__fixtures__');

function loadFixture<T = VeilCertificate>(name: string): T {
  return JSON.parse(readFileSync(join(fixturesDir, name), 'utf8')) as T;
}

// Extract the raw 32-byte Ed25519 public key from a node:crypto KeyObject.
// Node's Ed25519 public-key JWK format carries `x` as base64url of the raw
// 32 bytes.
function rawPubFromKeyObject(pk: {
  export(options: { format: 'jwk' }): JsonWebKey;
}): Uint8Array {
  const jwk = pk.export({ format: 'jwk' });
  if (typeof jwk.x !== 'string') {
    throw new Error('expected Ed25519 JWK with string x');
  }
  const b64 = jwk.x.replace(/-/g, '+').replace(/_/g, '/');
  return new Uint8Array(Buffer.from(b64, 'base64'));
}

describe('normalizeEd25519PublicKey', () => {
  it('passes Uint8Array of length 32 through', () => {
    const key = new Uint8Array(32).fill(0xaa);
    expect(normalizeEd25519PublicKey(key)).toEqual(key);
  });

  it('decodes base64 string into 32 bytes', () => {
    const bytes = new Uint8Array(32).fill(0xbb);
    const b64 = Buffer.from(bytes).toString('base64');
    expect(normalizeEd25519PublicKey(b64)).toEqual(bytes);
  });

  it('throws TypeError for wrong length (too short)', () => {
    expect(() => normalizeEd25519PublicKey(new Uint8Array(16))).toThrow(TypeError);
  });

  it('throws TypeError for wrong length (too long)', () => {
    expect(() => normalizeEd25519PublicKey(new Uint8Array(64))).toThrow(TypeError);
  });

  it('throws TypeError for non-string non-bytes input', () => {
    expect(() => normalizeEd25519PublicKey(42 as unknown as string)).toThrow(TypeError);
    expect(() => normalizeEd25519PublicKey(null as unknown as string)).toThrow(TypeError);
  });
});

describe('verifyEd25519', () => {
  it('verifies a signature produced by node:crypto sign() over the same message', () => {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const message = new TextEncoder().encode('the quick brown fox');
    const signature = sign(null, Buffer.from(message), privateKey);
    const raw = rawPubFromKeyObject(publicKey);
    expect(verifyEd25519(message, new Uint8Array(signature), raw)).toBe(true);
  });

  it('returns false for tampered signature', () => {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const message = new TextEncoder().encode('the quick brown fox');
    const sig = sign(null, Buffer.from(message), privateKey);
    sig[0] ^= 0x01; // flip one bit
    const raw = rawPubFromKeyObject(publicKey);
    expect(verifyEd25519(message, new Uint8Array(sig), raw)).toBe(false);
  });

  it('returns false for a message modified after signing', () => {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const original = new TextEncoder().encode('the quick brown fox');
    const sig = sign(null, Buffer.from(original), privateKey);
    const tampered = new TextEncoder().encode('the quick brown foz');
    const raw = rawPubFromKeyObject(publicKey);
    expect(verifyEd25519(tampered, new Uint8Array(sig), raw)).toBe(false);
  });

  it('accepts the public key as a base64 string', () => {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const message = new TextEncoder().encode('hello');
    const signature = sign(null, Buffer.from(message), privateKey);
    const raw = rawPubFromKeyObject(publicKey);
    const b64 = Buffer.from(raw).toString('base64');
    expect(verifyEd25519(message, new Uint8Array(signature), b64)).toBe(true);
  });

  it('throws TypeError when the public key input is not a valid Ed25519 key', () => {
    const message = new TextEncoder().encode('hello');
    const sig = new Uint8Array(64);
    expect(() => verifyEd25519(message, sig, new Uint8Array(16))).toThrow(TypeError);
  });
});

describe('cert fixtures loadable', () => {
  it('cert-valid-anchored.json matches expected shape', () => {
    const cert = loadFixture('cert-valid-anchored.json');
    expect(cert.protocol_version).toBe(2);
    expect(cert.anchor_status?.status).toBe('ANCHOR_STATUS_ANCHORED');
    expect(cert.verification.overall_verdict).toBe('VERDICT_VERIFIED');
    expect(cert.witness_signature).toBeTruthy();
    expect(cert.witness_key_id).toBe('witness_v1');
  });

  // B2 — lock in the protojson-UTC assumption. If the gateway ever ships
  // a `+00:00` suffix instead of `Z`, this fails loudly so signable
  // reconstruction doesn't silently produce `invalid_signature` on valid
  // certs.
  it('cert.issued_at terminates in Z (protojson UTC form)', () => {
    expect(loadFixture('cert-valid-anchored.json').issued_at).toMatch(/Z$/);
  });

  it('pending + failed + tampered variants parse as JSON', () => {
    expect(loadFixture('cert-valid-pending.json').anchor_status?.status).toBe(
      'ANCHOR_STATUS_PENDING',
    );
    expect(loadFixture('cert-valid-failed.json').anchor_status?.status).toBe(
      'ANCHOR_STATUS_FAILED',
    );
    expect(loadFixture('cert-tampered-payload.json').claims[0]?.claim_id).toMatch(
      /TAMPERED$/,
    );
  });

  it('no-signature + whitespace-signature variants have empty/whitespace witness_signature', () => {
    expect(loadFixture('cert-no-signature.json').witness_signature).toBe('');
    expect(loadFixture('cert-whitespace-signature.json').witness_signature).toMatch(
      /^\s+$/,
    );
  });

  it('protocol-version-mismatch variant carries non-2 protocol_version', () => {
    expect(loadFixture('cert-protocol-version-mismatch.json').protocol_version).toBe(
      999,
    );
  });
});
