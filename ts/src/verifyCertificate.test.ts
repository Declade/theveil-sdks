import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { generateKeyPairSync, sign, type JsonWebKey } from 'node:crypto';
import { normalizeEd25519PublicKey } from './verify-certificate/keys.js';
import { verifyEd25519 } from './verify-certificate/signature.js';
import { verifyCertificate } from './verify-certificate/index.js';
import { TheVeilCertificateError } from './errors.js';
import type { VeilCertificate, VerifyCertificateKeys } from './types.js';

const fixturesDir = join(__dirname, 'verify-certificate', '__fixtures__');

function loadFixture<T = VeilCertificate>(name: string): T {
  return JSON.parse(readFileSync(join(fixturesDir, name), 'utf8')) as T;
}

interface WitnessKeypairFixture {
  publicKey: string; // base64 raw 32B
  privateKeyJwk: JsonWebKey;
}

function keysAll(): VerifyCertificateKeys {
  const kp = loadFixture<WitnessKeypairFixture>('witness-keypair.json');
  return {
    witnessKeyId: 'witness_v1',
    witnessPublicKey: kp.publicKey,
  };
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

describe('verifyCertificate — failure reasons', () => {
  it('throws malformed when cert is not a JSON object', async () => {
    await expect(
      verifyCertificate(null as unknown as VeilCertificate, keysAll()),
    ).rejects.toMatchObject({ reason: 'malformed' });
    await expect(
      verifyCertificate('string' as unknown as VeilCertificate, keysAll()),
    ).rejects.toMatchObject({ reason: 'malformed' });
    await expect(
      verifyCertificate([] as unknown as VeilCertificate, keysAll()),
    ).rejects.toMatchObject({ reason: 'malformed' });
  });

  it('throws malformed when required fields are missing', async () => {
    await expect(
      verifyCertificate(loadFixture('cert-malformed-truncated.json'), keysAll()),
    ).rejects.toMatchObject({ reason: 'malformed' });
  });

  it('throws malformed when cert.request_id != cert.claims[0].request_id (gateway invariant)', async () => {
    const cert = loadFixture('cert-valid-anchored.json');
    cert.request_id = 'req_different_from_claims';
    await expect(verifyCertificate(cert, keysAll())).rejects.toMatchObject({
      reason: 'malformed',
    });
  });

  it('throws malformed on unknown overall_verdict enum literal', async () => {
    const cert = loadFixture('cert-valid-anchored.json');
    (cert.verification as { overall_verdict: string }).overall_verdict =
      'VERDICT_FUTURE_VALUE';
    await expect(verifyCertificate(cert, keysAll())).rejects.toMatchObject({
      reason: 'malformed',
    });
  });

  it('throws unsupported_protocol_version for non-2 protocol_version', async () => {
    await expect(
      verifyCertificate(loadFixture('cert-protocol-version-mismatch.json'), keysAll()),
    ).rejects.toMatchObject({ reason: 'unsupported_protocol_version' });
  });

  it('throws witness_mismatch when keys.witnessKeyId differs from cert.witness_key_id', async () => {
    await expect(
      verifyCertificate(loadFixture('cert-valid-anchored.json'), {
        ...keysAll(),
        witnessKeyId: 'different-label',
      }),
    ).rejects.toMatchObject({ reason: 'witness_mismatch' });
  });

  it('throws witness_signature_missing when witness_signature is empty', async () => {
    await expect(
      verifyCertificate(loadFixture('cert-no-signature.json'), keysAll()),
    ).rejects.toMatchObject({ reason: 'witness_signature_missing' });
  });

  it('throws witness_signature_missing when witness_signature is whitespace-only', async () => {
    await expect(
      verifyCertificate(loadFixture('cert-whitespace-signature.json'), keysAll()),
    ).rejects.toMatchObject({ reason: 'witness_signature_missing' });
  });

  it('throws invalid_signature when cert payload is tampered after signing', async () => {
    await expect(
      verifyCertificate(loadFixture('cert-tampered-payload.json'), keysAll()),
    ).rejects.toMatchObject({ reason: 'invalid_signature' });
  });

  it('throws invalid_signature with preserved TypeError on malformed witnessPublicKey', async () => {
    try {
      await verifyCertificate(loadFixture('cert-valid-anchored.json'), {
        witnessKeyId: 'witness_v1',
        witnessPublicKey: new Uint8Array(16), // wrong length
      });
      throw new Error('expected to throw');
    } catch (err) {
      expect(err).toBeInstanceOf(TheVeilCertificateError);
      const typed = err as TheVeilCertificateError;
      expect(typed.reason).toBe('invalid_signature');
      expect(typed.cause).toBeInstanceOf(TypeError);
    }
  });
});

describe('verifyCertificate — happy paths', () => {
  it('returns VerifyCertificateResult on valid ANCHORED cert, including ISO timestamp', async () => {
    const cert = loadFixture('cert-valid-anchored.json');
    const result = await verifyCertificate(cert, keysAll());
    expect(result).toEqual({
      certificateId: cert.certificate_id,
      requestId: cert.request_id,
      witnessKeyId: 'witness_v1',
      witnessAssertedIssuedAt: new Date(cert.issued_at),
      witnessAssertedIssuedAtIso: cert.issued_at,
      anchorStatus: 'ANCHOR_STATUS_ANCHORED',
      overallVerdict: 'VERDICT_VERIFIED',
    });
  });

  it('passes anchor_status PENDING through without gating verification', async () => {
    // Same signed payload — anchor_status is NOT in the signed subset.
    const result = await verifyCertificate(loadFixture('cert-valid-pending.json'), keysAll());
    expect(result.anchorStatus).toBe('ANCHOR_STATUS_PENDING');
  });

  it('passes anchor_status FAILED through without throwing (deferred to 2b-cert-strong)', async () => {
    const result = await verifyCertificate(loadFixture('cert-valid-failed.json'), keysAll());
    expect(result.anchorStatus).toBe('ANCHOR_STATUS_FAILED');
  });
});

describe('verifyCertificate — ordering + error shape', () => {
  it('stops at malformed before protocol-version / witness-id checks', async () => {
    await expect(
      verifyCertificate(loadFixture('cert-malformed-truncated.json'), {
        witnessKeyId: 'any',
        witnessPublicKey: new Uint8Array(32),
      }),
    ).rejects.toMatchObject({ reason: 'malformed' });
  });

  // C5 — full ordering lock-in. Cert is BOTH malformed (claims is a string
  // not an array) AND has wrong protocol_version. Parse must fire first so
  // verify returns `malformed`, not `unsupported_protocol_version`.
  it('stops at malformed before unsupported_protocol_version (parse wins)', async () => {
    await expect(
      verifyCertificate(
        loadFixture('cert-malformed-plus-bad-version.json'),
        keysAll(),
      ),
    ).rejects.toMatchObject({ reason: 'malformed' });
  });

  it('stops at unsupported_protocol_version before witness-id check', async () => {
    await expect(
      verifyCertificate(loadFixture('cert-protocol-version-mismatch.json'), {
        ...keysAll(),
        witnessKeyId: 'wrong-label',
      }),
    ).rejects.toMatchObject({ reason: 'unsupported_protocol_version' });
  });

  it('TheVeilCertificateError.certificateId is populated when cert parses', async () => {
    try {
      await verifyCertificate(loadFixture('cert-tampered-payload.json'), keysAll());
      throw new Error('expected to throw');
    } catch (err) {
      expect(err).toBeInstanceOf(TheVeilCertificateError);
      const typed = err as TheVeilCertificateError;
      expect(typed.reason).toBe('invalid_signature');
      expect(typed.certificateId).toBe(
        loadFixture('cert-tampered-payload.json').certificate_id,
      );
    }
  });

  it('TheVeilCertificateError.certificateId is undefined when cert fails structural parse', async () => {
    try {
      await verifyCertificate('garbage' as unknown as VeilCertificate, keysAll());
      throw new Error('expected to throw');
    } catch (err) {
      expect(err).toBeInstanceOf(TheVeilCertificateError);
      expect((err as TheVeilCertificateError).certificateId).toBeUndefined();
    }
  });
});

describe('TheVeil#verifyCertificate client delegation', () => {
  // Client-level smoke test — ensures the public method on TheVeil
  // delegates to the standalone verify function without drift.
  it('delegates to verify-certificate/index and returns the same result shape', async () => {
    // Avoid cross-file import cycles by importing inline.
    const { TheVeil } = await import('./client.js');
    const client = new TheVeil({ apiKey: 'dsa_' + '0'.repeat(32) });
    const cert = loadFixture('cert-valid-anchored.json');
    const result = await client.verifyCertificate(cert, keysAll());
    expect(result.witnessKeyId).toBe('witness_v1');
    expect(result.anchorStatus).toBe('ANCHOR_STATUS_ANCHORED');
    expect(result.overallVerdict).toBe('VERDICT_VERIFIED');
  });
});
