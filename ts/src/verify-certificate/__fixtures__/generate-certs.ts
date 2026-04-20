// Regenerate VeilCertificate fixtures for src/verifyCertificate.test.ts.
//
// Usage (from theveil-sdks-session-2b-cert/ts):
//
//   npx tsx src/verify-certificate/__fixtures__/generate-certs.ts
//
// All keypairs below are TEST KEY — DO NOT USE in production.
//
// CRITICAL: this generator imports `deriveWitnessSignedBytes` from the SDK.
// It MUST NOT reproduce that logic inline. If the signable derivation has
// a bug, the generator should produce data that exposes it, not quietly
// match the bug (C7 rule from the plan).
//
// Outputs (all written into this __fixtures__/ directory):
//
//   witness-keypair.json             — test Ed25519 public+secret
//   cert-valid-anchored.json         — valid cert, anchor_status.status = ANCHOR_STATUS_ANCHORED
//   cert-valid-pending.json          — valid cert, anchor_status.status = ANCHOR_STATUS_PENDING
//   cert-valid-failed.json           — valid cert, anchor_status.status = ANCHOR_STATUS_FAILED
//   cert-tampered-payload.json       — ANCHORED cert with claim_id mutated after signing
//   cert-no-signature.json           — ANCHORED cert with witness_signature = ""
//   cert-whitespace-signature.json   — ANCHORED cert with witness_signature = "   "
//   cert-protocol-version-mismatch.json  — cert with protocol_version = 999
//   cert-malformed-truncated.json    — missing witness_signature field entirely
//   cert-malformed-plus-bad-version.json — claims = "not-an-array" AND protocol_version = 999
//
// The signed-bytes construction here mirrors the gateway at
//   dual-sandbox-architecture/services/veil-witness/internal/assembler/assembler.go:117-132
// via the ported signable.ts. If that source changes, re-run this script and
// verify the happy-path verify test still passes.

import { generateKeyPairSync, sign } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { deriveWitnessSignedBytes } from '../signable.js';
import type { VeilCertificate } from '../../types.js';

const FIXTURES_DIR = __dirname;
const TEST_COMMENT = 'TEST KEY — DO NOT USE';

// Base cert shape matching the 2026-04-20 observation on 116. Values are
// synthetic but full-name-enum, nanosecond-precision-UTC, and structurally
// identical to what the gateway emits.
function buildBaseCert(): VeilCertificate {
  return {
    certificate_id: 'veil_test_0000000000000001',
    request_id: 'req_test_0000000000000001',
    protocol_version: 2,
    claims: [
      {
        claim_id: 'clm_test_token_generated_0001',
        request_id: 'req_test_0000000000000001',
        service_id: 'dsa-bridge',
        claim_type: 'CLAIM_TYPE_TOKEN_GENERATED',
        data_seen: ['customer_id'],
        data_not_seen: ['context', 'prompt_template', 'inference_result'],
        canonical_payload: Buffer.from('{"test":"bridge"}').toString('base64'),
        timestamp: '2026-04-20T05:24:09.617230313Z',
        signature: Buffer.from(new Uint8Array(64)).toString('base64'),
        bridge: { token_hash: 'AAA=', epoch: '0', encryption_enabled: true },
      },
      {
        claim_id: 'clm_test_pii_sanitized_0002',
        request_id: 'req_test_0000000000000001',
        service_id: 'dsa-sanitizer',
        claim_type: 'CLAIM_TYPE_PII_SANITIZED',
        data_seen: ['context_fields'],
        data_not_seen: ['customer_id', 'token', 'inference_result'],
        canonical_payload: Buffer.from('{"test":"sanitizer"}').toString('base64'),
        timestamp: '2026-04-20T05:24:09.666135Z',
        signature: Buffer.from(new Uint8Array(64)).toString('base64'),
        sanitizer: {
          pii_entities_found: 1,
          redaction_manifest_hash: 'AAA=',
          layers_active: ['known_entity_matching', 'presidio_ner', 'llm_pii_scan'],
        },
      },
      {
        claim_id: 'clm_test_inference_completed_0003',
        request_id: 'req_test_0000000000000001',
        service_id: 'dsa-ai',
        claim_type: 'CLAIM_TYPE_INFERENCE_COMPLETED',
        data_seen: ['opaque_token', 'sanitized_context'],
        data_not_seen: ['customer_id', 'raw_context', 'pii'],
        canonical_payload: Buffer.from('{"test":"inference"}').toString('base64'),
        timestamp: '2026-04-20T05:24:11.066748Z',
        signature: Buffer.from(new Uint8Array(64)).toString('base64'),
        inference: {
          isolation_probe: 'ISOLATION_PROBE_VERIFIED',
          model_used: 'claude-sonnet-4-20250514',
          response_hash: 'AAA=',
        },
      },
      {
        claim_id: 'clm_test_events_recorded_0004',
        request_id: 'req_test_0000000000000001',
        service_id: 'dsa-audit',
        claim_type: 'CLAIM_TYPE_EVENTS_RECORDED',
        data_seen: ['event_hashes'],
        data_not_seen: ['pii', 'context', 'inference_result'],
        canonical_payload: Buffer.from('{"test":"audit"}').toString('base64'),
        timestamp: '2026-04-20T05:24:12.704438306Z',
        signature: Buffer.from(new Uint8Array(64)).toString('base64'),
        audit: {
          event_ids: ['test_event_0001'],
          chain_head_hash: 'AAA=',
          chain_length: '1',
        },
      },
    ],
    verification: {
      signatures_valid: true,
      completeness: 'COMPLETENESS_FULL',
      missing_services: [],
      temporal_consistent: true,
      data_visibility_consistent: true,
      isolation_verified: true,
      qi_score: null,
      overall_verdict: 'VERDICT_VERIFIED',
    },
    issued_at: '2026-04-20T05:24:12.710321721Z',
    formal_verification: null,
    audit_integrity: null,
    privacy_budget: null,
    witness_signature: '', // filled in after signing
    witness_key_id: 'witness_v1',
    attestation: {
      timestamp: null,
      transparency_log: null,
      notary: {
        provider: 'dsa-veil-witness',
        notary_signature: '', // mirrored from witness_signature below
        notary_public_key_id: 'witness_v1',
        checks_performed: ['canonical_json_signing'],
        attested_at: null,
      },
    },
    anchor_status: {
      status: 'ANCHOR_STATUS_ANCHORED',
      attempts: 1,
      last_error: '',
      human_note: '',
    },
  };
}

function writeJson(name: string, value: unknown): void {
  writeFileSync(join(FIXTURES_DIR, name), JSON.stringify(value, null, 2) + '\n', 'utf8');
}

function cloneCert(cert: VeilCertificate): VeilCertificate {
  return JSON.parse(JSON.stringify(cert)) as VeilCertificate;
}

function main(): void {
  // 1. Deterministic test keypair generated fresh each run.
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const pubRaw = publicKey.export({ format: 'jwk' });
  if (typeof pubRaw.x !== 'string') {
    throw new Error('expected Ed25519 JWK with string x');
  }
  const pubB64 = Buffer.from(
    pubRaw.x.replace(/-/g, '+').replace(/_/g, '/'),
    'base64',
  ).toString('base64');
  const privRaw = privateKey.export({ format: 'jwk' });
  writeJson('witness-keypair.json', {
    _note: `${TEST_COMMENT}. Regenerated by generate-certs.ts. Public key is raw 32-byte Ed25519 base64.`,
    publicKey: pubB64,
    privateKeyJwk: privRaw,
  });

  // 2. Valid ANCHORED cert — sign the 7-field canonical JSON, populate
  //    both witness_signature and attestation.notary.notary_signature.
  const base = buildBaseCert();
  const signedBytes = deriveWitnessSignedBytes(base);
  const signature = sign(null, Buffer.from(signedBytes), privateKey);
  const signatureB64 = Buffer.from(signature).toString('base64');
  base.witness_signature = signatureB64;
  if (base.attestation?.notary) base.attestation.notary.notary_signature = signatureB64;
  writeJson('cert-valid-anchored.json', base);

  // 3. PENDING + FAILED variants — same signed payload (anchor_status
  //    is NOT part of the signed subset), only anchor_status.status flips.
  const pending = cloneCert(base);
  if (pending.anchor_status) pending.anchor_status.status = 'ANCHOR_STATUS_PENDING';
  writeJson('cert-valid-pending.json', pending);

  const failed = cloneCert(base);
  if (failed.anchor_status) failed.anchor_status.status = 'ANCHOR_STATUS_FAILED';
  writeJson('cert-valid-failed.json', failed);

  // 4. Tampered payload — mutate claim_id AFTER signing. Signed bytes
  //    change, stored witness_signature stays, verify must fire
  //    `invalid_signature`.
  const tampered = cloneCert(base);
  tampered.claims[0]!.claim_id = 'clm_test_token_generated_TAMPERED';
  writeJson('cert-tampered-payload.json', tampered);

  // 5. No-signature + whitespace-signature variants for
  //    `witness_signature_missing`.
  const noSig = cloneCert(base);
  noSig.witness_signature = '';
  writeJson('cert-no-signature.json', noSig);

  const wsSig = cloneCert(base);
  wsSig.witness_signature = '   ';
  writeJson('cert-whitespace-signature.json', wsSig);

  // 6. Protocol-version mismatch (must throw `unsupported_protocol_version`).
  const wrongVersion = cloneCert(base);
  wrongVersion.protocol_version = 999;
  writeJson('cert-protocol-version-mismatch.json', wrongVersion);

  // 7. Malformed — missing witness_signature field entirely (forces
  //    parse-level rejection). Use a plain-object cast so the fixture
  //    can carry an invalid shape without a type-check error.
  const malformed: Partial<VeilCertificate> = cloneCert(base);
  delete (malformed as { witness_signature?: string }).witness_signature;
  writeJson('cert-malformed-truncated.json', malformed);

  // 8. C5 ordering probe — malformed shape (claims is a string) AND
  //    bad protocol_version. Parse must fire first (`malformed`), not
  //    the version check.
  const malformedPlusVersion = cloneCert(base) as unknown as Record<string, unknown>;
  malformedPlusVersion.claims = 'not-an-array';
  malformedPlusVersion.protocol_version = 999;
  writeJson('cert-malformed-plus-bad-version.json', malformedPlusVersion);

  // eslint-disable-next-line no-console
  console.log(`Wrote 10 fixture files to ${FIXTURES_DIR}`);
}

main();
