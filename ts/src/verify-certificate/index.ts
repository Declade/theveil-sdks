import { TheVeilCertificateError } from '../errors.js';
import type {
  VeilCertificate,
  VerifyCertificateKeys,
  VerifyCertificateResult,
} from '../types.js';
import { parseCertificate } from './parse.js';
import { deriveWitnessSignedBytes } from './signable.js';
import { verifyEd25519 } from './signature.js';

const SUPPORTED_PROTOCOL_VERSION = 2;

/**
 * Verify a Veil Certificate's witness Ed25519 signature against the
 * certificate's canonical JSON core fields (7-field subset per the Veil
 * witness assembler).
 *
 * External RFC 3161 timestamp verification and Sigstore Rekor transparency-
 * log verification are OUT OF SCOPE for this arc; they land in a follow-up
 * arc (2b-cert-strong) pending gateway fixes:
 *   - Declade/dual-sandbox-architecture#42 (anchor_status reliability bug)
 *   - Declade/dual-sandbox-architecture#43 (populate attestation.timestamp)
 *   - Declade/dual-sandbox-architecture#44 (populate attestation.transparency_log)
 *
 * The result surfaces `anchorStatus` and `overallVerdict` as pass-through
 * metadata with JSDoc caveats — the SDK does NOT independently verify them.
 *
 * @param rawCert - protojson-shaped `VeilCertificate` as served by the
 *   gateway at GET /api/v1/veil/certificate/{request_id}. This arc does
 *   NOT fetch the certificate; the caller is responsible for transport.
 * @param keys.witnessKeyId - expected operator-configured label (e.g.
 *   "witness_v1") asserted against `cert.witness_key_id`. Mismatch throws
 *   `TheVeilCertificateError({ reason: 'witness_mismatch' })` before any
 *   signature check runs.
 * @param keys.witnessPublicKey - raw 32-byte Ed25519 public key as
 *   `Uint8Array`, OR a base64 string encoding those 32 bytes. NOT PEM
 *   SPKI. Malformed input surfaces as
 *   `TheVeilCertificateError({ reason: 'invalid_signature', cause })`.
 *
 * @returns `VerifyCertificateResult` on success. The witness-asserted
 *   issued-at appears in two forms: `witnessAssertedIssuedAt: Date`
 *   (millisecond precision, ergonomic) and `witnessAssertedIssuedAtIso:
 *   string` (full RFC 3339 precision, exactly as signed).
 *
 * @throws `TheVeilCertificateError` with one of 5 reasons:
 *   - `malformed` — cert shape invalid, or gateway invariant broken
 *     (cert.request_id mismatch vs claims[0]), or unknown verdict literal
 *   - `unsupported_protocol_version` — cert.protocol_version !== 2
 *   - `witness_mismatch` — keys.witnessKeyId !== cert.witness_key_id
 *   - `witness_signature_missing` — cert.witness_signature is empty or
 *     whitespace-only
 *   - `invalid_signature` — Ed25519 verification failed, or the provided
 *     witnessPublicKey is malformed
 */
export async function verifyCertificate(
  rawCert: unknown,
  keys: VerifyCertificateKeys,
): Promise<VerifyCertificateResult> {
  // Guard: null/undefined/non-object keys argument. TS strict mode catches
  // this at compile time, but untyped JS callers, JSON-RPC bridges, and
  // cross-language embedders would otherwise see a raw "Cannot read
  // properties of null" TypeError. Surface it as TypeError (programmer
  // error), not as TheVeilCertificateError — wrong input to the SDK is
  // not a cert-verification failure.
  if (keys === null || typeof keys !== 'object') {
    throw new TypeError('verifyCertificate: keys argument is required');
  }

  // Step 1: structural parse → malformed on bad shape / missing required
  // fields / non-string overall_verdict.
  const cert = parseCertificate(rawCert);

  // Step 2: protocol-version guard — forward-compat escape hatch. A newer
  // gateway that emits protocol_version=3 with a different signing rule
  // would otherwise silently fail invalid_signature; this surfaces the
  // "upgrade your SDK" intent loudly.
  if (cert.protocol_version !== SUPPORTED_PROTOCOL_VERSION) {
    throw new TheVeilCertificateError(
      `Unsupported Veil protocol version: ${cert.protocol_version} (SDK supports ${SUPPORTED_PROTOCOL_VERSION})`,
      { reason: 'unsupported_protocol_version', certificateId: cert.certificate_id },
    );
  }

  // Step 3: witness identity — cheap string check before any crypto work.
  if (cert.witness_key_id !== keys.witnessKeyId) {
    throw new TheVeilCertificateError(
      `Witness key ID mismatch: cert has "${cert.witness_key_id}", expected "${keys.witnessKeyId}"`,
      { reason: 'witness_mismatch', certificateId: cert.certificate_id },
    );
  }

  // Step 4: signature presence. trim() routes "" AND whitespace-only
  // signatures to the same reason — "   " base64-decodes to empty bytes
  // which would otherwise surface as a confusing invalid_signature.
  if (cert.witness_signature.trim().length === 0) {
    throw new TheVeilCertificateError('Certificate has no witness signature', {
      reason: 'witness_signature_missing',
      certificateId: cert.certificate_id,
    });
  }

  // Step 5: derive canonical signed bytes + Ed25519 verify.
  //
  // deriveWitnessSignedBytes may itself throw `malformed` (C2/C3 guards
  // for the gateway invariant + unknown verdict literal + non-string
  // claim_id elements). It may also throw TypeError from the canonical
  // JSON encoder for structurally-valid-but-semantically-invalid inputs
  // (e.g., naked JS numbers from a JS-only caller bypassing TS types,
  // circular references, unsupported value types). Wrap those as
  // `malformed` so callers always get a typed error and the 5-reason
  // contract holds even under adversarial JS-only inputs.
  //
  // Key-normalization TypeErrors from verifyEd25519 (wrong key length,
  // null key input, etc.) are wrapped as `invalid_signature` so a
  // caller who passed a malformed key still gets a typed error with
  // the original TypeError preserved on .cause.
  let signedBytes: Uint8Array;
  try {
    signedBytes = deriveWitnessSignedBytes(cert);
  } catch (err) {
    if (err instanceof TheVeilCertificateError) throw err;
    if (err instanceof TypeError) {
      throw new TheVeilCertificateError(
        `Failed to derive signed payload: ${err.message}`,
        { reason: 'malformed', certificateId: cert.certificate_id, cause: err },
      );
    }
    throw err;
  }
  const signatureBytes = new Uint8Array(Buffer.from(cert.witness_signature, 'base64'));
  let valid: boolean;
  try {
    valid = verifyEd25519(signedBytes, signatureBytes, keys.witnessPublicKey);
  } catch (err) {
    if (err instanceof TypeError) {
      throw new TheVeilCertificateError(`Invalid witnessPublicKey: ${err.message}`, {
        reason: 'invalid_signature',
        certificateId: cert.certificate_id,
        cause: err,
      });
    }
    throw err;
  }
  if (!valid) {
    throw new TheVeilCertificateError('Witness Ed25519 signature verification failed', {
      reason: 'invalid_signature',
      certificateId: cert.certificate_id,
    });
  }

  return buildResult(cert);
}

function buildResult(cert: VeilCertificate): VerifyCertificateResult {
  return {
    certificateId: cert.certificate_id,
    requestId: cert.request_id,
    witnessKeyId: cert.witness_key_id,
    witnessAssertedIssuedAt: new Date(cert.issued_at),
    witnessAssertedIssuedAtIso: cert.issued_at,
    anchorStatus: cert.anchor_status?.status ?? 'ANCHOR_STATUS_UNSPECIFIED',
    overallVerdict: cert.verification.overall_verdict,
  };
}
