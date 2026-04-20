import { TheVeilCertificateError } from '../errors.js';
import type { VeilCertificate, VeilVerificationResult } from '../types.js';

// Structural validation — asserts the shape this arc reads. Does NOT
// validate enum literal membership beyond "string" here (the signable
// derivation layer throws `malformed` on unknown verdict literals, which
// is where that check belongs semantically). Returns the narrowed type
// on success or throws TheVeilCertificateError with reason 'malformed'.
export function parseCertificate(raw: unknown): VeilCertificate {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    throw new TheVeilCertificateError('Certificate is not a JSON object', {
      reason: 'malformed',
    });
  }
  const cert = raw as Partial<VeilCertificate>;
  const certId = typeof cert.certificate_id === 'string' ? cert.certificate_id : undefined;

  if (
    typeof cert.certificate_id !== 'string' ||
    typeof cert.request_id !== 'string' ||
    typeof cert.witness_key_id !== 'string' ||
    typeof cert.witness_signature !== 'string' ||
    typeof cert.issued_at !== 'string' ||
    typeof cert.protocol_version !== 'number' ||
    !Array.isArray(cert.claims) ||
    typeof cert.verification !== 'object' ||
    cert.verification === null
  ) {
    throw new TheVeilCertificateError('Certificate missing required fields', {
      reason: 'malformed',
      certificateId: certId,
    });
  }

  // C6 — verification.overall_verdict must be a string (protojson enum
  // form). The signable derivation step later maps this string to a Go
  // int enum; reject non-string values here rather than letting them
  // cascade into a less-legible invalid_signature.
  const verif = cert.verification as Partial<VeilVerificationResult>;
  if (typeof verif.overall_verdict !== 'string') {
    throw new TheVeilCertificateError(
      'verification.overall_verdict must be a string enum literal',
      { reason: 'malformed', certificateId: certId },
    );
  }

  return cert as VeilCertificate;
}
