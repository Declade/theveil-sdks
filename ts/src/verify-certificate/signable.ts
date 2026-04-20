// Port of
//   dual-sandbox-architecture/services/veil-witness/internal/assembler/assembler.go:117-132.
//
// TODO(proxy-sync): keep the 7-key set and Go-int enum mapping in lockstep
// with the Go source. Any change to the assembler's signable construction
// (added key, renamed key, changed enum-to-int mapping, changed issued_at
// format) must land here in the same arc.
//
// Gateway invariant enforced defensively:
//   cert.request_id === cert.claims[0].request_id
// The Go assembler reads claims[0].RequestId for the signed subset; the TS
// port adds a guard so drift surfaces loudly (throws `malformed`) rather
// than silently failing as `invalid_signature` on a cert with a valid
// signature computed over a different request_id.

import { canonicalJson, rawIntegerNumber } from './canonical-json.js';
import { TheVeilCertificateError } from '../errors.js';
import type { VeilCertificate, VeilVerdict } from '../types.js';

const VERDICT_TO_INT: Record<VeilVerdict, number> = {
  VERDICT_UNSPECIFIED: 0,
  VERDICT_VERIFIED: 1,
  VERDICT_PARTIAL: 2,
  VERDICT_FAILED: 3,
};

export function deriveWitnessSignedBytes(cert: VeilCertificate): Uint8Array {
  // C2 defensive guard — fail loudly on invariant drift. Optional chaining
  // on an empty claims[] yields undefined; strict-inequality catches it
  // and produces a single clean `malformed` throw rather than a downstream
  // `invalid_signature` that looks identical to tamper/wrong-key.
  if (cert.claims[0]?.request_id !== cert.request_id) {
    throw new TheVeilCertificateError(
      'cert.request_id does not match cert.claims[0].request_id (gateway invariant violated)',
      { reason: 'malformed', certificateId: cert.certificate_id },
    );
  }

  // C3 + C6 — unknown verdict literal means schema drift. Emit `malformed`
  // so the caller gets a clear "upgrade your SDK" signal rather than a
  // misleading `invalid_signature` on what may be a legitimate signature
  // over a newer enum value.
  const verdictInt = VERDICT_TO_INT[cert.verification.overall_verdict];
  if (verdictInt === undefined) {
    throw new TheVeilCertificateError(
      `Unknown verification.overall_verdict literal: ${cert.verification.overall_verdict} — SDK may be out of date`,
      { reason: 'malformed', certificateId: cert.certificate_id },
    );
  }

  const signable = {
    certificate_id: cert.certificate_id,
    request_id: cert.request_id,
    protocol_version: rawIntegerNumber(2),
    claim_ids: cert.claims.map((c) => c.claim_id),
    issued_at: cert.issued_at,
    overall_verdict: rawIntegerNumber(verdictInt),
    witness_key_id: cert.witness_key_id,
  };
  return canonicalJson(signable);
}
