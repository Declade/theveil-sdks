// Port of
//   dual-sandbox-architecture/services/veil-witness/internal/assembler/assembler.go:117-132.
//
// TODO(proxy-sync): keep the 7-key set, the Go short-form enum mapping, and
// the string-vs-number encoding of each field in lockstep with the Go source.
// Any change to the assembler's signable construction must land here in the
// same arc.
//
// Gateway invariant enforced defensively:
//   cert.request_id === cert.claims[0].request_id
// The Go assembler reads claims[0].RequestId for the signed subset; the TS
// port adds a guard so drift surfaces loudly (throws `malformed`) rather
// than silently failing as `invalid_signature` on a cert with a valid
// signature computed over a different request_id.
//
// CRITICAL ENCODING NOTE (resolved 2026-04-20 after contract-drift-detector
// caught it):
//   The Go assembler signs `vr.OverallVerdict` (verifier.go:56 — type
//   `string`) DIRECTLY. vr.OverallVerdict holds short-form strings like
//   "VERIFIED", NOT the proto enum integer and NOT the full-name protojson
//   form "VERDICT_VERIFIED". Therefore the signable emits a JSON string
//   (quoted) via canonical JSON's default string path — NOT an integer
//   via rawIntegerNumber. An earlier version of this file mapped to
//   integer; that version silently disagreed with Go byte-for-byte on
//   every real gateway cert and was only caught by the cert-oracle
//   fixture (cert-go-signed-reference.json), not by the canonical-JSON
//   golden fixture (which tested canonicalJson in isolation and agreed
//   with Go on a closed TS→TS loop).
//
// Protojson → Go short-form mapping: the gateway emits full-name
// VERDICT_* literals on the wire (UseProtoNames + default enum
// serialization); the witness signs the short-form. The SDK must convert.

import { canonicalJson, rawIntegerNumber } from './canonical-json.js';
import { TheVeilCertificateError } from '../errors.js';
import type { VeilCertificate, VeilVerdict } from '../types.js';

// Null-prototype object so key lookups never hit Object.prototype. With a
// plain object literal, `VERDICT_FULL_TO_SHORT['__proto__']` returns
// Object.prototype (truthy, not undefined), bypassing membership checks.
// Combined with Object.hasOwn below, this is defense-in-depth.
const VERDICT_FULL_TO_SHORT: Record<VeilVerdict, string> = Object.assign(
  Object.create(null) as Record<VeilVerdict, string>,
  {
    VERDICT_UNSPECIFIED: 'UNSPECIFIED',
    VERDICT_VERIFIED: 'VERIFIED',
    VERDICT_PARTIAL: 'PARTIAL',
    VERDICT_FAILED: 'FAILED',
  } satisfies Record<VeilVerdict, string>,
);

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

  // C3 + C6 — unknown verdict literal means schema drift. Object.hasOwn
  // avoids the Object.prototype pollution footgun (`__proto__` /
  // `constructor` / `toString` etc. would otherwise resolve truthy via
  // the prototype chain and bypass `=== undefined` checks on a plain
  // object literal).
  const fullName = cert.verification.overall_verdict;
  if (!Object.hasOwn(VERDICT_FULL_TO_SHORT, fullName)) {
    throw new TheVeilCertificateError(
      `Unknown verification.overall_verdict literal: ${fullName} — SDK may be out of date`,
      { reason: 'malformed', certificateId: cert.certificate_id },
    );
  }
  const goShortForm = VERDICT_FULL_TO_SHORT[fullName];

  // Validate each claim element carries a string claim_id — bug-hunter C1.
  // Without this, a JS-only caller with `claims: [{claim_id: null}]` would
  // pass structural parse + C2 and surface as a raw TypeError from
  // canonical-json's "unsupported value type undefined/null" path.
  const claimIds: string[] = cert.claims.map((c, i) => {
    if (!c || typeof c.claim_id !== 'string') {
      throw new TheVeilCertificateError(
        `cert.claims[${i}].claim_id must be a string`,
        { reason: 'malformed', certificateId: cert.certificate_id },
      );
    }
    return c.claim_id;
  });

  // The signable map mirrors Go assembler.go:117-125 field-for-field.
  // protocol_version: Go int 2 → JSON integer 2 (via rawIntegerNumber).
  // overall_verdict: Go short string → JSON quoted string (via default
  //   string path — canonicalJson applies HTML-safe escape automatically).
  // All other fields are strings or string arrays, pass-through.
  const signable = {
    certificate_id: cert.certificate_id,
    request_id: cert.request_id,
    protocol_version: rawIntegerNumber(2),
    claim_ids: claimIds,
    issued_at: cert.issued_at,
    overall_verdict: goShortForm,
    witness_key_id: cert.witness_key_id,
  };
  return canonicalJson(signable);
}
