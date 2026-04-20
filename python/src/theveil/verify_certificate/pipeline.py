"""Verify-certificate pipeline — parse → canonical → signature → result."""

from __future__ import annotations

import base64
from datetime import datetime
from typing import Any

from theveil.errors import TheVeilCertificateError
from theveil.types import (
    VeilCertificate,
    VerifyCertificateKeys,
    VerifyCertificateResult,
)
from theveil.verify_certificate.parse import parse_certificate
from theveil.verify_certificate.signable import derive_witness_signed_bytes
from theveil.verify_certificate.signature import verify_ed25519

__all__ = ["verify_certificate"]


SUPPORTED_PROTOCOL_VERSION = 2


def verify_certificate(
    raw_cert: Any,
    keys: VerifyCertificateKeys,
) -> VerifyCertificateResult:
    """Verify a Veil Certificate's witness Ed25519 signature.

    External RFC 3161 timestamp verification and Sigstore Rekor
    transparency-log verification are OUT OF SCOPE for this SDK release;
    they land in a follow-up arc (2b-cert-strong) pending gateway fixes.
    The result surfaces ``anchor_status`` and ``overall_verdict`` as
    pass-through metadata — the SDK does NOT independently verify them.

    Args:
        raw_cert: protojson-shaped certificate body as returned by
            ``GET /api/v1/veil/certificate/{request_id}``. Either a
            ``dict`` or an already-parsed :class:`VeilCertificate`.
        keys: trust-root keys (:class:`VerifyCertificateKeys`).

    Returns:
        :class:`VerifyCertificateResult` on success.

    Raises:
        TheVeilCertificateError: with ``reason`` in one of:

          * ``malformed`` — cert shape invalid or gateway invariant broken
          * ``unsupported_protocol_version`` — ``protocol_version != 2``
          * ``witness_mismatch`` — ``keys.witness_key_id`` mismatch
          * ``witness_signature_missing`` — empty/whitespace-only signature
          * ``invalid_signature`` — Ed25519 verification failed or key
            input is malformed (wrong length, non-base64, etc.)
        TypeError: if ``keys`` is not a :class:`VerifyCertificateKeys`
            (programmer error, not a cert-verification failure).
    """

    if not isinstance(keys, VerifyCertificateKeys):
        raise TypeError(
            "verify_certificate: keys must be a VerifyCertificateKeys instance"
        )

    cert: VeilCertificate = (
        raw_cert if isinstance(raw_cert, VeilCertificate) else parse_certificate(raw_cert)
    )

    if cert.protocol_version != SUPPORTED_PROTOCOL_VERSION:
        raise TheVeilCertificateError(
            f"Unsupported Veil protocol version: {cert.protocol_version} "
            f"(SDK supports {SUPPORTED_PROTOCOL_VERSION})",
            reason="unsupported_protocol_version",
            certificate_id=cert.certificate_id,
        )

    if cert.witness_key_id != keys.witness_key_id:
        raise TheVeilCertificateError(
            f'Witness key ID mismatch: cert has "{cert.witness_key_id}", '
            f'expected "{keys.witness_key_id}"',
            reason="witness_mismatch",
            certificate_id=cert.certificate_id,
        )

    # ``strip()`` routes "" AND whitespace-only signatures to the same reason
    # — "   " base64-decodes to empty bytes which would otherwise surface as
    # a confusing invalid_signature.
    if cert.witness_signature.strip() == "":
        raise TheVeilCertificateError(
            "Certificate has no witness signature",
            reason="witness_signature_missing",
            certificate_id=cert.certificate_id,
        )

    try:
        signed_bytes = derive_witness_signed_bytes(cert)
    except TheVeilCertificateError:
        raise
    except TypeError as exc:
        raise TheVeilCertificateError(
            f"Failed to derive signed payload: {exc}",
            reason="malformed",
            certificate_id=cert.certificate_id,
            cause=exc,
        ) from exc

    try:
        signature_bytes = base64.b64decode(cert.witness_signature, validate=True)
    except (ValueError, base64.binascii.Error) as exc:  # type: ignore[attr-defined]
        raise TheVeilCertificateError(
            f"Witness signature base64 decode failed: {exc}",
            reason="invalid_signature",
            certificate_id=cert.certificate_id,
            cause=exc,
        ) from exc

    try:
        valid = verify_ed25519(signed_bytes, signature_bytes, keys.witness_public_key)
    except TypeError as exc:
        raise TheVeilCertificateError(
            f"Invalid witness_public_key: {exc}",
            reason="invalid_signature",
            certificate_id=cert.certificate_id,
            cause=exc,
        ) from exc

    if not valid:
        raise TheVeilCertificateError(
            "Witness Ed25519 signature verification failed",
            reason="invalid_signature",
            certificate_id=cert.certificate_id,
        )

    return _build_result(cert)


def _build_result(cert: VeilCertificate) -> VerifyCertificateResult:
    return VerifyCertificateResult(
        certificate_id=cert.certificate_id,
        request_id=cert.request_id,
        witness_key_id=cert.witness_key_id,
        witness_asserted_issued_at=_parse_iso(cert.issued_at),
        witness_asserted_issued_at_iso=cert.issued_at,
        anchor_status=(
            cert.anchor_status.status if cert.anchor_status is not None
            else "ANCHOR_STATUS_UNSPECIFIED"
        ),
        overall_verdict=cert.verification.overall_verdict,
    )


def _parse_iso(iso: str) -> datetime:
    """Parse an RFC 3339 timestamp into ``datetime`` with microsecond precision.

    The witness-asserted issued-at may carry nanosecond precision; Python
    ``datetime`` is microsecond-resolution, so sub-microsecond digits are
    dropped. Callers requiring full precision should read the
    ``witness_asserted_issued_at_iso`` field (raw string, unchanged).
    """

    # datetime.fromisoformat in 3.11+ accepts the "Z" suffix and nanoseconds
    # (nanoseconds since 3.12; "Z" since 3.11). For 3.10 compatibility,
    # substitute "Z" → "+00:00" and truncate fractional seconds beyond 6 digits.
    s = iso
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    # Truncate fractional seconds to microsecond resolution (6 digits).
    dot = s.find(".")
    if dot != -1:
        # Find end of fractional digits
        end = dot + 1
        while end < len(s) and s[end].isdigit():
            end += 1
        frac = s[dot + 1 : end]
        if len(frac) > 6:
            s = s[:dot] + "." + frac[:6] + s[end:]
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        # Fall back: strip timezone and parse the naive form — preserves
        # v1's "do our best; the ISO string is the authoritative form" posture.
        return datetime.fromisoformat(s.split("+")[0].split("-", 3)[0])
