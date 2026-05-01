"""VeilCertificate.client_id field + get_client_id helper.

W2A-B1 (PR #92, merged 2026-05-01) added `optional string client_id` to
the cert proto. The Pydantic model now exposes it as `client_id: str |
None`. Backward compatibility: certificates without the field still
deserialize cleanly (default None).
"""

from __future__ import annotations

from lucairn import VeilCertificate, get_client_id


_BASE_CERT = {
    "certificate_id": "cert_abc",
    "request_id": "req_abc",
    "protocol_version": 2,
    "claims": [],
    "verification": {
        "signatures_valid": True,
        "completeness": "COMPLETENESS_FULL",
        "missing_services": [],
        "temporal_consistent": True,
        "data_visibility_consistent": True,
        "isolation_verified": True,
        "qi_score": None,
        "overall_verdict": "VERDICT_VERIFIED",
    },
    "issued_at": "2026-05-01T00:00:00Z",
    "witness_signature": "AAAA",
    "witness_key_id": "witness_v1",
}


def test_client_id_present_when_gateway_emits() -> None:
    payload = {**_BASE_CERT, "client_id": "org_42"}
    cert = VeilCertificate.model_validate(payload)
    assert cert.client_id == "org_42"
    assert get_client_id(cert) == "org_42"


def test_client_id_default_none_when_omitted() -> None:
    cert = VeilCertificate.model_validate(_BASE_CERT)
    assert cert.client_id is None
    assert get_client_id(cert) is None


def test_client_id_explicit_null_remains_none() -> None:
    # protojson EmitUnpopulated:true serialises absent oneof / optional as
    # JSON null. Pydantic must deserialise that as Python None.
    payload = {**_BASE_CERT, "client_id": None}
    cert = VeilCertificate.model_validate(payload)
    assert cert.client_id is None
    assert get_client_id(cert) is None
