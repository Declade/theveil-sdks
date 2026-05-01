"""Lucairn.list_audit_events() — HTTP-level tests via respx.

The gateway endpoint is GET /api/v1/audit/export (handler at
dual-sandbox-architecture/services/gateway/internal/api/audit_export.go:60-100).
Auth is x-api-key; tier-gated, returns 503 audit_export_unavailable if
disabled.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from lucairn import (
    AuditExportOptions,
    AuditExportResponse,
    Lucairn,
    LucairnConfig,
    LucairnConfigError,
    LucairnHttpError,
    LucairnResponseValidationError,
)


VALID_KEY = "dsa_" + "0" * 32
BASE = "https://gateway.lucairn.eu"


def _client() -> Lucairn:
    return Lucairn(LucairnConfig(api_key=VALID_KEY))


_OK_BODY = {
    "customer_id": "cust_42",
    "tier": "pro",
    "period": "2026-04-01 to 2026-05-01",
    "events": [
        {
            "timestamp": "2026-04-15T10:00:00Z",
            "event_type": "proxy.completed",
            "actor": "cust_42",
            "details": "{\"ok\":true}",
            "request_id": "req_abc",
        },
        {
            "timestamp": "2026-04-20T11:00:00Z",
            "event_type": "audit.exported",
            "actor": "cust_42",
            "details": "{}",
        },
    ],
    "total_events": 2,
    "source": "audit_service",
}


class TestListAuditEventsHappyPath:
    @respx.mock
    def test_default_no_query_params(self) -> None:
        route = respx.get(f"{BASE}/api/v1/audit/export").mock(
            return_value=httpx.Response(200, json=_OK_BODY)
        )

        out = _client().list_audit_events()

        assert isinstance(out, AuditExportResponse)
        assert out.customer_id == "cust_42"
        assert out.total_events == 2
        assert len(out.events) == 2
        assert out.events[0].request_id == "req_abc"
        # Per Go's omitempty: missing request_id deserialises to None.
        assert out.events[1].request_id is None

        # Sanity: no query string was sent on the default call.
        sent = route.calls.last.request
        assert sent.url.query == b""

    @respx.mock
    def test_days_and_type_query_params(self) -> None:
        route = respx.get(
            f"{BASE}/api/v1/audit/export"
        ).mock(return_value=httpx.Response(200, json=_OK_BODY))

        _client().list_audit_events(
            AuditExportOptions(days=7, type="proxy.completed")
        )

        sent_url = str(route.calls.last.request.url)
        assert "days=7" in sent_url
        assert "type=proxy.completed" in sent_url

    @respx.mock
    def test_type_param_url_encoded(self) -> None:
        # Gateway accepts dotted event types; SDK still must URL-encode
        # any reserved chars to keep the path safe.
        route = respx.get(
            f"{BASE}/api/v1/audit/export"
        ).mock(return_value=httpx.Response(200, json=_OK_BODY))

        _client().list_audit_events(AuditExportOptions(type="weird/value"))

        sent_url = str(route.calls.last.request.url)
        assert "type=weird%2Fvalue" in sent_url


class TestListAuditEventsValidation:
    def test_days_must_be_positive_int(self) -> None:
        with pytest.raises(LucairnConfigError, match="days"):
            _client().list_audit_events(AuditExportOptions(days=0))

    def test_days_rejects_negative(self) -> None:
        with pytest.raises(LucairnConfigError, match="days"):
            _client().list_audit_events(AuditExportOptions(days=-1))

    def test_days_rejects_bool(self) -> None:
        # Python's bool is an int subtype; explicitly reject.
        with pytest.raises(LucairnConfigError, match="days"):
            _client().list_audit_events(AuditExportOptions(days=True))  # type: ignore[arg-type]

    def test_type_must_be_str(self) -> None:
        with pytest.raises(LucairnConfigError, match="type"):
            _client().list_audit_events(AuditExportOptions(type=123))  # type: ignore[arg-type]


class TestListAuditEventsErrors:
    @respx.mock
    def test_503_audit_export_unavailable(self) -> None:
        respx.get(f"{BASE}/api/v1/audit/export").mock(
            return_value=httpx.Response(
                503,
                json={
                    "code": "audit_export_unavailable",
                    "message": "Audit export unavailable. Try again shortly.",
                },
            )
        )

        with pytest.raises(LucairnHttpError) as exc_info:
            _client().list_audit_events()

        assert exc_info.value.status == 503
        assert exc_info.value.body["code"] == "audit_export_unavailable"

    @respx.mock
    def test_malformed_2xx_body_response_validation_error(self) -> None:
        respx.get(f"{BASE}/api/v1/audit/export").mock(
            return_value=httpx.Response(
                200,
                json={"customer_id": "cust_42"},  # missing required fields
            )
        )

        with pytest.raises(LucairnResponseValidationError):
            _client().list_audit_events()
