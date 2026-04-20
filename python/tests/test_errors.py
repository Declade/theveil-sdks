"""Error class identity + attribute tests."""

from __future__ import annotations

import pytest

from theveil import (
    TheVeilCertificateError,
    TheVeilConfigError,
    TheVeilError,
    TheVeilHttpError,
    TheVeilTimeoutError,
)


class TestErrorHierarchy:
    def test_base_is_exception(self) -> None:
        err = TheVeilError("x")
        assert isinstance(err, Exception)

    def test_config_inherits_base(self) -> None:
        err = TheVeilConfigError("x")
        assert isinstance(err, TheVeilError)
        assert isinstance(err, Exception)

    def test_http_inherits_base(self) -> None:
        err = TheVeilHttpError("x", status=500, body=None)
        assert isinstance(err, TheVeilError)

    def test_timeout_inherits_base(self) -> None:
        err = TheVeilTimeoutError("x")
        assert isinstance(err, TheVeilError)

    def test_certificate_inherits_base(self) -> None:
        err = TheVeilCertificateError("x", reason="malformed")
        assert isinstance(err, TheVeilError)


class TestTheVeilHttpError:
    def test_status_and_body_accessible(self) -> None:
        err = TheVeilHttpError("bad", status=401, body={"error": "nope"})
        assert err.status == 401
        assert err.body == {"error": "nope"}

    def test_message_on_str(self) -> None:
        err = TheVeilHttpError("bad", status=500, body=None)
        assert str(err) == "bad"

    def test_cause_attached(self) -> None:
        inner = ValueError("inner")
        err = TheVeilHttpError("bad", status=500, body=None, cause=inner)
        assert err.__cause__ is inner


class TestTheVeilCertificateError:
    def test_reason_and_certificate_id(self) -> None:
        err = TheVeilCertificateError(
            "nope",
            reason="invalid_signature",
            certificate_id="veil_xyz",
        )
        assert err.reason == "invalid_signature"
        assert err.certificate_id == "veil_xyz"

    def test_certificate_id_defaults_none(self) -> None:
        err = TheVeilCertificateError("nope", reason="malformed")
        assert err.certificate_id is None

    def test_cause_preserved(self) -> None:
        inner = TypeError("boom")
        err = TheVeilCertificateError(
            "wrap", reason="invalid_signature", cause=inner
        )
        assert err.__cause__ is inner


class TestTheVeilConfigError:
    def test_accepts_single_argument(self) -> None:
        err = TheVeilConfigError("config bad")
        assert str(err) == "config bad"


class TestTheVeilTimeoutError:
    def test_accepts_single_argument(self) -> None:
        err = TheVeilTimeoutError("slow")
        assert str(err) == "slow"


class TestCatchability:
    """Callers can ``except TheVeilError`` to catch all SDK-raised errors."""

    def test_catches_all_subclasses(self) -> None:
        for exc in (
            TheVeilConfigError("x"),
            TheVeilHttpError("x", status=500, body=None),
            TheVeilTimeoutError("x"),
            TheVeilCertificateError("x", reason="malformed"),
        ):
            try:
                raise exc
            except TheVeilError as caught:
                assert caught is exc
            else:
                pytest.fail(f"did not catch {type(exc).__name__}")
