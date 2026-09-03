"""Tests for dashboard authentication.

This gate guards a surface that can dispatch agent runs and change firewall
state, so most of these assert a refusal.
"""

from __future__ import annotations

import time

import pytest

from security_assistant.web.auth import (
    MIN_SECRET_LENGTH,
    SECRET_ENV_VAR,
    AuthError,
    AuthGate,
    generate_secret,
    is_loopback,
    secret_from_env,
    token_from_headers,
    warn_if_exposed,
)

SECRET = "k" * 48


class TestSecretFromEnv:
    def test_refuses_to_start_without_a_secret(self) -> None:
        """A dashboard that invents its own key is one whose access control
        nobody has thought about."""
        with pytest.raises(AuthError, match=SECRET_ENV_VAR):
            secret_from_env({})

    def test_error_tells_you_how_to_generate_one(self) -> None:
        with pytest.raises(AuthError, match="token_urlsafe"):
            secret_from_env({})

    def test_refuses_a_short_secret(self) -> None:
        with pytest.raises(AuthError, match="minimum"):
            secret_from_env({SECRET_ENV_VAR: "hunter2"})

    def test_accepts_a_long_secret(self) -> None:
        assert secret_from_env({SECRET_ENV_VAR: SECRET}) == SECRET

    def test_strips_whitespace(self) -> None:
        assert secret_from_env({SECRET_ENV_VAR: f"  {SECRET}  "}) == SECRET

    def test_blank_counts_as_unset(self) -> None:
        with pytest.raises(AuthError):
            secret_from_env({SECRET_ENV_VAR: "   "})

    def test_generated_secret_passes_its_own_check(self) -> None:
        assert len(generate_secret()) >= MIN_SECRET_LENGTH
        assert secret_from_env({SECRET_ENV_VAR: generate_secret()})


class TestTokenVerification:
    def test_accepts_the_right_token(self) -> None:
        assert AuthGate(SECRET).verify_token(SECRET) is True

    @pytest.mark.parametrize("wrong", ["", "x" * 48, SECRET[:-1], SECRET + "x"])
    def test_rejects_anything_else(self, wrong: str) -> None:
        assert AuthGate(SECRET).verify_token(wrong) is False

    def test_gate_rejects_a_short_secret_at_construction(self) -> None:
        with pytest.raises(AuthError, match="too short"):
            AuthGate("short")


class TestSessions:
    def test_issued_session_verifies(self) -> None:
        gate = AuthGate(SECRET)
        assert gate.verify_session(gate.issue()) is not None

    def test_forged_signature_is_rejected(self) -> None:
        gate = AuthGate(SECRET)
        issued, expires, _sig = gate.issue().split(".")
        assert gate.verify_session(f"{issued}.{expires}.forged") is None

    def test_tampered_expiry_is_rejected(self) -> None:
        """Extending your own session must invalidate the signature."""
        gate = AuthGate(SECRET)
        issued, expires, signature = gate.issue().split(".")
        longer = str(int(float(expires)) + 999999)
        assert gate.verify_session(f"{issued}.{longer}.{signature}") is None

    def test_expired_session_is_rejected(self) -> None:
        gate = AuthGate(SECRET, session_ttl_seconds=-1)
        assert gate.verify_session(gate.issue()) is None

    def test_a_session_from_another_secret_is_rejected(self) -> None:
        cookie = AuthGate("a" * 48).issue()
        assert AuthGate("b" * 48).verify_session(cookie) is None

    @pytest.mark.parametrize("junk", [None, "", "junk", "a.b", "a.b.c.d"])
    def test_malformed_cookies_are_unauthenticated_not_errors(self, junk: str | None) -> None:
        assert AuthGate(SECRET).verify_session(junk) is None

    def test_session_carries_no_secret(self) -> None:
        gate = AuthGate(SECRET)
        assert SECRET not in gate.issue()

    def test_expiry_is_in_the_future(self) -> None:
        gate = AuthGate(SECRET, session_ttl_seconds=60)
        session = gate.verify_session(gate.issue())
        assert session is not None
        assert session.expires_at > time.time()


class TestCookieFlags:
    def test_loopback_bind_does_not_set_secure(self) -> None:
        """A Secure cookie is never sent over plain http, so setting it on a
        loopback bind would lock the operator out of their own dashboard."""
        assert AuthGate(SECRET, loopback_only=True).cookie_secure is False

    def test_exposed_bind_sets_secure(self) -> None:
        assert AuthGate(SECRET, loopback_only=False).cookie_secure is True


class TestHeaderExtraction:
    def test_bearer_header(self) -> None:
        assert token_from_headers({"authorization": f"Bearer {SECRET}"}) == SECRET

    def test_case_insensitive_scheme(self) -> None:
        assert token_from_headers({"Authorization": f"bearer {SECRET}"}) == SECRET

    def test_custom_header_for_websocket_clients(self) -> None:
        assert token_from_headers({"x-dashboard-token": SECRET}) == SECRET

    def test_absent_returns_empty(self) -> None:
        assert token_from_headers({}) == ""

    def test_non_bearer_scheme_is_ignored(self) -> None:
        assert token_from_headers({"authorization": f"Basic {SECRET}"}) == ""


class TestBindWarnings:
    @pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1", ""])
    def test_loopback_addresses(self, host: str) -> None:
        assert is_loopback(host) is True
        assert warn_if_exposed(host) is None

    @pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.5", "10.0.0.1"])
    def test_exposed_addresses_warn(self, host: str) -> None:
        assert is_loopback(host) is False
        warning = warn_if_exposed(host)
        assert warning is not None
        assert "reachable from outside" in warning
