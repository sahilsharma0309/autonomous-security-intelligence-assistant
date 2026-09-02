"""Tests for the engagement scope and authorization gate.

These are the safety-critical tests: the scope is what stops the agent from
touching anything it has not been authorized to touch.
"""

from __future__ import annotations

import pytest

from security_assistant.core import AuthorizationScope, RiskLevel, ScopeRule
from security_assistant.core.authorization import (
    TargetKind,
    classify_target,
    normalize_target,
)
from security_assistant.core.exceptions import AuthorizationError, ConfigurationError


@pytest.fixture
def scope() -> AuthorizationScope:
    return AuthorizationScope(
        allow=["example.com", "192.0.2.0/24"],
        deny=["prod.example.com"],
        max_risk=RiskLevel.ACTIVE,
        authorization_reference="ENG-2024-114",
        engagement="demo",
    )


class TestNormalizeTarget:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("example.com", "example.com"),
            ("EXAMPLE.com", "example.com"),
            ("example.com.", "example.com"),
            ("https://example.com/admin?x=1", "example.com"),
            ("http://Example.COM:8443/path", "example.com"),
            ("example.com:443", "example.com"),
            ("10.0.0.0/24", "10.0.0.0/24"),
            ("[2001:db8::1]:8080", "2001:db8::1"),
        ],
    )
    def test_normalizes(self, raw: str, expected: str) -> None:
        assert normalize_target(raw) == expected

    @pytest.mark.parametrize("bad", ["", "   "])
    def test_rejects_empty(self, bad: str) -> None:
        with pytest.raises(ConfigurationError):
            normalize_target(bad)

    def test_rejects_non_string(self) -> None:
        with pytest.raises(ConfigurationError):
            normalize_target(None)  # type: ignore[arg-type]


class TestClassifyTarget:
    @pytest.mark.parametrize(
        ("raw", "kind"),
        [
            ("example.com", TargetKind.HOSTNAME),
            ("192.0.2.1", TargetKind.IP_ADDRESS),
            ("2001:db8::1", TargetKind.IP_ADDRESS),
            ("192.0.2.0/24", TargetKind.IP_NETWORK),
            ("not a host!", TargetKind.UNKNOWN),
        ],
    )
    def test_classifies(self, raw: str, kind: TargetKind) -> None:
        assert classify_target(raw)[0] is kind


class TestScopeRule:
    def test_matches_apex_and_subdomains(self) -> None:
        rule = ScopeRule("example.com")
        assert rule.matches("example.com")
        assert rule.matches("api.example.com")
        assert rule.matches("deep.nested.example.com")

    def test_does_not_match_lookalike_suffix(self) -> None:
        # The classic scoping bug: notexample.com must not match example.com.
        rule = ScopeRule("example.com")
        assert not rule.matches("notexample.com")
        assert not rule.matches("example.com.evil.net")

    def test_subdomains_can_be_disabled(self) -> None:
        rule = ScopeRule("example.com", include_subdomains=False)
        assert rule.matches("example.com")
        assert not rule.matches("api.example.com")

    def test_wildcard_means_subdomains_only(self) -> None:
        rule = ScopeRule("*.example.com")
        assert not rule.matches("example.com")
        assert rule.matches("api.example.com")

    def test_cidr_containment(self) -> None:
        rule = ScopeRule("192.0.2.0/24")
        assert rule.matches("192.0.2.10")
        assert not rule.matches("198.51.100.10")

    def test_network_target_must_be_fully_contained(self) -> None:
        rule = ScopeRule("10.0.0.0/16")
        assert rule.matches("10.0.1.0/24")
        assert not rule.matches("10.0.0.0/8")

    def test_empty_pattern_rejected(self) -> None:
        with pytest.raises(ConfigurationError):
            ScopeRule("   ")


class TestAuthorizationScope:
    def test_allows_in_scope_targets(self, scope: AuthorizationScope) -> None:
        assert scope.permits("example.com", RiskLevel.ACTIVE)
        assert scope.permits("api.example.com", RiskLevel.ACTIVE)
        assert scope.permits("192.0.2.10", RiskLevel.ACTIVE)

    def test_denies_out_of_scope(self, scope: AuthorizationScope) -> None:
        assert not scope.permits("someone-else.net", RiskLevel.PASSIVE)
        assert not scope.permits("198.51.100.5", RiskLevel.ACTIVE)

    def test_deny_beats_allow(self, scope: AuthorizationScope) -> None:
        decision = scope.evaluate("prod.example.com", RiskLevel.ACTIVE)
        assert not decision.allowed
        assert "deny rule" in decision.reason

    def test_risk_cap_enforced(self, scope: AuthorizationScope) -> None:
        decision = scope.evaluate("example.com", RiskLevel.INTRUSIVE)
        assert not decision.allowed
        assert "exceeds the authorized maximum" in decision.reason

    def test_empty_scope_authorizes_nothing(self) -> None:
        empty = AuthorizationScope.deny_all()
        assert empty.is_empty
        assert not empty.permits("example.com", RiskLevel.PASSIVE)

    def test_check_raises_when_denied(self, scope: AuthorizationScope) -> None:
        with pytest.raises(AuthorizationError, match="not authorized"):
            scope.check("someone-else.net", RiskLevel.PASSIVE)

    def test_check_returns_decision_when_allowed(self, scope: AuthorizationScope) -> None:
        decision = scope.check("api.example.com", RiskLevel.ACTIVE)
        assert decision.allowed
        assert decision.matched_rule is not None

    def test_url_targets_are_normalized(self, scope: AuthorizationScope) -> None:
        assert scope.permits("https://api.example.com:8443/x?y=1", RiskLevel.ACTIVE)

    def test_private_ranges_can_be_refused(self) -> None:
        external_only = AuthorizationScope(
            allow=["10.0.0.0/8"], allow_private_ranges=False, max_risk=RiskLevel.ACTIVE
        )
        decision = external_only.evaluate("10.1.2.3", RiskLevel.ACTIVE)
        assert not decision.allowed
        assert "private/reserved" in decision.reason

    def test_expired_engagement_denies(self) -> None:
        expired = AuthorizationScope(
            allow=["example.com"],
            expires_at=__import__("datetime").datetime(2000, 1, 1),
        )
        assert expired.is_expired
        assert not expired.permits("example.com")

    def test_from_config_roundtrip(self) -> None:
        built = AuthorizationScope.from_config(
            {
                "allow": ["example.com"],
                "deny": ["prod.example.com"],
                "max_risk": "intrusive",
                "authorization_reference": "ENG-9",
                "engagement": "cfg",
                "allow_private_ranges": False,
            }
        )
        assert built.max_risk is RiskLevel.INTRUSIVE
        assert built.authorization_reference == "ENG-9"
        assert built.permits("example.com", RiskLevel.INTRUSIVE)

    def test_from_config_rejects_non_mapping(self) -> None:
        with pytest.raises(ConfigurationError):
            AuthorizationScope.from_config(["example.com"])  # type: ignore[arg-type]

    def test_describe_is_audit_friendly(self, scope: AuthorizationScope) -> None:
        described = scope.describe()
        assert described["authorization_reference"] == "ENG-2024-114"
        assert described["allow"] == ["example.com", "192.0.2.0/24"]
        assert described["max_risk"] == "ACTIVE"
