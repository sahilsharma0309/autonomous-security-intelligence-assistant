"""Engagement scope and the authorization gate.

Every reconnaissance or scanning tool in this system operates against a third
party, so the core treats "am I allowed to touch this target?" as a
first-class, non-optional concern rather than an afterthought left to
individual tools.

The model is deliberately conservative:

* **Default deny.** An empty scope authorizes nothing at all.
* **Denies beat allows.** A target matching any deny rule is refused even if
  it also matches an allow rule.
* **Risk is capped.** A scope declares the most intrusive class of action it
  authorizes (see :class:`~security_assistant.core.types.RiskLevel`); anything
  above that cap is refused regardless of target.
* **Provenance is recorded.** A scope carries a reference to the written
  authorization it represents so results can be audited later.

The dispatcher enforces this gate for every tool declaring
``requires_scope=True``; tools never get to decide for themselves.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any
from urllib.parse import urlsplit

from security_assistant.core.exceptions import AuthorizationError, ConfigurationError
from security_assistant.core.types import RiskLevel, utcnow

logger = logging.getLogger(__name__)

__all__ = [
    "AuthorizationScope",
    "ScopeDecision",
    "ScopeRule",
    "TargetKind",
    "classify_target",
    "normalize_target",
]

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

# A permissive hostname check: labels of alphanumerics/hyphens separated by
# dots. Punycode (xn--) passes naturally; unicode domains should be encoded to
# IDNA by the caller before reaching the scope.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)


class TargetKind(StrEnum):
    """What sort of asset a target string denotes."""

    HOSTNAME = "hostname"
    IP_ADDRESS = "ip_address"
    IP_NETWORK = "ip_network"
    UNKNOWN = "unknown"


def normalize_target(target: str) -> str:
    """Reduce a user-supplied target to a bare host, IP, or CIDR.

    Accepts full URLs, ``host:port`` pairs, and trailing dots so callers can
    pass whatever the operator typed:

    >>> normalize_target("https://Example.COM:8443/admin?x=1")
    'example.com'
    >>> normalize_target("10.0.0.0/24")
    '10.0.0.0/24'
    """
    if not isinstance(target, str):
        raise ConfigurationError(f"Target must be a string, got {type(target).__name__}")

    value = target.strip()
    if not value:
        raise ConfigurationError("Target must not be empty")

    # Strip a URL wrapper if present.
    if "://" in value:
        parsed = urlsplit(value)
        value = parsed.hostname or parsed.path
        if not value:
            raise ConfigurationError(f"Could not extract a host from URL {target!r}")

    value = value.strip().rstrip(".")

    # A bracketed IPv6 literal, optionally with a port: [::1]:8080
    if value.startswith("["):
        end = value.find("]")
        if end != -1:
            return value[1:end].lower()

    # Preserve CIDR notation verbatim; only hosts get port stripping.
    if "/" in value:
        return value.lower()

    # Strip a trailing :port, but never mangle a bare IPv6 address (which has
    # multiple colons and no port syntax without brackets).
    if value.count(":") == 1:
        host, _, port = value.partition(":")
        if port.isdigit():
            value = host

    return value.lower()


def classify_target(target: str) -> tuple[TargetKind, Any]:
    """Classify a normalized target and return its parsed representation.

    Returns a ``(kind, parsed)`` pair where ``parsed`` is an
    :class:`ipaddress` object for IP targets and the lowercase string for
    hostnames.
    """
    value = normalize_target(target)

    if "/" in value:
        try:
            return TargetKind.IP_NETWORK, ipaddress.ip_network(value, strict=False)
        except ValueError:
            return TargetKind.UNKNOWN, value

    try:
        return TargetKind.IP_ADDRESS, ipaddress.ip_address(value)
    except ValueError:
        pass

    if _HOSTNAME_RE.match(value):
        return TargetKind.HOSTNAME, value

    return TargetKind.UNKNOWN, value


@dataclass(frozen=True, slots=True)
class ScopeRule:
    """A single allow/deny entry in an engagement scope.

    A rule matches one of three shapes:

    * an IP network (``10.0.0.0/8``) -- matches any address inside it,
    * a single IP address (``192.0.2.10``),
    * a hostname (``example.com``) -- matches the host itself and, when
      ``include_subdomains`` is set, anything beneath it.

    Hostname rules may also be written with a leading wildcard
    (``*.example.com``), which means subdomains *only*.
    """

    pattern: str
    include_subdomains: bool = True
    note: str = ""

    def __post_init__(self) -> None:
        if not self.pattern or not self.pattern.strip():
            raise ConfigurationError("Scope rule pattern must not be empty")

    @property
    def _effective(self) -> tuple[str, bool]:
        """Return the pattern with any wildcard stripped, and whether the
        wildcard restricted matching to subdomains only."""
        pattern = self.pattern.strip().lower().rstrip(".")
        if pattern.startswith("*."):
            return pattern[2:], True
        return pattern, False

    def matches(self, target: str) -> bool:
        """True when ``target`` falls inside this rule."""
        pattern, subdomains_only = self._effective
        kind, parsed = classify_target(target)

        # --- IP-shaped rules -------------------------------------------------
        try:
            network = ipaddress.ip_network(pattern, strict=False)
        except ValueError:
            network = None

        if network is not None:
            if kind is TargetKind.IP_ADDRESS:
                return parsed in network
            if kind is TargetKind.IP_NETWORK:
                # A target range is in scope only if fully contained.
                return parsed.subnet_of(network) if parsed.version == network.version else False
            return False

        # --- Hostname rules --------------------------------------------------
        if kind is not TargetKind.HOSTNAME:
            return False

        host = str(parsed)
        if host == pattern:
            return not subdomains_only
        return (self.include_subdomains or subdomains_only) and host.endswith("." + pattern)

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.pattern


@dataclass(frozen=True, slots=True)
class ScopeDecision:
    """The result of evaluating a target against a scope."""

    allowed: bool
    target: str
    reason: str
    matched_rule: ScopeRule | None = None
    risk: RiskLevel = RiskLevel.PASSIVE

    def __bool__(self) -> bool:  # pragma: no cover - trivial
        return self.allowed


@dataclass(slots=True)
class AuthorizationScope:
    """The set of assets an operator is authorized to assess.

    Construct one per engagement and hand it to the dispatcher. Nothing in the
    system contacts a target that this object has not approved.

    >>> scope = AuthorizationScope(
    ...     allow=["example.com", "192.0.2.0/24"],
    ...     deny=["prod.example.com"],
    ...     max_risk=RiskLevel.ACTIVE,
    ...     authorization_reference="ENG-2024-114",
    ... )
    >>> bool(scope.evaluate("api.example.com", RiskLevel.ACTIVE))
    True
    >>> bool(scope.evaluate("prod.example.com", RiskLevel.ACTIVE))
    False
    >>> bool(scope.evaluate("someone-else.net", RiskLevel.PASSIVE))
    False
    """

    allow: Sequence[str | ScopeRule] = field(default_factory=list)
    deny: Sequence[str | ScopeRule] = field(default_factory=list)
    max_risk: RiskLevel = RiskLevel.ACTIVE
    authorization_reference: str = ""
    """Ticket/contract id evidencing written permission. Recorded in audits."""

    engagement: str = ""
    expires_at: datetime | None = None
    allow_private_ranges: bool = True
    """When false, RFC1918 / loopback / link-local targets are refused.

    Useful for engagements that are strictly external, where hitting an
    internal address would mean a misconfiguration rather than intent.
    """

    _allow_rules: list[ScopeRule] = field(default_factory=list, init=False, repr=False)
    _deny_rules: list[ScopeRule] = field(default_factory=list, init=False, repr=False)

    def __post_init__(self) -> None:
        self.max_risk = RiskLevel.parse(self.max_risk)
        self._allow_rules = [_coerce_rule(r) for r in self.allow]
        self._deny_rules = [_coerce_rule(r) for r in self.deny]

    # -- construction ------------------------------------------------------ #
    @classmethod
    def from_config(cls, data: Mapping[str, Any]) -> AuthorizationScope:
        """Build a scope from a plain mapping (e.g. parsed YAML)."""
        if not isinstance(data, Mapping):
            raise ConfigurationError("Scope configuration must be a mapping")

        expires_raw = data.get("expires_at")
        expires: datetime | None = None
        if expires_raw:
            if isinstance(expires_raw, datetime):
                expires = expires_raw
            else:
                try:
                    expires = datetime.fromisoformat(str(expires_raw))
                except ValueError as exc:
                    raise ConfigurationError(
                        f"Invalid scope expires_at value: {expires_raw!r}"
                    ) from exc

        return cls(
            allow=list(data.get("allow", []) or []),
            deny=list(data.get("deny", []) or []),
            max_risk=RiskLevel.parse(data.get("max_risk", RiskLevel.ACTIVE)),
            authorization_reference=str(data.get("authorization_reference", "") or ""),
            engagement=str(data.get("engagement", "") or ""),
            expires_at=expires,
            allow_private_ranges=bool(data.get("allow_private_ranges", True)),
        )

    @classmethod
    def deny_all(cls) -> AuthorizationScope:
        """A scope that authorizes nothing -- the safe default."""
        return cls(allow=[], deny=[], max_risk=RiskLevel.PASSIVE)

    # -- evaluation -------------------------------------------------------- #
    @property
    def is_empty(self) -> bool:
        """True when no allow rules are configured (i.e. nothing is in scope)."""
        return not self._allow_rules

    @property
    def is_expired(self) -> bool:
        """True when the engagement window has closed."""
        if self.expires_at is None:
            return False
        expires = self.expires_at
        now = utcnow()
        if expires.tzinfo is None:
            now = now.replace(tzinfo=None)
        return expires < now

    def evaluate(self, target: str, risk: RiskLevel = RiskLevel.PASSIVE) -> ScopeDecision:
        """Evaluate ``target`` at ``risk`` without raising.

        Returns a :class:`ScopeDecision` explaining the outcome, which the
        dispatcher records verbatim in the audit trail.
        """
        risk = RiskLevel.parse(risk)

        try:
            normalized = normalize_target(target)
        except ConfigurationError as exc:
            return ScopeDecision(False, str(target), f"unparseable target: {exc}", risk=risk)

        if self.is_expired:
            return ScopeDecision(
                False,
                normalized,
                f"engagement authorization expired at {self.expires_at}",
                risk=risk,
            )

        if risk > self.max_risk:
            return ScopeDecision(
                False,
                normalized,
                f"risk level {risk} exceeds the authorized maximum {self.max_risk}",
                risk=risk,
            )

        if self.is_empty:
            return ScopeDecision(
                False, normalized, "scope is empty; nothing is authorized", risk=risk
            )

        kind, parsed = classify_target(normalized)
        if kind is TargetKind.UNKNOWN:
            return ScopeDecision(
                False, normalized, "target is neither a valid hostname nor IP", risk=risk
            )

        if (
            not self.allow_private_ranges
            and kind in (TargetKind.IP_ADDRESS, TargetKind.IP_NETWORK)
            and _is_non_public(parsed)
        ):
            return ScopeDecision(
                False,
                normalized,
                "private/reserved address space is not authorized in this scope",
                risk=risk,
            )

        # Denies always win.
        for rule in self._deny_rules:
            if rule.matches(normalized):
                return ScopeDecision(
                    False, normalized, f"matched deny rule {rule.pattern!r}", rule, risk
                )

        for rule in self._allow_rules:
            if rule.matches(normalized):
                return ScopeDecision(
                    True, normalized, f"matched allow rule {rule.pattern!r}", rule, risk
                )

        return ScopeDecision(False, normalized, "no allow rule matched", risk=risk)

    def check(self, target: str, risk: RiskLevel = RiskLevel.PASSIVE) -> ScopeDecision:
        """Like :meth:`evaluate`, but raise :class:`AuthorizationError` on deny."""
        decision = self.evaluate(target, risk)
        if not decision.allowed:
            logger.warning(
                "Authorization denied target=%s risk=%s reason=%s engagement=%s",
                decision.target,
                decision.risk,
                decision.reason,
                self.engagement or "<unset>",
            )
            raise AuthorizationError(
                f"Target {decision.target!r} is not authorized for {decision.risk} "
                f"actions: {decision.reason}"
            )
        return decision

    def permits(self, target: str, risk: RiskLevel = RiskLevel.PASSIVE) -> bool:
        """Boolean convenience wrapper around :meth:`evaluate`."""
        return self.evaluate(target, risk).allowed

    def describe(self) -> dict[str, Any]:
        """Return an audit-friendly description of this scope."""
        return {
            "engagement": self.engagement,
            "authorization_reference": self.authorization_reference,
            "allow": [r.pattern for r in self._allow_rules],
            "deny": [r.pattern for r in self._deny_rules],
            "max_risk": str(self.max_risk),
            "allow_private_ranges": self.allow_private_ranges,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "expired": self.is_expired,
        }

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"<AuthorizationScope engagement={self.engagement or '<unset>'} "
            f"allow={len(self._allow_rules)} deny={len(self._deny_rules)} "
            f"max_risk={self.max_risk}>"
        )


def _coerce_rule(value: str | ScopeRule | Mapping[str, Any]) -> ScopeRule:
    """Accept strings, mappings, or rules and return a :class:`ScopeRule`."""
    if isinstance(value, ScopeRule):
        return value
    if isinstance(value, str):
        return ScopeRule(pattern=value)
    if isinstance(value, Mapping):
        pattern = value.get("pattern")
        if not pattern:
            raise ConfigurationError(f"Scope rule mapping requires a 'pattern': {value!r}")
        return ScopeRule(
            pattern=str(pattern),
            include_subdomains=bool(value.get("include_subdomains", True)),
            note=str(value.get("note", "") or ""),
        )
    raise ConfigurationError(f"Cannot interpret scope rule: {value!r}")


def _is_non_public(parsed: Any) -> bool:
    """True for loopback/private/link-local/reserved address space."""
    try:
        return bool(
            parsed.is_private
            or parsed.is_loopback
            or parsed.is_link_local
            or parsed.is_reserved
            or parsed.is_multicast
        )
    except AttributeError:  # pragma: no cover - defensive
        return False


def iter_rules(values: Iterable[str | ScopeRule]) -> list[ScopeRule]:
    """Public helper to coerce an iterable of rule specs into rules."""
    return [_coerce_rule(v) for v in values]
