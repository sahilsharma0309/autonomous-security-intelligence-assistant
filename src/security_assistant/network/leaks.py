"""Leak validation: is traffic actually going through the tunnel?

A tunnel reporting ``UP`` says the peer answered. It does not say your traffic
is using it. The three ways that quietly fails are all checked here:

* **IP leak** -- the default route still prefers a physical interface, so the
  public address is unchanged. The tunnel is up and carrying nothing.
* **DNS leak** -- queries go to a resolver outside the tunnel, so the ISP sees
  every name looked up even while the traffic itself is encrypted. This is the
  most common real-world leak and the least visible.
* **Route leak** -- the tunnel's ``AllowedIPs`` do not actually cover the
  default route, so only some destinations are tunnelled.

**The honest-negative rule.** Every check here can fail to *run* -- no network,
no resolver tooling, no baseline to compare against. A check that could not run
reports :attr:`LeakStatus.UNKNOWN`, never "no leak". Reporting an unperformed
check as a pass is the failure mode that matters: an operator reads a green
report and assumes protection they do not have.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Protocol, runtime_checkable

from security_assistant.core.types import utcnow
from security_assistant.network.commands import (
    CommandError,
    CommandRunner,
    default_runner,
)

logger = logging.getLogger(__name__)

__all__ = [
    "LeakCheck",
    "LeakReport",
    "LeakStatus",
    "LeakValidator",
    "PublicIpProbe",
    "parse_resolvectl_dns",
]


class LeakStatus(StrEnum):
    """Outcome of one check."""

    OK = "ok"
    """Ran, and found no leak."""

    LEAK = "leak"
    """Ran, and found a leak."""

    UNKNOWN = "unknown"
    """Could not run. Not a pass."""

    @property
    def is_failure(self) -> bool:
        return self is LeakStatus.LEAK


@dataclass(frozen=True, slots=True)
class LeakCheck:
    """One check and what it found."""

    name: str
    status: LeakStatus
    detail: str = ""
    observed: str = ""
    expected: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status.value,
            "detail": self.detail,
            "observed": self.observed,
            "expected": self.expected,
        }


@dataclass(slots=True)
class LeakReport:
    """The result of a full validation pass."""

    interface: str
    checks: list[LeakCheck] = field(default_factory=list)
    checked_at: Any = field(default_factory=utcnow)

    @property
    def leaking(self) -> bool:
        return any(c.status.is_failure for c in self.checks)

    @property
    def inconclusive(self) -> list[LeakCheck]:
        """Checks that could not run. Never counted as passes."""
        return [c for c in self.checks if c.status is LeakStatus.UNKNOWN]

    @property
    def verdict(self) -> str:
        if self.leaking:
            return "leaking"
        if self.inconclusive:
            return "inconclusive"
        return "protected"

    def to_dict(self) -> dict[str, Any]:
        return {
            "interface": self.interface,
            "verdict": self.verdict,
            "leaking": self.leaking,
            "inconclusive_checks": [c.name for c in self.inconclusive],
            "checks": [c.to_dict() for c in self.checks],
            "checked_at": self.checked_at.isoformat(),
        }


@runtime_checkable
class PublicIpProbe(Protocol):
    """Reports the address the internet sees."""

    async def public_ip(self) -> str:  # pragma: no cover - protocol declaration
        ...


class UnavailableIpProbe:
    """Used when no HTTP client is configured.

    Raises rather than returning an empty string, so the validator records
    UNKNOWN instead of silently comparing against nothing.
    """

    __slots__ = ()

    async def public_ip(self) -> str:
        raise CommandError(
            "No public-IP probe configured. Inject a 'public_ip_probe' provider "
            "to enable IP-leak checking."
        )


_DNS_SERVER_RE = re.compile(r"DNS Servers?:\s*(?P<servers>.+)", re.IGNORECASE)
_LINK_RE = re.compile(r"^Link\s+\d+\s+\((?P<iface>[^)]+)\)", re.MULTILINE)


def parse_resolvectl_dns(output: str) -> dict[str, list[str]]:
    """Parse ``resolvectl status`` into ``{interface: [servers]}``.

    Global servers are keyed under ``"global"``. Only per-link sections are
    attributed to an interface, because that mapping is what decides whether
    a query left through the tunnel.
    """
    sections: dict[str, list[str]] = {}
    current = "global"

    for line in output.splitlines():
        link = _LINK_RE.match(line.strip()) or _LINK_RE.match(line)
        if link:
            current = link.group("iface").strip()
            continue
        match = _DNS_SERVER_RE.search(line)
        if match:
            servers = [s.strip() for s in match.group("servers").split() if s.strip()]
            if servers:
                sections.setdefault(current, []).extend(servers)
    return sections


class LeakValidator:
    """Runs the leak checks for one tunnel."""

    def __init__(
        self,
        runner: CommandRunner | None = None,
        probe: PublicIpProbe | None = None,
    ) -> None:
        self._runner = runner or default_runner()
        self._probe = probe or UnavailableIpProbe()

    async def validate(
        self,
        interface: str,
        *,
        baseline_ip: str = "",
        expected_dns: Sequence[str] = (),
    ) -> LeakReport:
        """Run every check and return a combined report.

        ``baseline_ip`` is the address seen *before* the tunnel came up. Without
        it the IP check cannot conclude anything and says so.
        """
        report = LeakReport(interface=interface)
        report.checks.append(await self._check_public_ip(baseline_ip))
        report.checks.append(await self._check_default_route(interface))
        report.checks.append(await self._check_dns(interface, expected_dns))
        return report

    async def _check_public_ip(self, baseline_ip: str) -> LeakCheck:
        try:
            observed = (await self._probe.public_ip()).strip()
        except Exception as exc:  # noqa: BLE001 - any probe failure is UNKNOWN
            return LeakCheck(
                name="public_ip",
                status=LeakStatus.UNKNOWN,
                detail=f"could not determine public address: {exc}",
            )

        if not observed:
            return LeakCheck(
                name="public_ip",
                status=LeakStatus.UNKNOWN,
                detail="probe returned no address",
            )

        if not baseline_ip:
            return LeakCheck(
                name="public_ip",
                status=LeakStatus.UNKNOWN,
                observed=observed,
                detail=(
                    "no pre-tunnel baseline address supplied, so a change "
                    "cannot be detected; capture one before connecting"
                ),
            )

        if observed == baseline_ip.strip():
            return LeakCheck(
                name="public_ip",
                status=LeakStatus.LEAK,
                observed=observed,
                expected=f"any address other than {baseline_ip}",
                detail=(
                    "public address is unchanged from before the tunnel came "
                    "up: traffic is not being routed through it"
                ),
            )

        return LeakCheck(
            name="public_ip",
            status=LeakStatus.OK,
            observed=observed,
            detail="public address differs from the pre-tunnel baseline",
        )

    async def _check_default_route(self, interface: str) -> LeakCheck:
        try:
            result = await self._runner.run(["ip", "route", "show", "default"], timeout=10.0)
        except CommandError as exc:
            return LeakCheck(name="default_route", status=LeakStatus.UNKNOWN, detail=str(exc))

        if not result.executed:
            return LeakCheck(
                name="default_route",
                status=LeakStatus.UNKNOWN,
                detail="dry run: routing table not inspected",
            )
        if not result.ok:
            return LeakCheck(
                name="default_route",
                status=LeakStatus.UNKNOWN,
                detail=result.stderr.strip()[:200] or "could not read routes",
            )

        routes = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        if not routes:
            return LeakCheck(
                name="default_route",
                status=LeakStatus.UNKNOWN,
                detail="no default route present",
            )

        via_tunnel = [r for r in routes if f"dev {interface}" in r]
        if via_tunnel:
            return LeakCheck(
                name="default_route",
                status=LeakStatus.OK,
                observed=via_tunnel[0],
                detail=f"default route uses {interface}",
            )

        return LeakCheck(
            name="default_route",
            status=LeakStatus.LEAK,
            observed=routes[0],
            expected=f"default via {interface}",
            detail=(
                f"default route does not use {interface}: traffic to the "
                "internet bypasses the tunnel"
            ),
        )

    async def _check_dns(self, interface: str, expected_dns: Sequence[str]) -> LeakCheck:
        try:
            result = await self._runner.run(["resolvectl", "status"], timeout=10.0)
        except CommandError as exc:
            return LeakCheck(name="dns", status=LeakStatus.UNKNOWN, detail=str(exc))

        if not result.executed or not result.ok:
            return LeakCheck(
                name="dns",
                status=LeakStatus.UNKNOWN,
                detail=(
                    "dry run: resolvers not inspected"
                    if not result.executed
                    else (result.stderr.strip()[:200] or "resolvectl failed")
                ),
            )

        sections = parse_resolvectl_dns(result.stdout)
        if not sections:
            return LeakCheck(
                name="dns",
                status=LeakStatus.UNKNOWN,
                detail="no resolvers reported",
            )

        tunnel_servers = sections.get(interface, [])
        other_servers = [
            server for name, servers in sections.items() if name != interface for server in servers
        ]

        if expected_dns:
            allowed = {s.strip() for s in expected_dns}
            outside = [s for s in other_servers if s not in allowed]
            if outside:
                return LeakCheck(
                    name="dns",
                    status=LeakStatus.LEAK,
                    observed=", ".join(sorted(set(outside))),
                    expected=", ".join(sorted(allowed)),
                    detail=(
                        "resolvers outside the expected set are configured: "
                        "name lookups can be observed even though traffic is "
                        "encrypted"
                    ),
                )
            return LeakCheck(
                name="dns",
                status=LeakStatus.OK,
                observed=", ".join(sorted(set(tunnel_servers or allowed))),
                detail="all configured resolvers are expected ones",
            )

        # Without an expected set, a public resolver reachable off-tunnel is
        # the strongest signal available.
        public_off_tunnel = [s for s in other_servers if _is_public(s)]
        if public_off_tunnel and not tunnel_servers:
            return LeakCheck(
                name="dns",
                status=LeakStatus.LEAK,
                observed=", ".join(sorted(set(public_off_tunnel))),
                detail=(
                    f"no resolver is bound to {interface}, and public resolvers "
                    "are configured on other links"
                ),
            )
        if tunnel_servers:
            return LeakCheck(
                name="dns",
                status=LeakStatus.OK,
                observed=", ".join(tunnel_servers),
                detail=f"resolver(s) bound to {interface}",
            )
        return LeakCheck(
            name="dns",
            status=LeakStatus.UNKNOWN,
            detail=(
                "could not attribute resolvers to an interface; supply "
                "expected_dns for a definite answer"
            ),
        )


def _is_public(address: str) -> bool:
    try:
        parsed = ipaddress.ip_address(address.strip())
    except ValueError:
        return False
    return not (parsed.is_private or parsed.is_loopback or parsed.is_link_local)


def summarize(reports: Sequence[LeakReport]) -> Mapping[str, Any]:
    """Aggregate several reports for a health snapshot."""
    return {
        "total": len(reports),
        "leaking": sum(1 for r in reports if r.leaking),
        "inconclusive": sum(1 for r in reports if r.inconclusive and not r.leaking),
    }
