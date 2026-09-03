"""Kill-switch: block non-VPN traffic when the tunnel is not usable.

This is the most dangerous code in the project, and not because of anything it
does to a target. A firewall policy that defaults to DROP and forgets one rule
takes the operator's own machine off the network -- and if that machine is
remote, it takes it away permanently, with no way back in to undo the change.
Every design choice here is about that failure.

**A plan is built, checked, then applied.** :class:`KillSwitchPlan` is an
ordered, inspectable list of rules with a matching rollback. Nothing is
executed while it is being assembled, so it can be printed, diffed, or
reviewed before anything happens.

**The lockout guard refuses unsafe plans.** :class:`LockoutGuard` rejects any
plan that does not preserve loopback, established connections, DHCP, and the
VPN endpoint itself -- because a policy that blocks the tunnel's own handshake
can never come back up -- plus any administrative CIDRs the operator named.
The guard runs before application, and it fails closed.

**Application is a dead-man's switch.** :meth:`KillSwitch.apply` installs the
rules and then rolls them back automatically unless
:meth:`KillSwitch.confirm` is called within a timeout. This is the
``iptables-apply`` pattern: if the new policy severed your own connection, you
cannot confirm, so the machine restores itself. Disabling it is possible and
must be explicit.

Nothing executes by default -- the default runner is a dry run.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from security_assistant.core.types import utcnow
from security_assistant.network.commands import (
    CommandError,
    CommandResult,
    CommandRunner,
    default_runner,
)

logger = logging.getLogger(__name__)

__all__ = [
    "FirewallFamily",
    "KillSwitch",
    "KillSwitchError",
    "KillSwitchPlan",
    "LockoutGuard",
    "LockoutRiskError",
    "build_iptables_plan",
]

#: How long the operator has to confirm before rules revert automatically.
DEFAULT_CONFIRM_SECONDS = 60.0


class KillSwitchError(RuntimeError):
    """A kill-switch operation failed or was refused."""


class LockoutRiskError(KillSwitchError):
    """A plan would probably cut the operator's own access."""


class FirewallFamily(StrEnum):
    IPTABLES = "iptables"
    NFTABLES = "nftables"


@dataclass(frozen=True, slots=True)
class FirewallRule:
    """One rule, as an argument vector plus why it exists."""

    argv: tuple[str, ...]
    purpose: str = ""

    @property
    def text(self) -> str:
        """Display form. Never re-parsed or executed as a string."""
        return " ".join(self.argv)

    def to_dict(self) -> dict[str, Any]:
        return {"command": self.text, "purpose": self.purpose}


@dataclass(slots=True)
class KillSwitchPlan:
    """An inspectable set of rules and the rollback that undoes them."""

    family: FirewallFamily
    interface: str
    rules: list[FirewallRule] = field(default_factory=list)
    rollback: list[FirewallRule] = field(default_factory=list)
    allowed_endpoints: list[str] = field(default_factory=list)
    admin_cidrs: list[str] = field(default_factory=list)
    created_at: Any = field(default_factory=utcnow)

    #: Purposes the guard requires to be present. Named rather than pattern
    #: matched so a renamed rule fails loudly instead of silently passing.
    REQUIRED_PURPOSES = (
        "allow-loopback",
        "allow-established",
        "allow-vpn-interface",
        "allow-vpn-endpoint",
    )

    def purposes(self) -> set[str]:
        return {r.purpose for r in self.rules}

    def describe(self) -> str:
        """Human-readable plan, for review before applying."""
        lines = [
            f"Kill-switch plan ({self.family.value}) for {self.interface}",
            f"  VPN endpoints preserved: {self.allowed_endpoints or ['(none)']}",
            f"  Admin networks preserved: {self.admin_cidrs or ['(none)']}",
            "  Rules:",
        ]
        lines.extend(f"    {i + 1:2d}. {r.text}   # {r.purpose}" for i, r in enumerate(self.rules))
        lines.append("  Rollback:")
        lines.extend(f"    {i + 1:2d}. {r.text}" for i, r in enumerate(self.rollback))
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "family": self.family.value,
            "interface": self.interface,
            "rules": [r.to_dict() for r in self.rules],
            "rollback": [r.to_dict() for r in self.rollback],
            "allowed_endpoints": list(self.allowed_endpoints),
            "admin_cidrs": list(self.admin_cidrs),
        }


_HOST_RE = re.compile(r"^[A-Za-z0-9_.:\[\]-]{1,255}$")


def _endpoint_host(endpoint: str) -> str:
    """``1.2.3.4:51820`` -> ``1.2.3.4``; ``[2001:db8::1]:51820`` -> ``2001:db8::1``."""
    text = endpoint.strip()
    if not text:
        return ""
    if text.startswith("["):
        end = text.find("]")
        return text[1:end] if end != -1 else ""
    host, _, _port = text.rpartition(":")
    return host or text


def build_iptables_plan(
    interface: str,
    *,
    endpoints: Sequence[str] = (),
    admin_cidrs: Sequence[str] = (),
    allow_dhcp: bool = True,
    allow_dns_to_vpn: bool = True,
) -> KillSwitchPlan:
    """Build a default-DROP plan that keeps the machine reachable.

    Rule order matters: the accepts are inserted before the policy flips, so
    there is never a window in which the policy is DROP and the exemptions are
    not yet present.
    """
    if not _HOST_RE.match(interface.strip()):
        raise KillSwitchError(f"Invalid interface name {interface!r}")

    plan = KillSwitchPlan(family=FirewallFamily.IPTABLES, interface=interface.strip())
    add = plan.rules.append

    add(
        FirewallRule(
            ("iptables", "-I", "OUTPUT", "1", "-o", "lo", "-j", "ACCEPT"),
            "allow-loopback",
        )
    )
    add(
        FirewallRule(
            (
                "iptables",
                "-I",
                "OUTPUT",
                "2",
                "-m",
                "conntrack",
                "--ctstate",
                "ESTABLISHED,RELATED",
                "-j",
                "ACCEPT",
            ),
            "allow-established",
        )
    )
    add(
        FirewallRule(
            ("iptables", "-I", "OUTPUT", "3", "-o", plan.interface, "-j", "ACCEPT"),
            "allow-vpn-interface",
        )
    )

    position = 4
    for endpoint in endpoints:
        host = _endpoint_host(endpoint)
        if not host:
            continue
        try:
            ipaddress.ip_address(host)
        except ValueError as exc:
            # A hostname here would be resolved by iptables at insert time,
            # which silently bakes in one address and breaks on rotation.
            raise KillSwitchError(
                f"VPN endpoint {endpoint!r} must be an IP address, not a hostname: {exc}"
            ) from exc
        add(
            FirewallRule(
                ("iptables", "-I", "OUTPUT", str(position), "-d", host, "-j", "ACCEPT"),
                "allow-vpn-endpoint",
            )
        )
        plan.allowed_endpoints.append(host)
        position += 1

    for cidr in admin_cidrs:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError as exc:
            raise KillSwitchError(f"Invalid admin CIDR {cidr!r}: {exc}") from exc
        add(
            FirewallRule(
                (
                    "iptables",
                    "-I",
                    "OUTPUT",
                    str(position),
                    "-d",
                    str(network),
                    "-j",
                    "ACCEPT",
                ),
                "allow-admin-network",
            )
        )
        plan.admin_cidrs.append(str(network))
        position += 1

    if allow_dhcp:
        add(
            FirewallRule(
                (
                    "iptables",
                    "-I",
                    "OUTPUT",
                    str(position),
                    "-p",
                    "udp",
                    "--dport",
                    "67:68",
                    "-j",
                    "ACCEPT",
                ),
                "allow-dhcp",
            )
        )
        position += 1

    if allow_dns_to_vpn:
        add(
            FirewallRule(
                (
                    "iptables",
                    "-I",
                    "OUTPUT",
                    str(position),
                    "-o",
                    plan.interface,
                    "-p",
                    "udp",
                    "--dport",
                    "53",
                    "-j",
                    "ACCEPT",
                ),
                "allow-dns-over-vpn",
            )
        )
        position += 1

    # The policy flip goes last, after every exemption is in place.
    add(FirewallRule(("iptables", "-P", "OUTPUT", "DROP"), "default-drop"))

    plan.rollback.append(
        FirewallRule(("iptables", "-P", "OUTPUT", "ACCEPT"), "restore-default-policy")
    )
    plan.rollback.append(FirewallRule(("iptables", "-F", "OUTPUT"), "flush-output-chain"))
    return plan


@dataclass(slots=True)
class LockoutGuard:
    """Refuses plans that would probably sever the operator's own access.

    Fails closed: an unrecognized plan is rejected rather than assumed safe.
    """

    require_endpoint: bool = True
    """A kill-switch with no exemption for the VPN endpoint can never let the
    tunnel re-establish, so the machine stays offline forever."""

    required_admin_cidrs: tuple[str, ...] = ()
    """Networks that must stay reachable, e.g. the range you SSH from."""

    def check(self, plan: KillSwitchPlan) -> None:
        """Raise :class:`LockoutRiskError` if the plan looks like a lockout."""
        present = plan.purposes()

        missing = [
            purpose
            for purpose in ("allow-loopback", "allow-established", "allow-vpn-interface")
            if purpose not in present
        ]
        if missing:
            raise LockoutRiskError(
                f"Refusing kill-switch: plan omits {missing}. Without these the "
                "host loses local and in-flight connectivity the moment the "
                "policy flips."
            )

        if self.require_endpoint and "allow-vpn-endpoint" not in present:
            raise LockoutRiskError(
                "Refusing kill-switch: no VPN endpoint exemption. The tunnel "
                "handshake would be blocked by its own kill-switch and could "
                "never reconnect. Pass the endpoint address, or set "
                "require_endpoint=False if you have another route back in."
            )

        for cidr in self.required_admin_cidrs:
            try:
                required = ipaddress.ip_network(cidr, strict=False)
            except ValueError as exc:  # pragma: no cover - config error
                raise LockoutRiskError(f"Invalid required admin CIDR {cidr!r}: {exc}") from exc
            if not any(_covers(allowed, required) for allowed in plan.admin_cidrs):
                raise LockoutRiskError(
                    f"Refusing kill-switch: administrative network {required} is "
                    f"not preserved by this plan (it allows {plan.admin_cidrs}). "
                    "Applying it would likely cut your own access to this host."
                )

        if not any(r.purpose == "default-drop" for r in plan.rules):
            raise LockoutRiskError(
                "Refusing kill-switch: plan never sets a default DROP policy, "
                "so it would not actually block anything."
            )

        if not plan.rollback:
            raise LockoutRiskError(
                "Refusing kill-switch: plan carries no rollback, so a mistake could not be undone."
            )


def _covers(allowed_cidr: str, required: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    try:
        allowed = ipaddress.ip_network(allowed_cidr, strict=False)
    except ValueError:  # pragma: no cover - defensive
        return False
    if allowed.version != required.version:
        return False
    return required.subnet_of(allowed)  # type: ignore[arg-type]


@dataclass(slots=True)
class KillSwitchState:
    """What the kill-switch currently is."""

    engaged: bool = False
    plan: KillSwitchPlan | None = None
    applied_at: Any = None
    confirmed: bool = False
    results: list[CommandResult] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "engaged": self.engaged,
            "confirmed": self.confirmed,
            "applied_at": self.applied_at.isoformat() if self.applied_at else None,
            "interface": self.plan.interface if self.plan else None,
            "rules_applied": len(self.results),
        }


class KillSwitch:
    """Applies and removes a kill-switch, with a dead-man's-switch rollback."""

    def __init__(
        self,
        runner: CommandRunner | None = None,
        guard: LockoutGuard | None = None,
    ) -> None:
        self._runner = runner or default_runner()
        self._guard = guard or LockoutGuard()
        self._state = KillSwitchState()
        self._rollback_task: asyncio.Task[None] | None = None

    @property
    def state(self) -> KillSwitchState:
        return self._state

    @property
    def engaged(self) -> bool:
        return self._state.engaged

    async def apply(
        self,
        plan: KillSwitchPlan,
        *,
        confirm_within: float | None = DEFAULT_CONFIRM_SECONDS,
    ) -> KillSwitchState:
        """Check, then apply a plan, arming an automatic rollback.

        ``confirm_within`` is the dead-man's switch: unless :meth:`confirm` is
        called within that many seconds, the rules are removed. Passing
        ``None`` disables it, which should be a deliberate choice on a host
        you can physically reach.
        """
        self._guard.check(plan)

        if self._state.engaged:
            raise KillSwitchError(
                "Kill-switch is already engaged; release it before applying another plan"
            )

        logger.warning(
            "Applying kill-switch on %s (%d rules). Auto-rollback in %s.",
            plan.interface,
            len(plan.rules),
            f"{confirm_within}s" if confirm_within else "DISABLED",
        )

        applied: list[CommandResult] = []
        try:
            for rule in plan.rules:
                result = await self._runner.run(
                    rule.argv, privileged=True, timeout=15.0, check=True
                )
                applied.append(result)
        except CommandError as exc:
            # A partial ruleset is the worst possible state: exemptions may be
            # in place with no policy, or a policy with no exemptions. Undo
            # immediately rather than leaving it.
            logger.error("Kill-switch application failed; rolling back: %s", exc)
            await self._run_rollback(plan)
            raise KillSwitchError(
                f"Kill-switch application failed and was rolled back: {exc}"
            ) from exc

        self._state = KillSwitchState(
            engaged=True,
            plan=plan,
            applied_at=utcnow(),
            confirmed=confirm_within is None,
            results=applied,
        )

        if confirm_within is not None:
            self._rollback_task = asyncio.create_task(self._auto_rollback(plan, confirm_within))
        return self._state

    def confirm(self) -> None:
        """Confirm connectivity survived, cancelling the automatic rollback."""
        if not self._state.engaged:
            raise KillSwitchError("Kill-switch is not engaged")
        self._state.confirmed = True
        if self._rollback_task is not None:
            self._rollback_task.cancel()
            self._rollback_task = None
        logger.info("Kill-switch confirmed; automatic rollback cancelled")

    async def release(self) -> KillSwitchState:
        """Remove the kill-switch."""
        if self._rollback_task is not None:
            self._rollback_task.cancel()
            self._rollback_task = None

        plan = self._state.plan
        if plan is not None:
            await self._run_rollback(plan)
        self._state = KillSwitchState(engaged=False)
        logger.info("Kill-switch released")
        return self._state

    async def _auto_rollback(self, plan: KillSwitchPlan, delay: float) -> None:
        try:
            await asyncio.sleep(delay)
        except asyncio.CancelledError:  # pragma: no cover - normal path
            return
        if self._state.confirmed:
            return
        logger.error(
            "Kill-switch was not confirmed within %.0fs; rolling back. "
            "This usually means the new policy cut the connection used to "
            "confirm it.",
            delay,
        )
        await self._run_rollback(plan)
        self._state = KillSwitchState(engaged=False)

    async def _run_rollback(self, plan: KillSwitchPlan) -> None:
        for rule in plan.rollback:
            try:
                await self._runner.run(rule.argv, privileged=True, timeout=15.0)
            except CommandError as exc:  # pragma: no cover - best effort
                # Keep going: every remaining rollback rule still matters.
                logger.error("Rollback step failed (%s): %s", rule.text, exc)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<KillSwitch engaged={self._state.engaged}>"


def plan_for_status(
    interface: str,
    endpoint: str = "",
    *,
    admin_cidrs: Iterable[str] = (),
) -> KillSwitchPlan:
    """Convenience: build a plan from a tunnel's interface and endpoint."""
    endpoints = [endpoint] if endpoint else []
    return build_iptables_plan(interface, endpoints=endpoints, admin_cidrs=list(admin_cidrs))
