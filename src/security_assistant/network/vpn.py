"""VPN tunnel lifecycle: status, handshake verification, reconnection.

Supports WireGuard and OpenVPN behind one :class:`VpnBackend` protocol, so the
daemon and CLI never branch on which implementation is in use.

**"Interface is up" is not "tunnel is working".** This is the distinction the
module is built around. A WireGuard interface stays up, keeps its routes, and
keeps accepting packets long after the peer has stopped answering -- traffic
just goes nowhere. Reporting that as connected is worse than reporting nothing,
because a kill-switch keyed on it will happily let traffic out of a tunnel that
is silently black-holing. So a tunnel is only ``UP`` when there is a *recent
handshake*; a live interface with a stale handshake is ``DEGRADED``, which is
its own state precisely so callers must decide what to do about it.

For OpenVPN, which has no handshake counter, the equivalent evidence is the
management interface's state line plus interface presence, and the module is
explicit that this is weaker.

Nothing here executes anything by default -- see
:mod:`security_assistant.network.commands`.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
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
    "OpenVpnBackend",
    "RecoveryState",
    "SupervisorStatus",
    "TunnelState",
    "TunnelStatus",
    "TunnelSupervisor",
    "VpnBackend",
    "VpnConfig",
    "VpnError",
    "VpnManager",
    "WireGuardBackend",
    "parse_wg_dump",
]

#: A WireGuard handshake older than this means the peer has stopped
#: answering. WireGuard rekeys about every 2 minutes when there is traffic,
#: so three minutes of silence is a real fault rather than an idle period.
STALE_HANDSHAKE_SECONDS = 180.0


class VpnError(RuntimeError):
    """A VPN operation failed."""


class TunnelState(StrEnum):
    """What a tunnel is actually doing."""

    DOWN = "down"
    """No interface, or the interface exists but carries no peer."""

    CONNECTING = "connecting"
    """Interface exists; no handshake completed yet."""

    UP = "up"
    """Interface exists and the peer answered recently."""

    DEGRADED = "degraded"
    """Interface is up but the last handshake is stale -- traffic is
    probably going nowhere. Deliberately not ``UP``."""

    UNKNOWN = "unknown"
    """Status could not be determined (tooling missing, command failed)."""

    @property
    def is_usable(self) -> bool:
        """Whether traffic can be trusted to this tunnel."""
        return self is TunnelState.UP


@dataclass(slots=True)
class TunnelStatus:
    """A point-in-time view of one tunnel."""

    interface: str
    state: TunnelState = TunnelState.UNKNOWN
    backend: str = ""
    endpoint: str = ""
    public_key: str = ""
    allowed_ips: list[str] = field(default_factory=list)
    last_handshake: datetime | None = None
    handshake_age_seconds: float | None = None
    rx_bytes: int = 0
    tx_bytes: int = 0
    detail: str = ""
    checked_at: datetime = field(default_factory=utcnow)

    @property
    def connected(self) -> bool:
        return self.state.is_usable

    def to_dict(self) -> dict[str, Any]:
        return {
            "interface": self.interface,
            "state": self.state.value,
            "backend": self.backend,
            "endpoint": self.endpoint,
            "public_key": self.public_key[:16] + "..." if self.public_key else "",
            "allowed_ips": list(self.allowed_ips),
            "last_handshake": (self.last_handshake.isoformat() if self.last_handshake else None),
            "handshake_age_seconds": self.handshake_age_seconds,
            "rx_bytes": self.rx_bytes,
            "tx_bytes": self.tx_bytes,
            "connected": self.connected,
            "detail": self.detail,
            "checked_at": self.checked_at.isoformat(),
        }


@runtime_checkable
class VpnBackend(Protocol):
    """Controls one VPN implementation."""

    name: str

    async def status(
        self, interface: str
    ) -> TunnelStatus:  # pragma: no cover - protocol declaration
        ...

    async def up(self, interface: str) -> TunnelStatus:  # pragma: no cover - protocol declaration
        ...

    async def down(self, interface: str) -> TunnelStatus:  # pragma: no cover - protocol declaration
        ...


# --------------------------------------------------------------------------- #
# WireGuard
# --------------------------------------------------------------------------- #
def parse_wg_dump(output: str, interface: str) -> TunnelStatus:
    """Parse ``wg show <iface> dump``.

    The dump format is tab-separated: the first line describes the interface
    (private key, public key, listen port, fwmark) and each later line is a
    peer (public key, preshared key, endpoint, allowed ips, last handshake,
    rx, tx, keepalive). Field positions are fixed, which is why this is
    parsed rather than scraped from the human-readable output.
    """
    status = TunnelStatus(interface=interface, backend="wireguard")
    lines = [line for line in output.splitlines() if line.strip()]

    if not lines:
        status.state = TunnelState.DOWN
        status.detail = "no interface"
        return status

    peers = lines[1:]
    if not peers:
        status.state = TunnelState.DOWN
        status.detail = "interface up but no peer configured"
        return status

    # One tunnel, one peer, in every configuration this manages.
    fields = peers[0].split("\t")
    if len(fields) < 8:
        status.state = TunnelState.UNKNOWN
        status.detail = f"unrecognized wg dump format ({len(fields)} fields)"
        return status

    status.public_key = fields[0].strip()
    endpoint = fields[2].strip()
    status.endpoint = "" if endpoint == "(none)" else endpoint
    status.allowed_ips = [
        a.strip() for a in fields[3].split(",") if a.strip() and a.strip() != "(none)"
    ]

    try:
        handshake_epoch = int(fields[4])
    except ValueError:
        handshake_epoch = 0
    try:
        status.rx_bytes = int(fields[5])
        status.tx_bytes = int(fields[6])
    except ValueError:  # pragma: no cover - defensive
        pass

    if handshake_epoch <= 0:
        status.state = TunnelState.CONNECTING
        status.detail = "no handshake yet"
        return status

    from datetime import UTC

    status.last_handshake = datetime.fromtimestamp(handshake_epoch, tz=UTC)
    age = (utcnow() - status.last_handshake).total_seconds()
    status.handshake_age_seconds = round(age, 1)

    if age <= STALE_HANDSHAKE_SECONDS:
        status.state = TunnelState.UP
        status.detail = f"handshake {age:.0f}s ago"
    else:
        # The interface is up and routes still point at it, but the peer has
        # gone quiet. Traffic is being dropped into a hole.
        status.state = TunnelState.DEGRADED
        status.detail = (
            f"last handshake {age:.0f}s ago (>{STALE_HANDSHAKE_SECONDS:.0f}s): "
            "peer is not responding"
        )
    return status


class WireGuardBackend:
    """WireGuard control via ``wg`` and ``wg-quick``."""

    name = "wireguard"

    __slots__ = ("_runner",)

    def __init__(self, runner: CommandRunner | None = None) -> None:
        self._runner = runner or default_runner()

    async def status(self, interface: str) -> TunnelStatus:
        _validate_interface(interface)
        try:
            result = await self._runner.run(
                ["wg", "show", interface, "dump"], privileged=True, timeout=10.0
            )
        except CommandError as exc:
            return TunnelStatus(
                interface=interface,
                backend=self.name,
                state=TunnelState.UNKNOWN,
                detail=str(exc),
            )

        if not result.executed:
            # A dry run cannot know the real state; saying DOWN would be a
            # guess presented as a fact.
            return TunnelStatus(
                interface=interface,
                backend=self.name,
                state=TunnelState.UNKNOWN,
                detail="dry run: status not queried",
            )
        if not result.ok:
            return TunnelStatus(
                interface=interface,
                backend=self.name,
                state=TunnelState.DOWN,
                detail=result.stderr.strip()[:200] or "interface not present",
            )
        return parse_wg_dump(result.stdout, interface)

    async def up(self, interface: str) -> TunnelStatus:
        _validate_interface(interface)
        result = await self._runner.run(
            ["wg-quick", "up", interface], privileged=True, timeout=60.0
        )
        if result.executed and not result.ok:
            raise VpnError(f"wg-quick up {interface} failed: {result.stderr.strip()[:300]}")
        return await self.status(interface)

    async def down(self, interface: str) -> TunnelStatus:
        _validate_interface(interface)
        result = await self._runner.run(
            ["wg-quick", "down", interface], privileged=True, timeout=60.0
        )
        if result.executed and not result.ok:
            raise VpnError(f"wg-quick down {interface} failed: {result.stderr.strip()[:300]}")
        return TunnelStatus(
            interface=interface,
            backend=self.name,
            state=TunnelState.DOWN,
            detail="brought down",
        )


# --------------------------------------------------------------------------- #
# OpenVPN
# --------------------------------------------------------------------------- #
_OPENVPN_STATE_RE = re.compile(r"^\d+,(?P<state>[A-Z_]+)", re.MULTILINE)

#: OpenVPN management states that mean the tunnel is carrying traffic.
_OPENVPN_UP_STATES = frozenset({"CONNECTED"})
_OPENVPN_PENDING_STATES = frozenset(
    {"CONNECTING", "WAIT", "AUTH", "GET_CONFIG", "ASSIGN_IP", "ADD_ROUTES", "RECONNECTING"}
)


class OpenVpnBackend:
    """OpenVPN control via ``systemctl`` for a named client unit.

    OpenVPN exposes no handshake counter, so ``UP`` here rests on the service
    being active plus the management state reading ``CONNECTED``. That is
    weaker evidence than WireGuard's handshake age, and
    :attr:`TunnelStatus.detail` says so rather than letting the two look
    equally certain.
    """

    name = "openvpn"

    __slots__ = ("_runner", "_unit_template")

    def __init__(
        self,
        runner: CommandRunner | None = None,
        unit_template: str = "openvpn-client@{interface}",
    ) -> None:
        self._runner = runner or default_runner()
        self._unit_template = unit_template

    def _unit(self, interface: str) -> str:
        return self._unit_template.format(interface=interface)

    async def status(self, interface: str) -> TunnelStatus:
        _validate_interface(interface)
        status = TunnelStatus(interface=interface, backend=self.name)

        try:
            result = await self._runner.run(
                ["systemctl", "is-active", self._unit(interface)], timeout=10.0
            )
        except CommandError as exc:
            status.state = TunnelState.UNKNOWN
            status.detail = str(exc)
            return status

        if not result.executed:
            status.state = TunnelState.UNKNOWN
            status.detail = "dry run: status not queried"
            return status

        active = result.stdout.strip()
        if active != "active":
            status.state = TunnelState.DOWN
            status.detail = f"unit {self._unit(interface)} is {active or 'inactive'}"
            return status

        # Active unit: confirm the link exists before claiming a usable tunnel.
        link = await self._runner.run(["ip", "link", "show", interface], timeout=10.0)
        if link.executed and not link.ok:
            status.state = TunnelState.CONNECTING
            status.detail = "service active but interface not present yet"
            return status

        status.state = TunnelState.UP
        status.detail = (
            "service active and interface present; OpenVPN exposes no "
            "handshake counter, so this is weaker evidence than WireGuard's"
        )
        return status

    async def up(self, interface: str) -> TunnelStatus:
        _validate_interface(interface)
        result = await self._runner.run(
            ["systemctl", "start", self._unit(interface)], privileged=True, timeout=60.0
        )
        if result.executed and not result.ok:
            raise VpnError(
                f"Starting {self._unit(interface)} failed: {result.stderr.strip()[:300]}"
            )
        return await self.status(interface)

    async def down(self, interface: str) -> TunnelStatus:
        _validate_interface(interface)
        result = await self._runner.run(
            ["systemctl", "stop", self._unit(interface)], privileged=True, timeout=60.0
        )
        if result.executed and not result.ok:
            raise VpnError(
                f"Stopping {self._unit(interface)} failed: {result.stderr.strip()[:300]}"
            )
        return TunnelStatus(
            interface=interface,
            backend=self.name,
            state=TunnelState.DOWN,
            detail="unit stopped",
        )


_INTERFACE_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,32}$")


def _validate_interface(interface: str) -> str:
    """Reject interface names that are not plain identifiers."""
    name = interface.strip()
    if not _INTERFACE_RE.match(name):
        raise VpnError(
            f"Invalid interface name {interface!r}: expected letters, digits, "
            "'_', '.', '@' or '-' (max 32 characters)"
        )
    return name


# --------------------------------------------------------------------------- #
# Manager
# --------------------------------------------------------------------------- #
class RecoveryState(StrEnum):
    """Where the supervisor's recovery state machine is.

    The machine exists so that autonomous recovery is bounded. An agent that
    retries a tunnel forever is not self-healing, it is a loop that hides a
    fault and hammers an endpoint; the terminal state is what turns a
    persistent failure into something a human is told about.
    """

    HEALTHY = "healthy"
    """Tunnel usable; nothing to do."""

    DEGRADED = "degraded"
    """Fault observed, recovery not yet started."""

    RECOVERING = "recovering"
    """A reconnect attempt is in flight."""

    BACKOFF = "backoff"
    """Waiting out the delay before the next attempt."""

    NEEDS_OPERATOR = "needs_operator"
    """Attempts exhausted. Terminal: the supervisor will not try again until
    an operator calls :meth:`TunnelSupervisor.reset`."""

    @property
    def is_terminal(self) -> bool:
        return self is RecoveryState.NEEDS_OPERATOR


@dataclass(slots=True)
class VpnConfig:
    """How a tunnel should be managed."""

    interface: str = "wg0"
    backend: str = "wireguard"

    auto_reconnect: bool = True
    """Recover a dropped tunnel without being asked. Bounded by
    ``max_reconnect_attempts`` and the supervisor's state machine, and
    disabled at runtime with ``--no-auto-reconnect``."""

    killswitch_enabled: bool = False
    """Engage the kill-switch when the tunnel is unusable. Off by default:
    it rewrites the host firewall, which needs a deliberate decision and a
    reachable admin path (see :mod:`security_assistant.network.killswitch`)."""

    max_reconnect_attempts: int = 5
    """After this many consecutive failures the supervisor stops and requires
    operator intervention."""

    reconnect_backoff_seconds: float = 5.0
    """Base delay; the supervisor doubles it per attempt."""

    max_backoff_seconds: float = 300.0
    treat_degraded_as_down: bool = True
    """A stale handshake triggers recovery. Turning this off leaves a
    black-holing tunnel alone."""

    def __post_init__(self) -> None:
        try:
            _validate_interface(self.interface)
        except VpnError as exc:
            # Construction-time validation raises ValueError like every other
            # *Config in this project; VpnError is for operational failures.
            raise ValueError(str(exc)) from exc
        if self.max_reconnect_attempts < 1:
            raise ValueError("max_reconnect_attempts must be >= 1")
        if self.reconnect_backoff_seconds < 0:
            raise ValueError("reconnect_backoff_seconds must be >= 0")
        if self.max_backoff_seconds < self.reconnect_backoff_seconds:
            raise ValueError("max_backoff_seconds must be >= reconnect_backoff_seconds")

    def backoff_for(self, attempt: int) -> float:
        """Exponential backoff for a 1-based attempt number, capped."""
        if attempt <= 1:
            return self.reconnect_backoff_seconds
        delay = self.reconnect_backoff_seconds * float(2 ** (attempt - 1))
        return float(min(delay, self.max_backoff_seconds))


class VpnManager:
    """Orchestrates one tunnel across whichever backend is configured."""

    def __init__(
        self,
        backend: VpnBackend | None = None,
        config: VpnConfig | None = None,
        runner: CommandRunner | None = None,
    ) -> None:
        self._config = config or VpnConfig()
        if backend is not None:
            self._backend = backend
        elif self._config.backend == "openvpn":
            self._backend = OpenVpnBackend(runner)
        else:
            self._backend = WireGuardBackend(runner)

    @property
    def config(self) -> VpnConfig:
        return self._config

    @property
    def backend(self) -> VpnBackend:
        return self._backend

    async def status(self) -> TunnelStatus:
        """Current tunnel state."""
        return await self._backend.status(self._config.interface)

    async def connect(self) -> TunnelStatus:
        """Bring the tunnel up (idempotent)."""
        current = await self.status()
        if current.state is TunnelState.UP:
            logger.info("Tunnel %s already up", self._config.interface)
            return current
        return await self._backend.up(self._config.interface)

    async def disconnect(self) -> TunnelStatus:
        """Bring the tunnel down."""
        return await self._backend.down(self._config.interface)

    async def reconnect_once(self) -> TunnelStatus:
        """Cycle the tunnel exactly once, with no retry or sleep.

        Retries, backoff and the give-up decision belong to
        :class:`TunnelSupervisor`, which owns the state machine. Keeping the
        loop out of here means the manager never blocks and the bound on
        attempts lives in exactly one place.
        """
        try:
            await self._backend.down(self._config.interface)
        except VpnError as exc:
            # A tunnel that was already down is not a failure to bring up.
            logger.debug("Ignoring teardown error during reconnect: %s", exc)

        return await self._backend.up(self._config.interface)

    async def reconnect(self) -> TunnelStatus:
        """Cycle the tunnel once, converting failure into a status.

        Convenience for the CLI, where a single explicit attempt is what the
        operator asked for.
        """
        try:
            return await self.reconnect_once()
        except VpnError as exc:
            return TunnelStatus(
                interface=self._config.interface,
                backend=self._backend.name,
                state=TunnelState.DOWN,
                detail=str(exc),
            )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"<VpnManager {self._config.interface} backend={self._backend.name} "
            f"auto_reconnect={self._config.auto_reconnect}>"
        )


@dataclass(slots=True)
class SupervisorStatus:
    """The supervisor's own state, distinct from the tunnel's."""

    state: RecoveryState = RecoveryState.HEALTHY
    attempts: int = 0
    next_attempt_after: float = 0.0
    last_error: str = ""
    last_transition: datetime = field(default_factory=utcnow)
    tunnel: TunnelStatus | None = None

    @property
    def needs_operator(self) -> bool:
        return self.state.is_terminal

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state.value,
            "attempts": self.attempts,
            "next_attempt_after_seconds": self.next_attempt_after,
            "needs_operator": self.needs_operator,
            "last_error": self.last_error,
            "last_transition": self.last_transition.isoformat(),
            "tunnel": self.tunnel.to_dict() if self.tunnel else None,
        }


class TunnelSupervisor:
    """Bounded autonomous recovery for one tunnel.

    Each call to :meth:`tick` advances the machine by at most one step, so the
    caller (the daemon) controls the cadence and the supervisor never blocks
    for a backoff period.

    ::

        HEALTHY ──fault──> DEGRADED ──> RECOVERING ──ok──> HEALTHY
                                            │
                                          fail
                                            ↓
                                         BACKOFF ──(attempts left)──> RECOVERING
                                            │
                                    (attempts exhausted)
                                            ↓
                                     NEEDS_OPERATOR  (terminal until reset)
    """

    def __init__(self, manager: VpnManager, *, clock: Any = None) -> None:
        self._manager = manager
        self._status = SupervisorStatus()
        self._clock = clock or _monotonic
        self._ready_at: float = 0.0

    @property
    def status(self) -> SupervisorStatus:
        return self._status

    @property
    def config(self) -> VpnConfig:
        return self._manager.config

    def reset(self) -> SupervisorStatus:
        """Clear a terminal state after an operator has intervened."""
        logger.info("Supervisor reset by operator for %s", self.config.interface)
        self._status = SupervisorStatus()
        self._ready_at = 0.0
        return self._status

    async def tick(self) -> SupervisorStatus:
        """Advance the machine one step and return the new status."""
        config = self.config

        if self._status.state is RecoveryState.NEEDS_OPERATOR:
            # Terminal. Still report the tunnel, but take no action.
            self._status.tunnel = await self._manager.status()
            return self._status

        tunnel = await self._manager.status()
        self._status.tunnel = tunnel

        healthy = tunnel.state is TunnelState.UP
        faulted = tunnel.state is TunnelState.DOWN or (
            config.treat_degraded_as_down and tunnel.state is TunnelState.DEGRADED
        )

        if healthy:
            if self._status.state is not RecoveryState.HEALTHY:
                logger.info(
                    "Tunnel %s recovered after %d attempt(s)",
                    config.interface,
                    self._status.attempts,
                )
                self._transition(RecoveryState.HEALTHY)
                self._status.attempts = 0
                self._status.last_error = ""
                self._status.next_attempt_after = 0.0
            return self._status

        if not faulted:
            # CONNECTING or UNKNOWN: not healthy, but not yet a fault worth
            # tearing the tunnel down over.
            return self._status

        if not config.auto_reconnect:
            self._transition(RecoveryState.DEGRADED)
            self._status.last_error = f"tunnel is {tunnel.state.value}; auto-reconnect disabled"
            return self._status

        if self._status.state is RecoveryState.BACKOFF:
            remaining = self._ready_at - self._clock()
            if remaining > 0:
                self._status.next_attempt_after = round(remaining, 1)
                return self._status

        return await self._attempt_recovery()

    async def _attempt_recovery(self) -> SupervisorStatus:
        config = self.config
        self._status.attempts += 1
        attempt = self._status.attempts
        self._transition(RecoveryState.RECOVERING)

        logger.warning(
            "Recovering tunnel %s (attempt %d/%d)",
            config.interface,
            attempt,
            config.max_reconnect_attempts,
        )

        try:
            tunnel = await self._manager.reconnect_once()
        except VpnError as exc:
            tunnel = TunnelStatus(
                interface=config.interface,
                backend=self._manager.backend.name,
                state=TunnelState.DOWN,
                detail=str(exc),
            )
        self._status.tunnel = tunnel

        if tunnel.state is TunnelState.UP:
            logger.info("Tunnel %s recovered on attempt %d", config.interface, attempt)
            self._transition(RecoveryState.HEALTHY)
            self._status.attempts = 0
            self._status.last_error = ""
            self._status.next_attempt_after = 0.0
            return self._status

        self._status.last_error = tunnel.detail or "reconnect did not bring the tunnel up"

        if attempt >= config.max_reconnect_attempts:
            logger.error(
                "Tunnel %s did not recover after %d attempts; operator "
                "intervention required. Last error: %s",
                config.interface,
                attempt,
                self._status.last_error,
            )
            self._transition(RecoveryState.NEEDS_OPERATOR)
            self._status.next_attempt_after = 0.0
            return self._status

        delay = config.backoff_for(attempt)
        self._ready_at = self._clock() + delay
        self._status.next_attempt_after = round(delay, 1)
        self._transition(RecoveryState.BACKOFF)
        logger.info("Tunnel %s still down; next attempt in %.0fs", config.interface, delay)
        return self._status

    def _transition(self, state: RecoveryState) -> None:
        if state is not self._status.state:
            logger.debug(
                "Supervisor %s: %s -> %s",
                self.config.interface,
                self._status.state.value,
                state.value,
            )
        self._status.state = state
        self._status.last_transition = utcnow()

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"<TunnelSupervisor {self.config.interface} "
            f"state={self._status.state.value} attempts={self._status.attempts}>"
        )


def _monotonic() -> float:
    import time

    return time.monotonic()


def backend_for(name: str, runner: CommandRunner | None = None) -> VpnBackend:
    """Build a backend by name."""
    normalized = name.strip().lower()
    if normalized in {"wireguard", "wg"}:
        return WireGuardBackend(runner)
    if normalized in {"openvpn", "ovpn"}:
        return OpenVpnBackend(runner)
    raise VpnError(f"Unknown VPN backend {name!r}; expected wireguard or openvpn")


def summarize(statuses: Sequence[TunnelStatus]) -> Mapping[str, Any]:
    """Aggregate several tunnels for a health report."""
    return {
        "total": len(statuses),
        "connected": sum(1 for s in statuses if s.connected),
        "degraded": sum(1 for s in statuses if s.state is TunnelState.DEGRADED),
        "down": sum(1 for s in statuses if s.state is TunnelState.DOWN),
    }
