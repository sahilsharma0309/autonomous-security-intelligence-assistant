"""The background daemon: heartbeat, health, tunnel supervision, recovery.

One asyncio loop drives three periodic jobs -- health sampling, tunnel
supervision, and worker liveness -- each on its own interval, plus a heartbeat
that records the daemon is alive.

**Restart budgets, not restart loops.** A worker that dies once is a blip; a
worker that dies every two seconds is a bug, and restarting it forever burns
CPU while hiding the fault. :class:`WorkerSupervisor` gives each worker a
bounded number of restarts inside a rolling window, then stops and marks it
``FAILED``, which surfaces in the health report. Self-healing that never gives
up is not self-healing.

**Shutdown is orderly and bounded.** SIGTERM (systemd's stop signal) and SIGINT
set a stop event; in-flight jobs get a grace period, then are cancelled. A
daemon that ignores SIGTERM gets SIGKILL from the service manager, losing any
chance to release a kill-switch or record why it stopped.

**Nothing here is privileged.** All system interaction goes through the
injected VPN supervisor and command runner, which default to dry runs.
"""

from __future__ import annotations

import asyncio
import contextlib
import functools
import logging
import signal
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from security_assistant.core.types import utcnow
from security_assistant.daemon.health import (
    HealthGrade,
    HealthMonitor,
    HealthReport,
)
from security_assistant.network.vpn import (
    RecoveryState,
    SupervisorStatus,
    TunnelSupervisor,
)

logger = logging.getLogger(__name__)

__all__ = [
    "DaemonConfig",
    "DaemonState",
    "SecurityDaemon",
    "WorkerSpec",
    "WorkerState",
    "WorkerSupervisor",
]


class WorkerState(StrEnum):
    """Lifecycle of a managed background worker."""

    STOPPED = "stopped"
    RUNNING = "running"
    RESTARTING = "restarting"
    FAILED = "failed"
    """Restart budget exhausted. Terminal until an operator intervenes."""

    @property
    def is_terminal(self) -> bool:
        return self is WorkerState.FAILED


@dataclass(slots=True)
class WorkerSpec:
    """A long-running coroutine the daemon keeps alive."""

    name: str
    factory: Callable[[], Awaitable[None]]
    max_restarts: int = 5
    """Restarts allowed inside ``restart_window_seconds`` before giving up."""

    restart_window_seconds: float = 300.0
    restart_delay_seconds: float = 2.0
    critical: bool = False
    """If True, this worker failing takes the daemon down rather than leaving
    it running in a state that only looks healthy."""

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("Worker name must not be empty")
        if self.max_restarts < 0:
            raise ValueError("max_restarts must be >= 0")


@dataclass(slots=True)
class WorkerStatus:
    """What one worker is doing."""

    name: str
    state: WorkerState = WorkerState.STOPPED
    restarts: int = 0
    last_error: str = ""
    started_at: Any = None
    recent_restarts: list[float] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "state": self.state.value,
            "restarts": self.restarts,
            "last_error": self.last_error,
            "started_at": self.started_at.isoformat() if self.started_at else None,
        }


class WorkerSupervisor:
    """Keeps workers alive within a restart budget."""

    def __init__(self, *, clock: Callable[[], float] | None = None) -> None:
        self._specs: dict[str, WorkerSpec] = {}
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._status: dict[str, WorkerStatus] = {}
        self._clock = clock or _monotonic
        self._stopping = False

    @property
    def statuses(self) -> dict[str, WorkerStatus]:
        return dict(self._status)

    @property
    def busy(self) -> int:
        return sum(1 for s in self._status.values() if s.state is WorkerState.RUNNING)

    @property
    def total(self) -> int:
        return len(self._specs)

    @property
    def failed(self) -> list[str]:
        return [n for n, s in self._status.items() if s.state.is_terminal]

    def register(self, spec: WorkerSpec) -> None:
        if spec.name in self._specs:
            raise ValueError(f"Worker {spec.name!r} is already registered")
        self._specs[spec.name] = spec
        self._status[spec.name] = WorkerStatus(name=spec.name)

    async def start_all(self) -> None:
        for name in self._specs:
            await self.start(name)

    async def start(self, name: str) -> None:
        spec = self._specs.get(name)
        if spec is None:
            raise KeyError(f"No worker registered as {name!r}")
        if name in self._tasks and not self._tasks[name].done():
            return

        status = self._status[name]
        if status.state.is_terminal:
            logger.warning("Worker %s is FAILED (restart budget exhausted); not starting", name)
            return

        status.state = WorkerState.RUNNING
        status.started_at = utcnow()
        self._tasks[name] = asyncio.create_task(self._run(spec), name=f"worker:{name}")

    async def _run(self, spec: WorkerSpec) -> None:
        status = self._status[spec.name]
        while not self._stopping:
            try:
                await spec.factory()
                logger.info("Worker %s completed normally", spec.name)
                status.state = WorkerState.STOPPED
                return
            except asyncio.CancelledError:
                status.state = WorkerState.STOPPED
                raise
            except Exception as exc:
                status.last_error = f"{type(exc).__name__}: {exc}"
                logger.exception("Worker %s crashed", spec.name)

            if self._stopping:
                status.state = WorkerState.STOPPED
                return

            now = self._clock()
            window_start = now - spec.restart_window_seconds
            status.recent_restarts = [t for t in status.recent_restarts if t >= window_start]

            if len(status.recent_restarts) >= spec.max_restarts:
                logger.error(
                    "Worker %s exceeded its restart budget (%d in %.0fs); marking "
                    "FAILED. Last error: %s",
                    spec.name,
                    spec.max_restarts,
                    spec.restart_window_seconds,
                    status.last_error,
                )
                status.state = WorkerState.FAILED
                return

            status.recent_restarts.append(now)
            status.restarts += 1
            status.state = WorkerState.RESTARTING
            delay = spec.restart_delay_seconds * (2 ** min(len(status.recent_restarts) - 1, 5))
            logger.warning(
                "Restarting worker %s in %.1fs (restart %d)",
                spec.name,
                delay,
                status.restarts,
            )
            try:
                await asyncio.sleep(delay)
            except asyncio.CancelledError:
                status.state = WorkerState.STOPPED
                raise
            status.state = WorkerState.RUNNING
            status.started_at = utcnow()

    def reset(self, name: str) -> WorkerStatus:
        """Clear a FAILED worker after an operator has intervened."""
        status = self._status.get(name)
        if status is None:
            raise KeyError(f"No worker registered as {name!r}")
        status.state = WorkerState.STOPPED
        status.recent_restarts.clear()
        status.last_error = ""
        return status

    async def stop_all(self, grace_seconds: float = 5.0) -> None:
        """Cancel every worker, giving each a grace period first."""
        self._stopping = True
        tasks = [t for t in self._tasks.values() if not t.done()]
        for task in tasks:
            task.cancel()
        if tasks:
            with contextlib.suppress(asyncio.TimeoutError, TimeoutError):
                await asyncio.wait_for(
                    asyncio.gather(*tasks, return_exceptions=True),
                    timeout=grace_seconds,
                )
        for status in self._status.values():
            if status.state is not WorkerState.FAILED:
                status.state = WorkerState.STOPPED
        self._tasks.clear()


def _monotonic() -> float:
    import time

    return time.monotonic()


@dataclass(slots=True)
class DaemonConfig:
    """How the daemon runs."""

    health_interval_seconds: float = 30.0
    tunnel_interval_seconds: float = 15.0
    heartbeat_interval_seconds: float = 60.0
    shutdown_grace_seconds: float = 10.0
    install_signal_handlers: bool = True
    max_iterations: int | None = None
    """Stop after this many loop iterations. For tests and one-shot runs;
    ``None`` means run until stopped."""

    def __post_init__(self) -> None:
        for name in (
            "health_interval_seconds",
            "tunnel_interval_seconds",
            "heartbeat_interval_seconds",
        ):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be positive")


@dataclass(slots=True)
class DaemonState:
    """What the daemon has seen."""

    started_at: Any = None
    iterations: int = 0
    heartbeats: int = 0
    last_health: HealthReport | None = None
    last_tunnel: SupervisorStatus | None = None
    stopped: bool = False
    stop_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "iterations": self.iterations,
            "heartbeats": self.heartbeats,
            "stopped": self.stopped,
            "stop_reason": self.stop_reason,
            "health": self.last_health.to_dict() if self.last_health else None,
            "tunnel": self.last_tunnel.to_dict() if self.last_tunnel else None,
        }


class SecurityDaemon:
    """Long-running supervisor for health, tunnels and workers."""

    def __init__(
        self,
        *,
        config: DaemonConfig | None = None,
        health: HealthMonitor | None = None,
        tunnel: TunnelSupervisor | None = None,
        workers: WorkerSupervisor | None = None,
        on_event: Callable[[str, Mapping[str, Any]], None] | None = None,
    ) -> None:
        self._config = config or DaemonConfig()
        self._health = health or HealthMonitor()
        self._tunnel = tunnel
        self._workers = workers or WorkerSupervisor()
        self._on_event = on_event
        self._state = DaemonState()
        self._stop = asyncio.Event()

    @property
    def state(self) -> DaemonState:
        return self._state

    @property
    def workers(self) -> WorkerSupervisor:
        return self._workers

    def request_stop(self, reason: str = "requested") -> None:
        """Ask the loop to finish its current iteration and exit."""
        if not self._state.stopped:
            self._state.stop_reason = reason
        self._stop.set()

    async def run(self) -> DaemonState:
        """Run until stopped. Returns the final state."""
        self._state = DaemonState(started_at=utcnow())
        self._stop = asyncio.Event()

        if self._config.install_signal_handlers:
            self._install_signal_handlers()

        await self._workers.start_all()
        self._emit("daemon.started", {"workers": self._workers.total})

        try:
            await self._loop()
        finally:
            await self._workers.stop_all(self._config.shutdown_grace_seconds)
            self._state.stopped = True
            self._emit("daemon.stopped", {"reason": self._state.stop_reason})
            logger.info("Daemon stopped: %s", self._state.stop_reason or "clean exit")

        return self._state

    async def _loop(self) -> None:
        config = self._config
        next_health = 0.0
        next_tunnel = 0.0
        next_heartbeat = 0.0
        elapsed = 0.0
        tick = min(
            config.health_interval_seconds,
            config.tunnel_interval_seconds,
            config.heartbeat_interval_seconds,
        )

        while not self._stop.is_set():
            self._state.iterations += 1

            if elapsed >= next_tunnel:
                await self._check_tunnel()
                next_tunnel = elapsed + config.tunnel_interval_seconds

            if elapsed >= next_health:
                await self._check_health()
                next_health = elapsed + config.health_interval_seconds

            if elapsed >= next_heartbeat:
                self._heartbeat()
                next_heartbeat = elapsed + config.heartbeat_interval_seconds

            if (
                config.max_iterations is not None
                and self._state.iterations >= config.max_iterations
            ):
                self.request_stop("max_iterations reached")
                break

            # A timeout here is the normal path: it means the stop event did
            # not fire during this tick, so the loop simply continues.
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._stop.wait(), timeout=tick)
            elapsed += tick

    async def _check_health(self) -> None:
        try:
            report = await self._health.check(
                workers_busy=self._workers.busy, workers_total=self._workers.total
            )
        except Exception as exc:
            logger.exception("Health check failed")
            self._emit("health.error", {"error": str(exc)})
            return

        failed = self._workers.failed
        if failed:
            report.notes.append(f"workers requiring operator attention: {failed}")
            report.grades["workers"] = HealthGrade.CRITICAL

        self._state.last_health = report
        if report.overall.is_bad:
            logger.warning("Health %s: %s", report.overall.value, report.to_dict()["grades"])
        self._emit("health.checked", report.to_dict())

    async def _check_tunnel(self) -> None:
        if self._tunnel is None:
            return
        try:
            status = await self._tunnel.tick()
        except Exception as exc:
            logger.exception("Tunnel supervision failed")
            self._emit("tunnel.error", {"error": str(exc)})
            return

        previous = self._state.last_tunnel
        self._state.last_tunnel = status

        if previous is None or previous.state is not status.state:
            self._emit("tunnel.state_changed", status.to_dict())
            if status.state is RecoveryState.NEEDS_OPERATOR:
                logger.error(
                    "Tunnel %s needs operator intervention after %d attempts: %s",
                    self._tunnel.config.interface,
                    status.attempts,
                    status.last_error,
                )

    def _heartbeat(self) -> None:
        self._state.heartbeats += 1
        payload = {
            "heartbeat": self._state.heartbeats,
            "iterations": self._state.iterations,
            "workers": {n: s.state.value for n, s in self._workers.statuses.items()},
        }
        logger.debug("Heartbeat %d", self._state.heartbeats)
        self._emit("daemon.heartbeat", payload)

    def _emit(self, event: str, payload: Mapping[str, Any]) -> None:
        if self._on_event is None:
            return
        try:
            self._on_event(event, payload)
        except Exception:
            logger.exception("Event listener for %r raised", event)

    def _install_signal_handlers(self) -> None:
        """Handle SIGTERM/SIGINT so shutdown is orderly.

        systemd sends SIGTERM; ignoring it means SIGKILL after the timeout and
        no chance to record why the daemon stopped.
        """
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:  # pragma: no cover - defensive
            return
        for signame in ("SIGTERM", "SIGINT"):
            sig = getattr(signal, signame, None)
            if sig is None:  # pragma: no cover - platform dependent
                continue
            try:
                loop.add_signal_handler(
                    sig, functools.partial(self.request_stop, f"received {signame}")
                )
            except (NotImplementedError, RuntimeError):  # pragma: no cover
                logger.debug("Signal handler for %s unavailable here", signame)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<SecurityDaemon iterations={self._state.iterations} workers={self._workers.total}>"


def worker_from_coroutine(
    name: str, coroutine_factory: Callable[[], Awaitable[None]], **kwargs: Any
) -> WorkerSpec:
    """Convenience constructor for a :class:`WorkerSpec`."""
    return WorkerSpec(name=name, factory=coroutine_factory, **kwargs)


def summarize_workers(statuses: Sequence[WorkerStatus]) -> Mapping[str, Any]:
    """Aggregate worker states for a report."""
    counts: dict[str, int] = {}
    for status in statuses:
        counts[status.state.value] = counts.get(status.state.value, 0) + 1
    return {"total": len(statuses), "by_state": counts}
