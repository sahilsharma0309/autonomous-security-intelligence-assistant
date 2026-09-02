"""The process-level orchestrator: event loop, job queue, and lifecycle.

Where :class:`~security_assistant.core.agent.Agent` decides *what* to do for a
single goal, :class:`AgentOrchestrator` owns the long-lived process that runs
many such goals: a priority job queue, a pool of concurrent workers, graceful
startup and shutdown, and the background services (VPN supervision, health
monitors, schedulers) that must stay alive alongside them.

Design points worth knowing:

* **Bounded and back-pressured.** The queue has a configurable capacity;
  submitting to a full queue waits rather than growing without limit.
* **Graceful shutdown.** :meth:`AgentOrchestrator.stop` stops accepting work,
  lets in-flight jobs finish within a grace period, then cancels the stragglers
  and unwinds background services in reverse registration order.
* **Crash-isolated workers.** A worker that dies from an unexpected exception
  is logged and replaced; one poisoned job never drains the pool.
* **Signal-aware.** :meth:`run_forever` installs SIGINT/SIGTERM handlers so the
  daemon terminates cleanly under systemd or Docker.

Typical use::

    async with AgentOrchestrator(agent_factory=make_agent) as orch:
        job_id = await orch.submit("Inventory attack surface", target="example.com")
        result = await orch.wait_for(job_id)
"""

from __future__ import annotations

import asyncio
import logging
import signal
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum
from typing import Any, Protocol, runtime_checkable

from security_assistant.core.agent import Agent, AgentRunResult
from security_assistant.core.dispatcher import EventSink
from security_assistant.core.exceptions import (
    OrchestratorError,
    OrchestratorNotRunningError,
)
from security_assistant.core.types import TaskStatus, new_id, utcnow

logger = logging.getLogger(__name__)

__all__ = [
    "AgentOrchestrator",
    "BackgroundService",
    "Job",
    "JobPriority",
    "OrchestratorConfig",
]


class JobPriority(IntEnum):
    """Queue priority. Lower values are dequeued first."""

    URGENT = 0
    HIGH = 1
    NORMAL = 2
    LOW = 3

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.name


@dataclass(slots=True)
class Job:
    """One unit of work submitted to the orchestrator."""

    goal: str
    target: str | None = None
    priority: JobPriority = JobPriority.NORMAL
    context: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: new_id("job"))
    status: TaskStatus = TaskStatus.PENDING
    submitted_at: datetime = field(default_factory=utcnow)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    result: AgentRunResult | None = None
    error: str | None = None
    worker: str | None = None

    @property
    def is_finished(self) -> bool:
        return self.status.is_terminal

    @property
    def queue_time_ms(self) -> float:
        """Milliseconds spent waiting before a worker picked this up."""
        if self.started_at is None:
            return 0.0
        return (self.started_at - self.submitted_at).total_seconds() * 1000.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "goal": self.goal,
            "target": self.target,
            "priority": str(self.priority),
            "status": self.status.value,
            "submitted_at": self.submitted_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "queue_time_ms": round(self.queue_time_ms, 3),
            "worker": self.worker,
            "error": self.error,
            "result": self.result.to_dict() if self.result else None,
        }

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Job {self.id} {self.status.value} {self.priority} goal={self.goal[:32]!r}>"


@runtime_checkable
class BackgroundService(Protocol):
    """A long-lived component managed by the orchestrator's lifecycle.

    The VPN supervisor and health monitor implement this, so the orchestrator
    can guarantee the network posture is up before any job runs and torn down
    after the last one finishes.
    """

    @property
    def name(self) -> str:  # pragma: no cover - protocol declaration
        ...

    async def start(self) -> None:  # pragma: no cover - protocol declaration
        ...

    async def stop(self) -> None:  # pragma: no cover - protocol declaration
        ...


@dataclass(slots=True)
class OrchestratorConfig:
    """Tunables for the orchestrator process."""

    workers: int = 4
    """Number of jobs executed concurrently."""

    queue_size: int = 256
    """Maximum queued-but-not-started jobs; submission blocks when full."""

    shutdown_grace_seconds: float = 30.0
    """How long in-flight jobs get to finish during shutdown."""

    job_history_size: int = 500
    """Completed jobs retained for inspection."""

    install_signal_handlers: bool = True
    """Handle SIGINT/SIGTERM in :meth:`AgentOrchestrator.run_forever`."""

    start_services_before_workers: bool = True
    """Bring background services up before accepting work.

    Leave this on: it is what guarantees the VPN tunnel is established before
    any scan traffic is generated.
    """

    def __post_init__(self) -> None:
        if self.workers < 1:
            raise ValueError("workers must be >= 1")
        if self.queue_size < 1:
            raise ValueError("queue_size must be >= 1")
        if self.shutdown_grace_seconds < 0:
            raise ValueError("shutdown_grace_seconds must be >= 0")


AgentFactory = Callable[[], Agent]
"""Builds an :class:`Agent` for a worker. Called once per worker."""


class AgentOrchestrator:
    """Runs agents against a queue of jobs, with a managed lifecycle."""

    def __init__(
        self,
        agent_factory: AgentFactory,
        config: OrchestratorConfig | None = None,
        *,
        services: Sequence[BackgroundService] = (),
        event_sink: EventSink | None = None,
    ) -> None:
        if not callable(agent_factory):
            raise TypeError("agent_factory must be callable and return an Agent")

        self._agent_factory = agent_factory
        self._config = config or OrchestratorConfig()
        self._services: list[BackgroundService] = list(services)
        self._event_sink = event_sink

        self._queue: asyncio.PriorityQueue[tuple[int, int, str]] = asyncio.PriorityQueue(
            maxsize=self._config.queue_size
        )
        self._jobs: dict[str, Job] = {}
        self._completion: dict[str, asyncio.Event] = {}
        self._history: list[str] = []
        self._workers: list[asyncio.Task[None]] = []
        self._started_services: list[BackgroundService] = []

        self._running = False
        self._shutting_down = False
        self._sequence = 0
        self._started_at: datetime | None = None
        self._counters: dict[str, int] = {}
        self._lock = asyncio.Lock()

    # -- properties -------------------------------------------------------- #
    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def config(self) -> OrchestratorConfig:
        return self._config

    @property
    def queue_depth(self) -> int:
        return self._queue.qsize()

    @property
    def active_jobs(self) -> list[Job]:
        return [j for j in self._jobs.values() if j.status is TaskStatus.RUNNING]

    # -- service registration ---------------------------------------------- #
    def register_service(self, service: BackgroundService) -> None:
        """Add a background service.

        Services registered before :meth:`start` are brought up during startup;
        one registered afterwards is started immediately.
        """
        if any(s.name == service.name for s in self._services):
            raise OrchestratorError(f"A service named {service.name!r} is already registered")
        self._services.append(service)
        logger.debug("Registered background service %s", service.name)

    # -- lifecycle --------------------------------------------------------- #
    async def start(self) -> None:
        """Bring up services and worker tasks."""
        async with self._lock:
            if self._running:
                logger.debug("Orchestrator already running; start() ignored")
                return

            self._running = True
            self._shutting_down = False
            self._started_at = utcnow()

            if self._config.start_services_before_workers:
                await self._start_services()

            for index in range(self._config.workers):
                name = f"worker-{index}"
                task = asyncio.create_task(self._worker_loop(name), name=name)
                self._workers.append(task)

            if not self._config.start_services_before_workers:
                await self._start_services()

        logger.info(
            "Orchestrator started workers=%d queue_size=%d services=%d",
            self._config.workers,
            self._config.queue_size,
            len(self._services),
        )
        await self._emit("orchestrator.started", {"workers": self._config.workers})

    async def stop(self, *, drain: bool = True) -> None:
        """Stop accepting work and shut down cleanly.

        With ``drain=True`` the orchestrator waits (up to the configured grace
        period) for queued and in-flight jobs; otherwise it cancels immediately.
        """
        async with self._lock:
            if not self._running:
                return
            self._shutting_down = True

        logger.info("Orchestrator stopping (drain=%s)", drain)

        if drain and self._config.shutdown_grace_seconds > 0:
            try:
                await asyncio.wait_for(
                    self._queue.join(), timeout=self._config.shutdown_grace_seconds
                )
            except TimeoutError:
                logger.warning(
                    "Shutdown grace period (%.1fs) elapsed with %d job(s) still queued",
                    self._config.shutdown_grace_seconds,
                    self._queue.qsize(),
                )

        for task in self._workers:
            task.cancel()
        if self._workers:
            await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers.clear()

        await self._stop_services()

        # Anything still queued or running never completed; mark and release.
        for job in self._jobs.values():
            if not job.is_finished:
                job.status = TaskStatus.CANCELLED
                job.error = "Orchestrator shut down before the job completed"
                job.finished_at = utcnow()
                self._signal_completion(job.id)

        self._running = False
        logger.info("Orchestrator stopped")
        await self._emit("orchestrator.stopped", {"counters": dict(self._counters)})

    async def run_forever(self) -> None:
        """Start and block until a termination signal arrives.

        This is the daemon entry point. Signal handlers are installed on the
        running loop when supported (POSIX); on platforms without
        :meth:`asyncio.loop.add_signal_handler` the orchestrator still runs and
        relies on :class:`KeyboardInterrupt`.
        """
        await self.start()
        stop_event = asyncio.Event()

        if self._config.install_signal_handlers:
            loop = asyncio.get_running_loop()
            for sig in (signal.SIGINT, signal.SIGTERM):
                try:
                    loop.add_signal_handler(sig, stop_event.set)
                except (NotImplementedError, RuntimeError, AttributeError):
                    # Windows, or a non-main thread: fall back to KeyboardInterrupt.
                    logger.debug("Signal handler for %s unavailable on this platform", sig)

        try:
            await stop_event.wait()
        except (KeyboardInterrupt, asyncio.CancelledError):  # pragma: no cover
            logger.info("Interrupt received")
        finally:
            await self.stop(drain=True)

    async def __aenter__(self) -> AgentOrchestrator:
        await self.start()
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        await self.stop(drain=exc_type is None)

    # -- job submission ---------------------------------------------------- #
    async def submit(
        self,
        goal: str,
        *,
        target: str | None = None,
        priority: JobPriority = JobPriority.NORMAL,
        context: Mapping[str, Any] | None = None,
    ) -> str:
        """Enqueue a job and return its id.

        Blocks while the queue is full, applying back-pressure rather than
        letting the backlog grow unbounded.
        """
        if not self._running or self._shutting_down:
            raise OrchestratorNotRunningError(
                "Cannot submit work: the orchestrator is not accepting jobs"
            )

        job = Job(
            goal=goal,
            target=target,
            priority=priority,
            context=dict(context or {}),
        )
        self._jobs[job.id] = job
        self._completion[job.id] = asyncio.Event()

        self._sequence += 1
        # FIFO within a priority band via a monotonic sequence tiebreaker.
        await self._queue.put((int(priority), self._sequence, job.id))

        logger.info(
            "Job submitted id=%s priority=%s goal=%r target=%s queue_depth=%d",
            job.id,
            priority,
            goal,
            target,
            self._queue.qsize(),
        )
        await self._emit("job.submitted", {"job_id": job.id, "goal": goal})
        return job.id

    async def wait_for(self, job_id: str, timeout: float | None = None) -> Job:
        """Block until ``job_id`` reaches a terminal state and return it."""
        event = self._completion.get(job_id)
        if event is None:
            job = self._jobs.get(job_id)
            if job is None:
                raise KeyError(f"Unknown job {job_id!r}")
            return job

        if timeout is not None:
            await asyncio.wait_for(event.wait(), timeout=timeout)
        else:
            await event.wait()
        return self._jobs[job_id]

    async def submit_and_wait(
        self,
        goal: str,
        *,
        target: str | None = None,
        priority: JobPriority = JobPriority.NORMAL,
        context: Mapping[str, Any] | None = None,
        timeout: float | None = None,
    ) -> Job:
        """Convenience wrapper: :meth:`submit` then :meth:`wait_for`."""
        job_id = await self.submit(
            goal, target=target, priority=priority, context=context
        )
        return await self.wait_for(job_id, timeout=timeout)

    async def submit_all(
        self,
        specs: Iterable[Mapping[str, Any]],
        *,
        priority: JobPriority = JobPriority.NORMAL,
    ) -> list[str]:
        """Submit many jobs described as ``{"goal": ..., "target": ...}``."""
        job_ids = []
        for spec in specs:
            goal = spec.get("goal")
            if not goal:
                raise ValueError(f"Job spec is missing a 'goal': {spec!r}")
            job_ids.append(
                await self.submit(
                    str(goal),
                    target=spec.get("target"),
                    priority=spec.get("priority", priority),
                    context=spec.get("context"),
                )
            )
        return job_ids

    # -- introspection ----------------------------------------------------- #
    def get_job(self, job_id: str) -> Job:
        """Return a job by id."""
        try:
            return self._jobs[job_id]
        except KeyError:
            raise KeyError(f"Unknown job {job_id!r}") from None

    def jobs(self, status: TaskStatus | None = None) -> list[Job]:
        """All known jobs, optionally filtered by status."""
        values = list(self._jobs.values())
        if status is not None:
            values = [j for j in values if j.status is status]
        return sorted(values, key=lambda j: j.submitted_at)

    def stats(self) -> dict[str, Any]:
        """A health/metrics snapshot suitable for a status endpoint."""
        uptime = (
            (utcnow() - self._started_at).total_seconds() if self._started_at else 0.0
        )
        return {
            "running": self._running,
            "shutting_down": self._shutting_down,
            "uptime_seconds": round(uptime, 2),
            "workers": len(self._workers),
            "queue_depth": self._queue.qsize(),
            "queue_capacity": self._config.queue_size,
            "jobs_tracked": len(self._jobs),
            "jobs_active": len(self.active_jobs),
            "counters": dict(self._counters),
            "services": [s.name for s in self._started_services],
        }

    # -- internals --------------------------------------------------------- #
    async def _worker_loop(self, name: str) -> None:
        """Pull jobs off the queue until cancelled."""
        try:
            agent = self._agent_factory()
        except Exception:
            logger.exception("Worker %s could not build its agent; worker exiting", name)
            return

        logger.debug("Worker %s ready", name)

        while True:
            try:
                _priority, _seq, job_id = await self._queue.get()
            except asyncio.CancelledError:
                logger.debug("Worker %s cancelled while idle", name)
                raise

            try:
                await self._run_job(agent, self._jobs[job_id], name)
            except asyncio.CancelledError:
                job = self._jobs.get(job_id)
                if job is not None and not job.is_finished:
                    job.status = TaskStatus.CANCELLED
                    job.error = "Cancelled during shutdown"
                    job.finished_at = utcnow()
                    self._signal_completion(job.id)
                # `finally` below issues the single task_done() for this item.
                raise
            except Exception:
                logger.exception("Worker %s hit an unexpected error on job %s", name, job_id)
                job = self._jobs.get(job_id)
                if job is not None and not job.is_finished:
                    job.status = TaskStatus.FAILED
                    job.error = "Worker error"
                    job.finished_at = utcnow()
                    self._signal_completion(job.id)
            finally:
                self._queue.task_done()

    async def _run_job(self, agent: Agent, job: Job, worker: str) -> None:
        """Execute one job with the worker's agent."""
        job.status = TaskStatus.RUNNING
        job.started_at = utcnow()
        job.worker = worker
        started = time.perf_counter()

        logger.info(
            "Job started id=%s worker=%s queue_time_ms=%.1f",
            job.id,
            worker,
            job.queue_time_ms,
        )
        await self._emit("job.started", {"job_id": job.id, "worker": worker})

        try:
            result = await agent.run(job.goal, target=job.target, context=job.context)
            job.result = result
            job.status = (
                TaskStatus.SUCCEEDED if result.status is TaskStatus.SUCCEEDED else TaskStatus.FAILED
            )
            job.error = result.error
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            job.status = TaskStatus.FAILED
            job.error = f"{type(exc).__name__}: {exc}"
            logger.exception("Job %s raised", job.id)
        finally:
            job.finished_at = utcnow()
            self._bump(job.status.value)
            self._remember(job.id)
            self._signal_completion(job.id)

        logger.info(
            "Job finished id=%s status=%s duration_ms=%.1f",
            job.id,
            job.status.value,
            (time.perf_counter() - started) * 1000.0,
        )
        await self._emit(
            "job.finished", {"job_id": job.id, "status": job.status.value}
        )

    async def _start_services(self) -> None:
        """Start background services in registration order.

        A service that fails to start aborts startup and unwinds the ones
        already running -- a half-configured network posture is worse than none.
        """
        for service in self._services:
            try:
                await service.start()
            except Exception as exc:
                logger.exception("Background service %s failed to start", service.name)
                await self._stop_services()
                raise OrchestratorError(
                    f"Background service {service.name!r} failed to start: {exc}"
                ) from exc
            self._started_services.append(service)
            logger.info("Background service started: %s", service.name)

    async def _stop_services(self) -> None:
        """Stop services in reverse order, never letting one failure block the rest."""
        while self._started_services:
            service = self._started_services.pop()
            try:
                await service.stop()
                logger.info("Background service stopped: %s", service.name)
            except Exception:
                logger.exception("Background service %s failed to stop cleanly", service.name)

    def _signal_completion(self, job_id: str) -> None:
        event = self._completion.get(job_id)
        if event is not None:
            event.set()

    def _remember(self, job_id: str) -> None:
        """Retain a bounded history of completed jobs."""
        self._history.append(job_id)
        overflow = len(self._history) - self._config.job_history_size
        if overflow > 0:
            for stale in self._history[:overflow]:
                self._jobs.pop(stale, None)
                self._completion.pop(stale, None)
            del self._history[:overflow]

    def _bump(self, key: str) -> None:
        self._counters[key] = self._counters.get(key, 0) + 1

    async def _emit(self, event: str, payload: dict[str, Any]) -> None:
        if self._event_sink is None:
            return
        try:
            result = self._event_sink(event, payload)
            if asyncio.iscoroutine(result):
                await result
        except Exception:
            logger.exception("Event sink raised while handling %s", event)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        state = "running" if self._running else "stopped"
        return (
            f"<AgentOrchestrator {state} workers={len(self._workers)} "
            f"queued={self._queue.qsize()} jobs={len(self._jobs)}>"
        )
