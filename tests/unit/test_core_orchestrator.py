"""Tests for the orchestrator's queue, worker pool, and lifecycle."""

from __future__ import annotations

import asyncio

import pytest

from security_assistant.core import (
    Agent,
    AgentOrchestrator,
    AuthorizationScope,
    JobPriority,
    OrchestratorConfig,
    RiskLevel,
    TaskStatus,
    ToolCategory,
    ToolContext,
    ToolRegistry,
    tool,
)
from security_assistant.core.exceptions import (
    OrchestratorError,
    OrchestratorNotRunningError,
)
from tests.unit.conftest import run


class RecordingService:
    """A background service that records its lifecycle transitions."""

    def __init__(self, name: str = "fake-vpn") -> None:
        self._name = name
        self.started = 0
        self.stopped = 0

    @property
    def name(self) -> str:
        return self._name

    async def start(self) -> None:
        self.started += 1

    async def stop(self) -> None:
        self.stopped += 1


class FailingService(RecordingService):
    async def start(self) -> None:
        raise RuntimeError("tunnel refused to come up")


class TestLifecycle:
    def test_runs_a_job_end_to_end(
        self, registry: ToolRegistry, scope: AuthorizationScope
    ) -> None:
        async def scenario():
            orch = AgentOrchestrator(
                lambda: Agent(registry, scope), OrchestratorConfig(workers=2)
            )
            async with orch:
                return await orch.submit_and_wait(
                    "Assess", target="example.com", timeout=30
                )

        job = run(scenario())
        assert job.status is TaskStatus.SUCCEEDED
        assert job.result is not None and job.result.ok
        assert job.worker is not None

    def test_services_start_before_work_and_stop_after(
        self, registry: ToolRegistry, scope: AuthorizationScope
    ) -> None:
        service = RecordingService()

        async def scenario() -> tuple[int, int]:
            orch = AgentOrchestrator(
                lambda: Agent(registry, scope),
                OrchestratorConfig(workers=1),
                services=[service],
            )
            async with orch:
                assert service.started == 1
                await orch.submit_and_wait("Assess", target="example.com", timeout=30)
            return service.started, service.stopped

        assert run(scenario()) == (1, 1)

    def test_failing_service_aborts_startup(
        self, registry: ToolRegistry, scope: AuthorizationScope
    ) -> None:
        good = RecordingService("good")

        async def scenario() -> None:
            orch = AgentOrchestrator(
                lambda: Agent(registry, scope),
                OrchestratorConfig(workers=1),
                services=[good, FailingService("bad")],
            )
            await orch.start()

        with pytest.raises(OrchestratorError, match="failed to start"):
            run(scenario())
        # The already-started service must be unwound, not left running.
        assert good.stopped == 1

    def test_submit_refused_when_not_running(
        self, registry: ToolRegistry, scope: AuthorizationScope
    ) -> None:
        orch = AgentOrchestrator(lambda: Agent(registry, scope))
        with pytest.raises(OrchestratorNotRunningError):
            run(orch.submit("Assess", target="example.com"))

    def test_duplicate_service_name_rejected(
        self, registry: ToolRegistry, scope: AuthorizationScope
    ) -> None:
        orch = AgentOrchestrator(lambda: Agent(registry, scope))
        orch.register_service(RecordingService("dup"))
        with pytest.raises(OrchestratorError, match="already registered"):
            orch.register_service(RecordingService("dup"))

    def test_rejects_non_callable_factory(self) -> None:
        with pytest.raises(TypeError, match="must be callable"):
            AgentOrchestrator("not a factory")  # type: ignore[arg-type]

    def test_start_is_idempotent(
        self, registry: ToolRegistry, scope: AuthorizationScope
    ) -> None:
        async def scenario() -> int:
            orch = AgentOrchestrator(
                lambda: Agent(registry, scope), OrchestratorConfig(workers=2)
            )
            await orch.start()
            await orch.start()
            workers = orch.stats()["workers"]
            await orch.stop()
            return workers

        assert run(scenario()) == 2


class TestQueueing:
    def test_batch_submission(
        self, registry: ToolRegistry, scope: AuthorizationScope
    ) -> None:
        async def scenario() -> list:
            orch = AgentOrchestrator(
                lambda: Agent(registry, scope), OrchestratorConfig(workers=3)
            )
            async with orch:
                ids = await orch.submit_all(
                    [{"goal": f"g{i}", "target": "example.com"} for i in range(5)]
                )
                return [await orch.wait_for(i, timeout=30) for i in ids]

        jobs = run(scenario())
        assert len(jobs) == 5
        assert all(j.status is TaskStatus.SUCCEEDED for j in jobs)

    def test_submit_all_requires_a_goal(
        self, registry: ToolRegistry, scope: AuthorizationScope
    ) -> None:
        async def scenario() -> None:
            orch = AgentOrchestrator(lambda: Agent(registry, scope))
            async with orch:
                await orch.submit_all([{"target": "example.com"}])

        with pytest.raises(ValueError, match="missing a 'goal'"):
            run(scenario())

    def test_priority_ordering(self, scope: AuthorizationScope) -> None:
        """Higher-priority jobs jump the queue ahead of earlier low-priority ones."""
        order: list[str] = []
        release = asyncio.Event()

        @tool(
            name="util.record",
            description="Record the job label.",
            category=ToolCategory.UTILITY,
            risk=RiskLevel.PASSIVE,
            requires_scope=False,
        )
        async def record(ctx: ToolContext) -> str:
            label = ctx.config.get("label", "")
            if label == "blocker":
                await release.wait()
            order.append(label)
            return "ok"

        registry = ToolRegistry("priority")
        registry.register(record)

        async def scenario() -> list[str]:
            orch = AgentOrchestrator(
                lambda: Agent(registry, scope), OrchestratorConfig(workers=1)
            )
            async with orch:
                # Occupy the single worker so the rest genuinely queue up.
                blocker = await orch.submit("blocker", context={"label": "blocker"})
                for _ in range(300):
                    if orch.get_job(blocker).status is TaskStatus.RUNNING:
                        break
                    await asyncio.sleep(0.01)

                await orch.submit(
                    "low", priority=JobPriority.LOW, context={"label": "low"}
                )
                last = await orch.submit(
                    "urgent", priority=JobPriority.URGENT, context={"label": "urgent"}
                )
                release.set()
                await orch.wait_for(last, timeout=30)
            return order

        assert run(scenario()) == ["blocker", "urgent", "low"]


class TestObservability:
    def test_emits_lifecycle_events(
        self, registry: ToolRegistry, scope: AuthorizationScope
    ) -> None:
        events: list[str] = []

        async def scenario() -> None:
            orch = AgentOrchestrator(
                lambda: Agent(registry, scope),
                OrchestratorConfig(workers=1),
                event_sink=lambda e, p: events.append(e),
            )
            async with orch:
                await orch.submit_and_wait("Assess", target="example.com", timeout=30)

        run(scenario())
        assert {"orchestrator.started", "job.submitted", "job.finished"} <= set(events)

    def test_stats_snapshot(
        self, registry: ToolRegistry, scope: AuthorizationScope
    ) -> None:
        async def scenario() -> dict:
            orch = AgentOrchestrator(
                lambda: Agent(registry, scope), OrchestratorConfig(workers=2)
            )
            async with orch:
                await orch.submit_and_wait("Assess", target="example.com", timeout=30)
                return orch.stats()

        stats = run(scenario())
        assert stats["running"] is True
        assert stats["workers"] == 2
        assert stats["counters"].get("succeeded") == 1

    def test_unknown_job_lookup_raises(
        self, registry: ToolRegistry, scope: AuthorizationScope
    ) -> None:
        orch = AgentOrchestrator(lambda: Agent(registry, scope))
        with pytest.raises(KeyError):
            orch.get_job("nope")

    def test_job_serialization(
        self, registry: ToolRegistry, scope: AuthorizationScope
    ) -> None:
        async def scenario() -> dict:
            orch = AgentOrchestrator(lambda: Agent(registry, scope))
            async with orch:
                job = await orch.submit_and_wait(
                    "Assess", target="example.com", timeout=30
                )
                return job.to_dict()

        payload = run(scenario())
        assert payload["status"] == "succeeded"
        assert payload["result"] is not None


class TestConfigValidation:
    @pytest.mark.parametrize(
        "kwargs",
        [{"workers": 0}, {"queue_size": 0}, {"shutdown_grace_seconds": -1}],
    )
    def test_rejects_invalid_config(self, kwargs: dict) -> None:
        with pytest.raises(ValueError):
            OrchestratorConfig(**kwargs)
