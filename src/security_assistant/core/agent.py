"""The autonomous agent: plan, execute, observe, remember.

:class:`Agent` is the reasoning layer. It owns one engagement's worth of state
-- a scope, a toolset, a memory namespace -- and turns a stated goal into
executed work:

1. **Recall** prior knowledge about the target from long-term memory.
2. **Plan** a DAG of tool invocations via a :class:`PlannerStrategy`.
3. **Execute** the DAG, running independent steps concurrently and skipping
   those whose dependencies failed.
4. **Refine** -- after each wave, an optional strategy hook may append steps in
   response to what was just learned, which is what makes the agent adaptive
   rather than a fixed pipeline.
5. **Remember** salient results so the next run starts better informed.

The agent deliberately does *not* execute tools itself; every call goes through
the :class:`~security_assistant.core.dispatcher.ToolDispatcher` so the
authorization gate, rate limits and audit trail apply without exception.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol, runtime_checkable

from security_assistant.core.authorization import AuthorizationScope
from security_assistant.core.dispatcher import DispatcherConfig, EventSink, ToolDispatcher
from security_assistant.core.exceptions import PlanningError, PlanValidationError
from security_assistant.core.memory import LongTermMemory
from security_assistant.core.planner import Plan, PlannerStrategy, PlanStep, RuleBasedPlanner
from security_assistant.core.registry import ToolRegistry
from security_assistant.core.types import (
    TaskStatus,
    ToolContext,
    ToolResult,
    new_id,
    utcnow,
)

logger = logging.getLogger(__name__)

__all__ = ["Agent", "AgentConfig", "AgentRunResult", "RefinementStrategy"]


@runtime_checkable
class RefinementStrategy(Protocol):
    """Optional hook that appends steps in response to interim results.

    Implementations receive the live plan and the results from the wave that
    just completed, and return any additional steps to append. Returning an
    empty sequence ends the adaptive loop.
    """

    async def refine(
        self,
        plan: Plan,
        results: Sequence[ToolResult],
        *,
        registry: ToolRegistry,
        context: Mapping[str, Any],
    ) -> Sequence[PlanStep]:  # pragma: no cover - protocol declaration
        ...


@dataclass(slots=True)
class AgentConfig:
    """Behavioural knobs for a single agent."""

    name: str = "security-assistant"
    max_parallel_steps: int = 8
    """Concurrency ceiling for one wave of ready steps."""

    fail_fast: bool = False
    """Abort the run on the first failure of a non-optional step."""

    max_refinement_rounds: int = 3
    """Cap on adaptive re-planning, so the agent cannot loop indefinitely."""

    run_timeout_seconds: float | None = 1800.0
    """Wall-clock ceiling for one :meth:`Agent.run` call."""

    recall_k: int = 5
    """How many prior memories to pull in as context before planning."""

    persist_results: bool = True
    """Write a summary of successful steps back into long-term memory."""

    dry_run: bool = False
    """Plan and authorize, but have tools describe rather than act."""

    def __post_init__(self) -> None:
        if self.max_parallel_steps < 1:
            raise ValueError("max_parallel_steps must be >= 1")
        if self.max_refinement_rounds < 0:
            raise ValueError("max_refinement_rounds must be >= 0")
        if self.run_timeout_seconds is not None and self.run_timeout_seconds <= 0:
            raise ValueError("run_timeout_seconds must be positive")


@dataclass(slots=True)
class AgentRunResult:
    """Everything one :meth:`Agent.run` produced."""

    goal: str
    status: TaskStatus
    plan: Plan | None = None
    results: list[ToolResult] = field(default_factory=list)
    target: str | None = None
    run_id: str = field(default_factory=lambda: new_id("run"))
    started_at: datetime = field(default_factory=utcnow)
    finished_at: datetime | None = None
    duration_ms: float = 0.0
    error: str | None = None
    recalled: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.status is TaskStatus.SUCCEEDED

    @property
    def succeeded(self) -> list[ToolResult]:
        return [r for r in self.results if r.ok]

    @property
    def failures(self) -> list[ToolResult]:
        return [r for r in self.results if not r.ok]

    @property
    def denied(self) -> list[ToolResult]:
        """Results blocked by the authorization gate.

        Worth surfacing prominently: a denial usually means the operator aimed
        at something outside the agreed engagement scope.
        """
        return [r for r in self.results if r.denied]

    def result_for(self, step_id: str) -> ToolResult | None:
        for result in self.results:
            if result.step_id == step_id:
                return result
        return None

    def values_by_tool(self) -> dict[str, Any]:
        """Successful return values keyed by tool name (last write wins)."""
        return {r.tool_name: r.value for r in self.results if r.ok}

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "goal": self.goal,
            "target": self.target,
            "status": self.status.value,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "duration_ms": round(self.duration_ms, 3),
            "error": self.error,
            "plan": self.plan.to_dict() if self.plan else None,
            "results": [r.to_dict() for r in self.results],
            "recalled": list(self.recalled),
            "metadata": dict(self.metadata),
        }

    def summary(self) -> str:
        """One-line human summary, suitable for logs and CLI output."""
        total = len(self.results)
        ok = len(self.succeeded)
        denied = len(self.denied)
        parts = [f"{ok}/{total} steps succeeded"]
        if denied:
            parts.append(f"{denied} denied by scope")
        failed = total - ok - denied
        if failed > 0:
            parts.append(f"{failed} failed")
        return (
            f"[{self.status.value}] {self.goal!r}"
            + (f" target={self.target}" if self.target else "")
            + " -- "
            + ", ".join(parts)
            + f" in {self.duration_ms / 1000:.2f}s"
        )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<AgentRunResult {self.run_id} {self.status.value} steps={len(self.results)}>"


class Agent:
    """A goal-directed, tool-using agent bound to one authorization scope.

    >>> agent = Agent(registry=registry, scope=scope)          # doctest: +SKIP
    >>> result = await agent.run("Inventory external attack surface",
    ...                          target="example.com")          # doctest: +SKIP
    >>> print(result.summary())                                 # doctest: +SKIP
    """

    def __init__(
        self,
        registry: ToolRegistry,
        scope: AuthorizationScope | None = None,
        *,
        config: AgentConfig | None = None,
        planner: PlannerStrategy | None = None,
        memory: LongTermMemory | None = None,
        dispatcher: ToolDispatcher | None = None,
        dispatcher_config: DispatcherConfig | None = None,
        refiner: RefinementStrategy | None = None,
        event_sink: EventSink | None = None,
    ) -> None:
        self._registry = registry
        self._scope = scope or AuthorizationScope.deny_all()
        self._config = config or AgentConfig()
        self._planner: PlannerStrategy = planner or RuleBasedPlanner(max_risk=self._scope.max_risk)
        self._memory = memory if memory is not None else LongTermMemory()
        self._refiner = refiner
        self._event_sink = event_sink
        self._dispatcher = dispatcher or ToolDispatcher(
            registry,
            self._scope,
            dispatcher_config,
            event_sink=event_sink,
        )
        self._runs: int = 0

    # -- properties -------------------------------------------------------- #
    @property
    def name(self) -> str:
        return self._config.name

    @property
    def registry(self) -> ToolRegistry:
        return self._registry

    @property
    def dispatcher(self) -> ToolDispatcher:
        return self._dispatcher

    @property
    def memory(self) -> LongTermMemory:
        return self._memory

    @property
    def scope(self) -> AuthorizationScope:
        return self._scope

    @scope.setter
    def scope(self, value: AuthorizationScope) -> None:
        self._scope = value
        self._dispatcher.scope = value

    @property
    def runs_completed(self) -> int:
        return self._runs

    # -- main entry point -------------------------------------------------- #
    async def run(
        self,
        goal: str,
        *,
        target: str | None = None,
        context: Mapping[str, Any] | None = None,
        plan: Plan | None = None,
    ) -> AgentRunResult:
        """Plan and execute ``goal``.

        Supplying ``plan`` skips the planning phase, which is how a reviewed or
        replayed plan is executed verbatim.

        Never raises for tool failures -- inspect the returned
        :class:`AgentRunResult`. Genuine programming errors and cancellation
        still propagate.
        """
        run_id = new_id("run")
        started = time.perf_counter()
        outcome = AgentRunResult(goal=goal, target=target, status=TaskStatus.RUNNING, run_id=run_id)

        deadline = (
            time.monotonic() + self._config.run_timeout_seconds
            if self._config.run_timeout_seconds
            else None
        )
        ctx = ToolContext(
            scope=self._scope,
            correlation_id=run_id,
            dry_run=self._config.dry_run,
            config=dict(context or {}),
            deadline=deadline,
        )

        logger.info(
            "Agent run starting agent=%s run_id=%s goal=%r target=%s scope=%s",
            self._config.name,
            run_id,
            goal,
            target,
            self._scope.engagement or "<unset>",
        )
        await self._emit("agent.run.start", {"run_id": run_id, "goal": goal, "target": target})

        try:
            if self._config.run_timeout_seconds:
                await asyncio.wait_for(
                    self._execute_run(goal, target, context, plan, ctx, outcome),
                    timeout=self._config.run_timeout_seconds,
                )
            else:
                await self._execute_run(goal, target, context, plan, ctx, outcome)
        except TimeoutError:
            outcome.status = TaskStatus.FAILED
            outcome.error = f"Run exceeded its {self._config.run_timeout_seconds:.0f}s time budget"
            logger.error("Agent run timed out run_id=%s", run_id)
        except asyncio.CancelledError:
            outcome.status = TaskStatus.CANCELLED
            outcome.error = "Run cancelled"
            self._finalize(outcome, started)
            raise
        except PlanningError as exc:
            outcome.status = TaskStatus.FAILED
            outcome.error = f"Planning failed: {exc}"
            logger.error("Agent planning failed run_id=%s error=%s", run_id, exc)
        except Exception as exc:
            outcome.status = TaskStatus.FAILED
            outcome.error = f"{type(exc).__name__}: {exc}"
            logger.exception("Agent run failed unexpectedly run_id=%s", run_id)

        self._finalize(outcome, started)
        self._runs += 1

        await self._emit(
            "agent.run.finish",
            {
                "run_id": run_id,
                "status": outcome.status.value,
                "steps": len(outcome.results),
                "duration_ms": outcome.duration_ms,
            },
        )
        logger.info("Agent run complete %s", outcome.summary())
        return outcome

    # -- phases ------------------------------------------------------------ #
    async def _execute_run(
        self,
        goal: str,
        target: str | None,
        context: Mapping[str, Any] | None,
        supplied_plan: Plan | None,
        ctx: ToolContext,
        outcome: AgentRunResult,
    ) -> None:
        """Recall -> plan -> execute -> remember."""
        merged_context: dict[str, Any] = dict(context or {})

        # 1. Recall ---------------------------------------------------------- #
        if self._config.recall_k > 0:
            recalled = await self._recall(goal, target)
            outcome.recalled = [r.text for r in recalled]
            if recalled:
                merged_context["prior_knowledge"] = outcome.recalled
                logger.debug("Recalled %d prior memories for run", len(recalled))

        # 2. Plan ------------------------------------------------------------ #
        if supplied_plan is not None:
            plan = supplied_plan
            plan.validate(self._registry)
        else:
            plan = await self._planner.plan(
                goal, target=target, registry=self._registry, context=merged_context
            )
        outcome.plan = plan
        ctx.state["plan_id"] = plan.id

        await self._emit(
            "agent.plan.ready",
            {"run_id": outcome.run_id, "plan_id": plan.id, "steps": len(plan.steps)},
        )

        # 3. Execute --------------------------------------------------------- #
        await self._execute_plan(plan, ctx, outcome, merged_context)

        # 4. Decide the overall verdict --------------------------------------- #
        outcome.status = self._verdict(plan)

        # 5. Remember --------------------------------------------------------- #
        if self._config.persist_results and not self._config.dry_run:
            await self._persist(outcome)

    async def _execute_plan(
        self,
        plan: Plan,
        ctx: ToolContext,
        outcome: AgentRunResult,
        context: dict[str, Any],
    ) -> None:
        """Walk the DAG wave by wave until nothing is runnable."""
        rounds = 0

        while True:
            # Steps whose dependencies failed can never run; retire them.
            for blocked in plan.blocked_steps():
                blocked.status = TaskStatus.SKIPPED
                logger.info(
                    "Skipping step=%s tool=%s (dependency did not succeed)",
                    blocked.id,
                    blocked.tool_name,
                )

            wave = plan.ready_steps()
            if not wave:
                # Nothing runnable: try one adaptive refinement round.
                if (
                    self._refiner is not None
                    and rounds < self._config.max_refinement_rounds
                    and not plan.is_complete
                ):
                    rounds += 1
                    if await self._refine(plan, outcome.results, context, rounds):
                        continue
                break

            for step in wave:
                step.status = TaskStatus.RUNNING

            invocations = [s.to_invocation() for s in wave]
            results = await self._dispatcher.dispatch_many(
                invocations, ctx, max_concurrency=self._config.max_parallel_steps
            )

            by_step = {r.step_id: r for r in results if r.step_id}
            aborted = False

            for step in wave:
                result = by_step.get(step.id)
                if result is None:  # pragma: no cover - defensive
                    step.status = TaskStatus.FAILED
                    continue

                outcome.results.append(result)
                step.status = TaskStatus.SUCCEEDED if result.ok else TaskStatus.FAILED

                # Share successful output with later steps in the same run.
                if result.ok:
                    ctx.state[step.tool_name] = result.value

                if not result.ok and not step.optional and self._config.fail_fast:
                    logger.warning(
                        "fail_fast: aborting run after step=%s tool=%s status=%s",
                        step.id,
                        step.tool_name,
                        result.status.value,
                    )
                    aborted = True

            if aborted:
                for step in plan.steps:
                    if step.status is TaskStatus.PENDING:
                        step.status = TaskStatus.CANCELLED
                break

            # Adaptive re-planning after a completed wave.
            if self._refiner is not None and rounds < self._config.max_refinement_rounds:
                rounds += 1
                await self._refine(plan, outcome.results, context, rounds)

    async def _refine(
        self,
        plan: Plan,
        results: Sequence[ToolResult],
        context: Mapping[str, Any],
        round_number: int,
    ) -> bool:
        """Ask the refiner for more steps. Returns whether any were added."""
        if self._refiner is None:
            return False
        try:
            extra = await self._refiner.refine(
                plan, list(results), registry=self._registry, context=context
            )
        except Exception:
            logger.exception("Refinement strategy raised; continuing without it")
            return False

        added = 0
        for step in extra or ():
            try:
                plan.add(step)
                added += 1
            except Exception:
                logger.exception("Refiner produced an invalid step; ignoring it")

        if not added:
            return False

        try:
            plan.validate(self._registry)
        except PlanValidationError as exc:
            # Roll the additions back rather than executing an invalid graph.
            del plan.steps[-added:]
            logger.error("Refined plan failed validation (%s); rolled back", exc)
            return False

        logger.info("Refinement round %d added %d step(s)", round_number, added)
        return True

    def _verdict(self, plan: Plan) -> TaskStatus:
        """Decide the run's overall status from its steps.

        Optional steps are excluded: a best-effort enrichment failing does not
        make the assessment itself a failure.
        """
        if any(s.status is TaskStatus.CANCELLED for s in plan.steps):
            return TaskStatus.CANCELLED
        required = [s for s in plan.steps if not s.optional]
        if any(s.status in (TaskStatus.FAILED, TaskStatus.SKIPPED) for s in required):
            return TaskStatus.FAILED
        return TaskStatus.SUCCEEDED

    # -- memory ------------------------------------------------------------ #
    async def _recall(self, goal: str, target: str | None) -> list[Any]:
        query = f"{goal} {target}" if target else goal
        try:
            return await self._memory.recall(query, k=self._config.recall_k)
        except Exception:
            logger.exception("Memory recall failed; continuing without prior knowledge")
            return []

    async def _persist(self, outcome: AgentRunResult) -> None:
        """Write a compact summary of the run into long-term memory."""
        successes = outcome.succeeded
        if not successes:
            return

        items: list[tuple[str, dict[str, Any]]] = []
        for result in successes:
            summary = _summarize_value(result.value)
            if not summary:
                continue
            items.append(
                (
                    f"{result.tool_name} on {outcome.target or 'n/a'}: {summary}",
                    {
                        "run_id": outcome.run_id,
                        "tool": result.tool_name,
                        "target": outcome.target,
                        "status": result.status.value,
                    },
                )
            )

        if not items:
            return

        try:
            await self._memory.remember_many(items)
            logger.debug("Persisted %d memories from run=%s", len(items), outcome.run_id)
        except Exception:
            logger.exception("Failed to persist run results to memory")

    # -- helpers ----------------------------------------------------------- #
    def _finalize(self, outcome: AgentRunResult, started: float) -> None:
        outcome.finished_at = utcnow()
        outcome.duration_ms = (time.perf_counter() - started) * 1000.0
        if outcome.status is TaskStatus.RUNNING:
            outcome.status = TaskStatus.FAILED
        outcome.metadata.setdefault("agent", self._config.name)
        outcome.metadata.setdefault("dry_run", self._config.dry_run)
        outcome.metadata.setdefault("denied_count", sum(1 for r in outcome.results if r.denied))

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
        return (
            f"<Agent {self._config.name!r} tools={len(self._registry)} "
            f"scope={self._scope.engagement or '<unset>'} runs={self._runs}>"
        )


def _summarize_value(value: Any, limit: int = 240) -> str:
    """Render a tool's return value as a short memory-friendly string."""
    if value is None:
        return ""
    if isinstance(value, str):
        text = value
    elif isinstance(value, Mapping):
        parts = [f"{k}={_short(v)}" for k, v in list(value.items())[:8]]
        text = ", ".join(parts)
    elif isinstance(value, (list, tuple, set)):
        items = list(value)
        text = f"{len(items)} item(s): " + ", ".join(_short(i) for i in items[:8])
    else:
        text = str(value)

    text = " ".join(text.split())
    return text[:limit] + ("..." if len(text) > limit else "")


def _short(value: Any, limit: int = 40) -> str:
    text = " ".join(str(value).split())
    return text[:limit] + ("..." if len(text) > limit else "")
