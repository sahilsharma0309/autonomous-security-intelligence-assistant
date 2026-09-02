"""Dynamic task planning.

A *plan* is a directed acyclic graph of tool invocations. The planner turns a
goal into that graph; the agent walks it, running independent steps
concurrently and respecting declared dependencies.

Two strategies ship here:

* :class:`RuleBasedPlanner` -- deterministic, offline, and the default. It
  orders the registry's capabilities by category and wires dependencies from
  the ``produces``/``consumes`` artifact declarations on each tool spec.
* :class:`SequentialPlanner` -- a trivial strategy that runs an explicit list
  of steps, useful for replaying a saved plan or for tests.

An LLM-backed strategy plugs in by implementing :class:`PlannerStrategy`; the
agent does not care which produced the plan. Whatever the source, every plan is
validated (:meth:`Plan.validate`) before execution, so a malformed or cyclic
plan is rejected up front rather than deadlocking at run time.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol, runtime_checkable

from security_assistant.core.exceptions import PlanningError, PlanValidationError
from security_assistant.core.registry import ToolRegistry
from security_assistant.core.types import (
    RiskLevel,
    TaskStatus,
    ToolCategory,
    ToolInvocation,
    new_id,
    utcnow,
)

logger = logging.getLogger(__name__)

__all__ = [
    "DEFAULT_CATEGORY_ORDER",
    "Plan",
    "PlanStep",
    "PlannerStrategy",
    "RuleBasedPlanner",
    "SequentialPlanner",
]

DEFAULT_CATEGORY_ORDER: tuple[ToolCategory, ...] = (
    # Network posture is established first so all subsequent traffic egresses
    # through the authorized path.
    ToolCategory.NETWORK,
    # Passive collection before anything that touches the target.
    ToolCategory.OSINT,
    ToolCategory.RECON,
    ToolCategory.SCANNING,
    ToolCategory.ANALYSIS,
    ToolCategory.MEMORY,
    ToolCategory.UTILITY,
)


@dataclass(slots=True)
class PlanStep:
    """One node in a plan."""

    tool_name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: new_id("step"))
    description: str = ""
    depends_on: tuple[str, ...] = ()
    optional: bool = False
    """When true, a failure here does not fail the plan."""

    status: TaskStatus = TaskStatus.PENDING

    def to_invocation(self) -> ToolInvocation:
        """Materialize this step as a dispatchable invocation."""
        return ToolInvocation(
            tool_name=self.tool_name,
            arguments=dict(self.arguments),
            step_id=self.id,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "tool_name": self.tool_name,
            "arguments": dict(self.arguments),
            "description": self.description,
            "depends_on": list(self.depends_on),
            "optional": self.optional,
            "status": self.status.value,
        }

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        deps = f" deps={list(self.depends_on)}" if self.depends_on else ""
        return f"<PlanStep {self.id} {self.tool_name} {self.status.value}{deps}>"


@dataclass(slots=True)
class Plan:
    """An executable DAG of steps."""

    goal: str
    steps: list[PlanStep] = field(default_factory=list)
    id: str = field(default_factory=lambda: new_id("plan"))
    target: str | None = None
    created_at: datetime = field(default_factory=utcnow)
    metadata: dict[str, Any] = field(default_factory=dict)

    # -- access ------------------------------------------------------------ #
    def __len__(self) -> int:
        return len(self.steps)

    def __iter__(self) -> Iterator[PlanStep]:
        return iter(self.steps)

    @property
    def step_map(self) -> dict[str, PlanStep]:
        return {s.id: s for s in self.steps}

    def step(self, step_id: str) -> PlanStep:
        """Return the step with ``step_id``."""
        for candidate in self.steps:
            if candidate.id == step_id:
                return candidate
        raise KeyError(f"No step {step_id!r} in plan {self.id}")

    def add(self, step: PlanStep) -> PlanStep:
        """Append a step (used by re-planning)."""
        if any(s.id == step.id for s in self.steps):
            raise PlanValidationError(f"Duplicate step id {step.id!r}")
        self.steps.append(step)
        return step

    # -- validation -------------------------------------------------------- #
    def validate(self, registry: ToolRegistry | None = None) -> None:
        """Check structural integrity, raising :class:`PlanValidationError`.

        Verifies unique ids, resolvable dependencies, absence of cycles and --
        when a registry is supplied -- that every referenced tool exists.
        """
        ids = [s.id for s in self.steps]
        duplicates = {i for i in ids if ids.count(i) > 1}
        if duplicates:
            raise PlanValidationError(f"Duplicate step ids: {sorted(duplicates)}")

        known = set(ids)
        for step in self.steps:
            dangling = set(step.depends_on) - known
            if dangling:
                raise PlanValidationError(
                    f"Step {step.id!r} depends on unknown step(s) {sorted(dangling)}"
                )
            if step.id in step.depends_on:
                raise PlanValidationError(f"Step {step.id!r} depends on itself")

        if registry is not None:
            missing = [s.tool_name for s in self.steps if s.tool_name not in registry]
            if missing:
                raise PlanValidationError(
                    f"Plan references unregistered tool(s): {sorted(set(missing))}"
                )

        # Cycle detection via Kahn's algorithm; a partial ordering means a cycle.
        ordered = self._topological_order()
        if len(ordered) != len(self.steps):
            remaining = known - {s.id for s in ordered}
            raise PlanValidationError(
                f"Plan contains a dependency cycle among steps {sorted(remaining)}"
            )

    def _topological_order(self) -> list[PlanStep]:
        indegree = {s.id: len(set(s.depends_on)) for s in self.steps}
        dependents: dict[str, list[str]] = {s.id: [] for s in self.steps}
        for step in self.steps:
            for dep in set(step.depends_on):
                if dep in dependents:
                    dependents[dep].append(step.id)

        by_id = self.step_map
        # Sort the frontier for deterministic output across runs.
        queue = sorted([sid for sid, deg in indegree.items() if deg == 0])
        ordered: list[PlanStep] = []

        while queue:
            current = queue.pop(0)
            ordered.append(by_id[current])
            newly_ready = []
            for dependent in dependents[current]:
                indegree[dependent] -= 1
                if indegree[dependent] == 0:
                    newly_ready.append(dependent)
            queue = sorted(queue + newly_ready)

        return ordered

    def topological_order(self) -> list[PlanStep]:
        """Steps in a valid execution order (raises if the plan is cyclic)."""
        ordered = self._topological_order()
        if len(ordered) != len(self.steps):
            raise PlanValidationError("Plan contains a dependency cycle")
        return ordered

    # -- execution helpers ------------------------------------------------- #
    def ready_steps(self) -> list[PlanStep]:
        """Pending steps whose dependencies have all finished successfully.

        A step whose dependency failed is *not* returned -- the agent marks it
        skipped instead (see :meth:`blocked_steps`).
        """
        by_id = self.step_map
        ready: list[PlanStep] = []
        for step in self.steps:
            if step.status is not TaskStatus.PENDING:
                continue
            if all(
                by_id[dep].status is TaskStatus.SUCCEEDED
                for dep in step.depends_on
                if dep in by_id
            ):
                ready.append(step)
        return ready

    def blocked_steps(self) -> list[PlanStep]:
        """Pending steps that can never run because a dependency did not succeed."""
        by_id = self.step_map
        blocked: list[PlanStep] = []
        for step in self.steps:
            if step.status is not TaskStatus.PENDING:
                continue
            for dep in step.depends_on:
                parent = by_id.get(dep)
                if parent is not None and parent.status in (
                    TaskStatus.FAILED,
                    TaskStatus.SKIPPED,
                    TaskStatus.CANCELLED,
                ):
                    blocked.append(step)
                    break
        return blocked

    @property
    def is_complete(self) -> bool:
        """True once no step remains pending or running."""
        return all(s.status.is_terminal for s in self.steps)

    def counts(self) -> dict[str, int]:
        """Step counts by status."""
        tally: dict[str, int] = {}
        for step in self.steps:
            tally[step.status.value] = tally.get(step.status.value, 0) + 1
        return tally

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "goal": self.goal,
            "target": self.target,
            "created_at": self.created_at.isoformat(),
            "steps": [s.to_dict() for s in self.steps],
            "metadata": dict(self.metadata),
            "counts": self.counts(),
        }

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Plan {self.id} steps={len(self.steps)} goal={self.goal[:40]!r}>"


@runtime_checkable
class PlannerStrategy(Protocol):
    """Produces a :class:`Plan` for a goal."""

    async def plan(
        self,
        goal: str,
        *,
        target: str | None = None,
        registry: ToolRegistry,
        context: Mapping[str, Any] | None = None,
    ) -> Plan:  # pragma: no cover - protocol declaration
        ...


class RuleBasedPlanner:
    """Deterministic planner driven by tool metadata.

    The plan is built in two passes:

    1. **Selection** -- take every registered tool that is permitted at or
       below ``max_risk``, optionally narrowed to ``categories``. Scope-gated
       tools are wired to the run's target; others are invoked bare.
    2. **Ordering** -- group by :data:`DEFAULT_CATEGORY_ORDER` so network
       posture precedes passive collection, which precedes active scanning,
       which precedes analysis. Within that, ``consumes``/``produces``
       declarations create fine-grained edges: a tool consuming ``hosts``
       depends on every tool producing ``hosts``.

    The result is a graph that maximizes safe concurrency -- independent
    collectors run together -- while guaranteeing analysis never starts before
    the data it reads exists.
    """

    def __init__(
        self,
        *,
        max_risk: RiskLevel = RiskLevel.ACTIVE,
        categories: Sequence[ToolCategory] | None = None,
        category_order: Sequence[ToolCategory] = DEFAULT_CATEGORY_ORDER,
        include_tags: Sequence[str] = (),
        optional_categories: Sequence[ToolCategory] = (ToolCategory.ANALYSIS,),
    ) -> None:
        self._max_risk = RiskLevel.parse(max_risk)
        self._categories = tuple(categories) if categories else None
        self._category_order = tuple(category_order)
        self._include_tags = tuple(include_tags)
        self._optional_categories = frozenset(optional_categories)

    async def plan(
        self,
        goal: str,
        *,
        target: str | None = None,
        registry: ToolRegistry,
        context: Mapping[str, Any] | None = None,
    ) -> Plan:
        selected = registry.select(
            categories=self._categories,
            max_risk=self._max_risk,
            tags=self._include_tags or None,
        )

        if not selected:
            raise PlanningError(
                f"No registered tool satisfies the planning constraints "
                f"(max_risk={self._max_risk}, categories={self._categories})"
            )

        scope_gated = [t for t in selected if t.spec.requires_scope]
        if scope_gated and not target:
            raise PlanningError(
                "A target is required: "
                f"{len(scope_gated)} selected tool(s) operate against a target "
                f"(e.g. {scope_gated[0].spec.name!r})"
            )

        order_index = {c: i for i, c in enumerate(self._category_order)}
        ranked = sorted(
            selected,
            key=lambda t: (
                order_index.get(t.spec.category, len(order_index)),
                t.spec.risk,
                t.spec.name,
            ),
        )

        plan = Plan(goal=goal, target=target)
        producers: dict[str, list[str]] = {}
        steps_by_category: dict[ToolCategory, list[str]] = {}
        unsatisfiable: dict[str, list[str]] = {}

        for tool in ranked:
            spec = tool.spec
            arguments: dict[str, Any] = {}
            if spec.requires_scope and target is not None:
                arguments[spec.target_argument] = target

            # Fill any other required parameter from the caller's context.
            for param in spec.parameters:
                if param.name in arguments or not param.required:
                    continue
                if context and param.name in context:
                    arguments[param.name] = context[param.name]

            # A tool needing an input nobody supplied is skipped, not planned.
            # Planning it anyway produces a step the dispatcher must reject as
            # INVALID, which fails the run and -- worse -- strands every step
            # that consumes what it would have produced. A tool like
            # `iot.shodan_search` (needs a query) or `osint.social` (needs a
            # username) is simply not applicable to a bare target, and saying
            # so here is more honest than dispatching it to fail.
            missing = sorted(
                p.name
                for p in spec.parameters
                if p.required and p.name not in arguments
            )
            if missing:
                unsatisfiable[spec.name] = missing
                logger.debug(
                    "Skipping %s: no value supplied for required argument(s) %s",
                    spec.name,
                    missing,
                )
                continue

            step = PlanStep(
                tool_name=spec.name,
                arguments=arguments,
                description=spec.description,
                optional=spec.category in self._optional_categories,
            )

            # Artifact edges: depend on everything producing what we consume.
            deps: set[str] = set()
            for artifact in spec.consumes:
                deps.update(producers.get(artifact, ()))

            # Category edges: a tool with no explicit artifact needs is
            # serialized behind the network tier when it touches the target, so
            # scan traffic never precedes the authorized egress path. Tools
            # carrying real dependency metadata keep their finer-grained edges
            # instead of being over-serialized.
            if not spec.consumes and spec.requires_scope:
                current_rank = order_index.get(spec.category, len(order_index))
                for category, ids in steps_by_category.items():
                    if (
                        category is ToolCategory.NETWORK
                        and order_index.get(category, len(order_index)) < current_rank
                    ):
                        deps.update(ids)

            step.depends_on = tuple(sorted(deps))
            plan.add(step)

            steps_by_category.setdefault(spec.category, []).append(step.id)
            for artifact in spec.produces:
                producers.setdefault(artifact, []).append(step.id)

        if not plan.steps:
            raise PlanningError(
                "No tool could be planned: every candidate needed an argument "
                f"that was not supplied ({sorted(unsatisfiable)})"
                if unsatisfiable
                else "No tool could be planned for this goal"
            )

        plan.metadata.update(
            {
                "planner": type(self).__name__,
                "max_risk": str(self._max_risk),
                "tool_count": len(plan.steps),
                # Recorded rather than dropped silently, so an operator can see
                # that a capability exists but went unused for want of an input.
                "skipped_unsatisfiable": dict(sorted(unsatisfiable.items())),
            }
        )
        plan.validate(registry)
        logger.info(
            "Planned goal=%r target=%s steps=%d planner=%s",
            goal,
            target,
            len(plan.steps),
            type(self).__name__,
        )
        return plan

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<RuleBasedPlanner max_risk={self._max_risk}>"


class SequentialPlanner:
    """Runs an explicit, caller-supplied list of steps in order.

    Each step depends on its predecessor, which makes this the right choice for
    replaying a reviewed plan or for deterministic tests.
    """

    def __init__(self, steps: Iterable[PlanStep]) -> None:
        self._template = list(steps)

    async def plan(
        self,
        goal: str,
        *,
        target: str | None = None,
        registry: ToolRegistry,
        context: Mapping[str, Any] | None = None,
    ) -> Plan:
        plan = Plan(goal=goal, target=target)
        previous: str | None = None

        for template in self._template:
            step = PlanStep(
                tool_name=template.tool_name,
                arguments=dict(template.arguments),
                description=template.description,
                optional=template.optional,
                depends_on=(previous,) if previous else (),
            )
            plan.add(step)
            previous = step.id

        plan.metadata["planner"] = type(self).__name__
        plan.validate(registry)
        return plan

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<SequentialPlanner steps={len(self._template)}>"
