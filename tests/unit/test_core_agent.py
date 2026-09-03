"""Tests for the agent's plan/execute/observe/remember loop."""

from __future__ import annotations

import pytest

from security_assistant.core import (
    Agent,
    AgentConfig,
    AuthorizationScope,
    Plan,
    PlanStep,
    RiskLevel,
    TaskStatus,
    ToolCategory,
    ToolContext,
    ToolParameter,
    ToolRegistry,
    tool,
)
from tests.unit.conftest import run


@tool(
    name="recon.broken",
    description="A collector that always fails.",
    category=ToolCategory.RECON,
    risk=RiskLevel.ACTIVE,
    parameters=[ToolParameter("target", str, description="Target")],
    produces=["hosts"],
)
async def broken_recon(ctx: ToolContext, target: str) -> list[str]:
    raise RuntimeError("collector exploded")


class TestSuccessfulRun:
    def test_runs_every_step(self, registry: ToolRegistry, scope: AuthorizationScope) -> None:
        agent = Agent(registry, scope, config=AgentConfig(name="t"))
        result = run(agent.run("Map external surface", target="example.com"))

        assert result.ok
        assert result.status is TaskStatus.SUCCEEDED
        assert len(result.results) == 4
        assert not result.denied

    def test_exposes_values_by_tool(
        self, registry: ToolRegistry, scope: AuthorizationScope
    ) -> None:
        agent = Agent(registry, scope)
        result = run(agent.run("goal", target="example.com"))
        assert "recon.dns" in result.values_by_tool()

    def test_summary_and_serialization(
        self, registry: ToolRegistry, scope: AuthorizationScope
    ) -> None:
        agent = Agent(registry, scope)
        result = run(agent.run("goal", target="example.com"))
        assert "succeeded" in result.summary()
        payload = result.to_dict()
        assert payload["status"] == "succeeded"
        assert len(payload["results"]) == 4

    def test_result_lookup_by_step(self, registry: ToolRegistry, scope: AuthorizationScope) -> None:
        agent = Agent(registry, scope)
        result = run(agent.run("goal", target="example.com"))
        step = result.plan.steps[0]
        assert result.result_for(step.id) is not None
        assert result.result_for("nonexistent") is None


class TestMemoryIntegration:
    def test_persists_and_recalls_across_runs(
        self, registry: ToolRegistry, scope: AuthorizationScope
    ) -> None:
        agent = Agent(registry, scope)

        async def scenario() -> tuple[int, list[str]]:
            await agent.run("Map external surface", target="example.com")
            size = await agent.memory.size()
            second = await agent.run("Map external surface", target="example.com")
            return size, second.recalled

        size, recalled = run(scenario())
        assert size > 0
        assert recalled, "second run should recall prior knowledge"

    def test_recall_can_be_disabled(
        self, registry: ToolRegistry, scope: AuthorizationScope
    ) -> None:
        agent = Agent(registry, scope, config=AgentConfig(recall_k=0))

        async def scenario() -> list[str]:
            await agent.run("goal", target="example.com")
            return (await agent.run("goal", target="example.com")).recalled

        assert run(scenario()) == []


class TestFailureHandling:
    def test_out_of_scope_target_fails_the_run(
        self, registry: ToolRegistry, scope: AuthorizationScope
    ) -> None:
        agent = Agent(registry, scope)
        result = run(agent.run("goal", target="unauthorized.net"))

        assert result.status is TaskStatus.FAILED
        assert len(result.denied) >= 2

    def test_dependent_steps_are_skipped_when_a_dependency_fails(
        self, scope: AuthorizationScope
    ) -> None:
        from tests.unit.conftest import correlate, vpn_up, whois_lookup

        registry = ToolRegistry("broken")
        registry.register_all([vpn_up, whois_lookup, broken_recon, correlate])

        agent = Agent(registry, scope)
        result = run(agent.run("goal", target="example.com"))

        correlate_step = next(s for s in result.plan.steps if s.tool_name == "analysis.correlate")
        assert correlate_step.status is TaskStatus.SKIPPED
        assert result.status is TaskStatus.FAILED

    def test_fail_fast_cancels_remaining_steps(self, scope: AuthorizationScope) -> None:
        from tests.unit.conftest import correlate, vpn_up, whois_lookup

        registry = ToolRegistry("failfast")
        registry.register_all([vpn_up, whois_lookup, broken_recon, correlate])

        agent = Agent(registry, scope, config=AgentConfig(fail_fast=True))
        result = run(agent.run("goal", target="example.com"))
        assert result.status is TaskStatus.CANCELLED

    def test_optional_step_failure_does_not_fail_the_run(self, scope: AuthorizationScope) -> None:
        # analysis.* is optional by default in RuleBasedPlanner, so a failure
        # there should not sink an otherwise clean assessment.
        from tests.unit.conftest import dns_resolve, vpn_up, whois_lookup

        @tool(
            name="analysis.flaky",
            description="Optional analysis that fails.",
            category=ToolCategory.ANALYSIS,
            risk=RiskLevel.PASSIVE,
            parameters=[ToolParameter("target", str)],
            consumes=["hosts"],
        )
        async def flaky_analysis(ctx: ToolContext, target: str) -> str:
            raise RuntimeError("analysis failed")

        registry = ToolRegistry("optional")
        registry.register_all([vpn_up, whois_lookup, dns_resolve, flaky_analysis])

        agent = Agent(registry, scope)
        result = run(agent.run("goal", target="example.com"))
        assert result.status is TaskStatus.SUCCEEDED
        assert len(result.failures) == 1

    def test_planning_failure_is_reported(self, scope: AuthorizationScope) -> None:
        agent = Agent(ToolRegistry("empty"), scope)
        result = run(agent.run("goal", target="example.com"))
        assert result.status is TaskStatus.FAILED
        assert "Planning failed" in (result.error or "")


class TestDryRun:
    def test_dry_run_succeeds_without_acting(
        self, registry: ToolRegistry, scope: AuthorizationScope
    ) -> None:
        agent = Agent(registry, scope, config=AgentConfig(dry_run=True))
        result = run(agent.run("goal", target="example.com"))

        assert result.ok
        assert all(r.value["dry_run"] for r in result.results)

    def test_dry_run_does_not_persist_memory(
        self, registry: ToolRegistry, scope: AuthorizationScope
    ) -> None:
        agent = Agent(registry, scope, config=AgentConfig(dry_run=True))

        async def scenario() -> int:
            await agent.run("goal", target="example.com")
            return await agent.memory.size()

        assert run(scenario()) == 0


class TestSuppliedPlan:
    def test_executes_a_caller_supplied_plan(
        self, registry: ToolRegistry, scope: AuthorizationScope
    ) -> None:
        plan = Plan(
            goal="explicit",
            steps=[
                PlanStep(
                    tool_name="osint.whois",
                    arguments={"target": "example.com"},
                    id="only",
                )
            ],
        )
        agent = Agent(registry, scope)
        result = run(agent.run("explicit", target="example.com", plan=plan))

        assert result.ok
        assert len(result.results) == 1
        assert result.results[0].tool_name == "osint.whois"


class TestRefinement:
    def test_refiner_can_append_steps(
        self, registry: ToolRegistry, scope: AuthorizationScope
    ) -> None:
        class AddOneStep:
            def __init__(self) -> None:
                self.calls = 0

            async def refine(self, plan, results, *, registry, context):
                self.calls += 1
                if self.calls > 1:
                    return []
                return [
                    PlanStep(
                        tool_name="osint.whois",
                        arguments={"target": "example.com"},
                        id="extra",
                    )
                ]

        agent = Agent(
            registry,
            scope,
            config=AgentConfig(max_refinement_rounds=2),
            refiner=AddOneStep(),
        )
        result = run(agent.run("goal", target="example.com"))
        assert any(r.step_id == "extra" for r in result.results)

    def test_broken_refiner_does_not_break_the_run(
        self, registry: ToolRegistry, scope: AuthorizationScope
    ) -> None:
        class Exploding:
            async def refine(self, plan, results, *, registry, context):
                raise RuntimeError("refiner is broken")

        agent = Agent(registry, scope, refiner=Exploding())
        assert run(agent.run("goal", target="example.com")).ok

    def test_invalid_refinement_is_rolled_back(
        self, registry: ToolRegistry, scope: AuthorizationScope
    ) -> None:
        class BadStep:
            async def refine(self, plan, results, *, registry, context):
                return [PlanStep(tool_name="not.registered", id="bad")]

        agent = Agent(registry, scope, refiner=BadStep())
        result = run(agent.run("goal", target="example.com"))
        assert all(s.tool_name != "not.registered" for s in result.plan.steps)


class TestConfigValidation:
    @pytest.mark.parametrize(
        "kwargs",
        [
            {"max_parallel_steps": 0},
            {"max_refinement_rounds": -1},
            {"run_timeout_seconds": 0},
        ],
    )
    def test_rejects_invalid_config(self, kwargs: dict) -> None:
        with pytest.raises(ValueError):
            AgentConfig(**kwargs)


class TestScopeSwap:
    def test_updating_scope_propagates_to_dispatcher(
        self, registry: ToolRegistry, scope: AuthorizationScope
    ) -> None:
        agent = Agent(registry, scope)
        wider = AuthorizationScope(allow=["other.test"], max_risk=RiskLevel.ACTIVE)
        agent.scope = wider
        assert agent.dispatcher.scope is wider
