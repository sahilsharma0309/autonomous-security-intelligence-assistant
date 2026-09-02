"""Tests for plan construction, validation, and DAG traversal."""

from __future__ import annotations

import pytest

from security_assistant.core import (
    Plan,
    PlanStep,
    RiskLevel,
    RuleBasedPlanner,
    SequentialPlanner,
    TaskStatus,
    ToolCategory,
    ToolRegistry,
)
from security_assistant.core.exceptions import PlanningError, PlanValidationError
from tests.unit.conftest import run


class TestRuleBasedPlanner:
    def test_plans_every_permitted_tool(self, registry: ToolRegistry) -> None:
        plan = run(
            RuleBasedPlanner(max_risk=RiskLevel.ACTIVE).plan(
                "assess", target="example.com", registry=registry
            )
        )
        assert len(plan) == 4

    def test_orders_network_before_active_work(self, registry: ToolRegistry) -> None:
        plan = run(
            RuleBasedPlanner(max_risk=RiskLevel.ACTIVE).plan(
                "assess", target="example.com", registry=registry
            )
        )
        order = [s.tool_name for s in plan.topological_order()]
        assert order.index("net.vpn_up") < order.index("recon.dns")

    def test_wires_artifact_dependencies(self, registry: ToolRegistry) -> None:
        plan = run(
            RuleBasedPlanner(max_risk=RiskLevel.ACTIVE).plan(
                "assess", target="example.com", registry=registry
            )
        )
        correlate = next(s for s in plan.steps if s.tool_name == "analysis.correlate")
        dependencies = {plan.step(d).tool_name for d in correlate.depends_on}
        assert dependencies == {"recon.dns", "osint.whois"}

    def test_injects_target_into_scope_gated_steps(self, registry: ToolRegistry) -> None:
        plan = run(
            RuleBasedPlanner().plan("assess", target="example.com", registry=registry)
        )
        dns = next(s for s in plan.steps if s.tool_name == "recon.dns")
        vpn = next(s for s in plan.steps if s.tool_name == "net.vpn_up")
        assert dns.arguments == {"target": "example.com"}
        assert vpn.arguments == {}

    def test_risk_cap_excludes_tools(self, registry: ToolRegistry) -> None:
        plan = run(
            RuleBasedPlanner(max_risk=RiskLevel.PASSIVE).plan(
                "assess", target="example.com", registry=registry
            )
        )
        assert "recon.dns" not in [s.tool_name for s in plan.steps]

    def test_category_filter(self, registry: ToolRegistry) -> None:
        plan = run(
            RuleBasedPlanner(categories=[ToolCategory.OSINT]).plan(
                "assess", target="example.com", registry=registry
            )
        )
        assert [s.tool_name for s in plan.steps] == ["osint.whois"]

    def test_requires_target_for_scope_gated_tools(self, registry: ToolRegistry) -> None:
        with pytest.raises(PlanningError, match="target is required"):
            run(RuleBasedPlanner().plan("assess", registry=registry))

    def test_raises_when_nothing_matches(self, registry: ToolRegistry) -> None:
        with pytest.raises(PlanningError, match="No registered tool"):
            run(
                RuleBasedPlanner(categories=[ToolCategory.MEMORY]).plan(
                    "assess", target="example.com", registry=registry
                )
            )


class TestSequentialPlanner:
    def test_chains_steps_in_order(self, registry: ToolRegistry) -> None:
        planner = SequentialPlanner(
            [
                PlanStep(tool_name="osint.whois", arguments={"target": "example.com"}),
                PlanStep(tool_name="recon.dns", arguments={"target": "example.com"}),
            ]
        )
        plan = run(planner.plan("seq", target="example.com", registry=registry))
        assert plan.steps[0].depends_on == ()
        assert plan.steps[1].depends_on == (plan.steps[0].id,)


class TestPlanValidation:
    def test_detects_cycles(self, registry: ToolRegistry) -> None:
        plan = Plan(goal="cyclic")
        plan.steps.extend(
            [
                PlanStep(tool_name="recon.dns", id="a", depends_on=("b",)),
                PlanStep(tool_name="osint.whois", id="b", depends_on=("a",)),
            ]
        )
        with pytest.raises(PlanValidationError, match="cycle"):
            plan.validate(registry)

    def test_detects_dangling_dependency(self, registry: ToolRegistry) -> None:
        plan = Plan(
            goal="dangling",
            steps=[PlanStep(tool_name="recon.dns", id="a", depends_on=("ghost",))],
        )
        with pytest.raises(PlanValidationError, match="unknown step"):
            plan.validate(registry)

    def test_detects_self_dependency(self, registry: ToolRegistry) -> None:
        plan = Plan(
            goal="self",
            steps=[PlanStep(tool_name="recon.dns", id="a", depends_on=("a",))],
        )
        with pytest.raises(PlanValidationError, match="depends on itself"):
            plan.validate(registry)

    def test_detects_duplicate_ids(self, registry: ToolRegistry) -> None:
        plan = Plan(goal="dup")
        plan.steps.extend(
            [
                PlanStep(tool_name="recon.dns", id="a"),
                PlanStep(tool_name="osint.whois", id="a"),
            ]
        )
        with pytest.raises(PlanValidationError, match="Duplicate step ids"):
            plan.validate(registry)

    def test_detects_unregistered_tool(self, registry: ToolRegistry) -> None:
        plan = Plan(goal="ghost", steps=[PlanStep(tool_name="not.registered", id="a")])
        with pytest.raises(PlanValidationError, match="unregistered tool"):
            plan.validate(registry)

    def test_add_rejects_duplicate_id(self) -> None:
        plan = Plan(goal="g", steps=[PlanStep(tool_name="t", id="a")])
        with pytest.raises(PlanValidationError, match="Duplicate step id"):
            plan.add(PlanStep(tool_name="t", id="a"))


class TestPlanTraversal:
    @staticmethod
    def _diamond() -> Plan:
        return Plan(
            goal="diamond",
            steps=[
                PlanStep(tool_name="net.vpn_up", id="root"),
                PlanStep(tool_name="osint.whois", id="left", depends_on=("root",)),
                PlanStep(tool_name="recon.dns", id="right", depends_on=("root",)),
                PlanStep(
                    tool_name="analysis.correlate", id="join", depends_on=("left", "right")
                ),
            ],
        )

    def test_ready_steps_follow_dependencies(self) -> None:
        plan = self._diamond()
        assert [s.id for s in plan.ready_steps()] == ["root"]

        plan.step("root").status = TaskStatus.SUCCEEDED
        assert {s.id for s in plan.ready_steps()} == {"left", "right"}

        plan.step("left").status = TaskStatus.SUCCEEDED
        assert [s.id for s in plan.ready_steps()] == ["right"]

        plan.step("right").status = TaskStatus.SUCCEEDED
        assert [s.id for s in plan.ready_steps()] == ["join"]

    def test_blocked_steps_detected_when_dependency_fails(self) -> None:
        plan = self._diamond()
        plan.step("root").status = TaskStatus.FAILED
        blocked = {s.id for s in plan.blocked_steps()}
        assert blocked == {"left", "right"}

    def test_is_complete(self) -> None:
        plan = self._diamond()
        assert not plan.is_complete
        for step in plan.steps:
            step.status = TaskStatus.SUCCEEDED
        assert plan.is_complete

    def test_counts_and_serialization(self) -> None:
        plan = self._diamond()
        plan.step("root").status = TaskStatus.SUCCEEDED
        assert plan.counts() == {"succeeded": 1, "pending": 3}
        payload = plan.to_dict()
        assert len(payload["steps"]) == 4
        assert payload["goal"] == "diamond"

    def test_step_lookup_raises_for_unknown(self) -> None:
        with pytest.raises(KeyError):
            self._diamond().step("nope")
