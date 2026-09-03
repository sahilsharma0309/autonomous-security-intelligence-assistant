"""Tests for the kill-switch and its lockout guard.

This is the code that can take a remote machine off the network permanently,
so most of these tests assert a *refusal*. A guard that can be talked into
approving an unsafe plan is worse than no guard, because it produces
confidence.
"""

from __future__ import annotations

import asyncio

import pytest

from security_assistant.network.commands import CommandResult, RecordingRunner
from security_assistant.network.killswitch import (
    FirewallFamily,
    KillSwitch,
    KillSwitchError,
    LockoutGuard,
    LockoutRiskError,
    build_iptables_plan,
    plan_for_status,
)
from tests.unit.conftest import run


def good_plan():  # type: ignore[no-untyped-def]
    return build_iptables_plan(
        "wg0", endpoints=["203.0.113.5:51820"], admin_cidrs=["198.51.100.0/24"]
    )


class TestPlanConstruction:
    def test_includes_every_survival_rule(self) -> None:
        purposes = good_plan().purposes()
        assert {
            "allow-loopback",
            "allow-established",
            "allow-vpn-interface",
            "allow-vpn-endpoint",
            "default-drop",
        } <= purposes

    def test_default_drop_comes_last(self) -> None:
        """There must be no window where the policy is DROP but the
        exemptions are not yet installed."""
        plan = good_plan()
        assert plan.rules[-1].purpose == "default-drop"

    def test_plan_carries_a_rollback(self) -> None:
        plan = good_plan()
        assert plan.rollback
        assert any("ACCEPT" in r.text for r in plan.rollback)

    def test_endpoint_must_be_an_address_not_a_hostname(self) -> None:
        # iptables would resolve a hostname once at insert time, baking in a
        # single address that breaks silently when the endpoint rotates.
        with pytest.raises(KillSwitchError, match="must be an IP address"):
            build_iptables_plan("wg0", endpoints=["vpn.example.com:51820"])

    def test_ipv6_endpoint_is_accepted(self) -> None:
        plan = build_iptables_plan("wg0", endpoints=["[2001:db8::1]:51820"])
        assert "2001:db8::1" in plan.allowed_endpoints

    def test_invalid_cidr_is_rejected(self) -> None:
        with pytest.raises(KillSwitchError, match="Invalid admin CIDR"):
            build_iptables_plan("wg0", admin_cidrs=["not-a-network"])

    def test_invalid_interface_is_rejected(self) -> None:
        with pytest.raises(KillSwitchError, match="Invalid interface"):
            build_iptables_plan("wg0; rm -rf /")

    def test_describe_is_reviewable(self) -> None:
        text = good_plan().describe()
        assert "Kill-switch plan" in text
        assert "allow-loopback" in text
        assert "203.0.113.5" in text

    def test_serializes(self) -> None:
        payload = good_plan().to_dict()
        assert payload["family"] == FirewallFamily.IPTABLES.value
        assert payload["interface"] == "wg0"


class TestLockoutGuard:
    def test_accepts_a_complete_plan(self) -> None:
        LockoutGuard().check(good_plan())

    def test_refuses_a_plan_without_loopback(self) -> None:
        plan = good_plan()
        plan.rules = [r for r in plan.rules if r.purpose != "allow-loopback"]
        with pytest.raises(LockoutRiskError, match="allow-loopback"):
            LockoutGuard().check(plan)

    def test_refuses_a_plan_without_established(self) -> None:
        plan = good_plan()
        plan.rules = [r for r in plan.rules if r.purpose != "allow-established"]
        with pytest.raises(LockoutRiskError, match="allow-established"):
            LockoutGuard().check(plan)

    def test_refuses_a_plan_with_no_endpoint_exemption(self) -> None:
        """Without it the tunnel's own handshake is blocked and the machine
        can never come back."""
        plan = build_iptables_plan("wg0")
        with pytest.raises(LockoutRiskError, match="never reconnect"):
            LockoutGuard().check(plan)

    def test_endpoint_requirement_can_be_waived_explicitly(self) -> None:
        LockoutGuard(require_endpoint=False).check(build_iptables_plan("wg0"))

    def test_refuses_when_a_required_admin_network_is_not_preserved(self) -> None:
        guard = LockoutGuard(required_admin_cidrs=("10.0.0.0/8",))
        with pytest.raises(LockoutRiskError, match="administrative network"):
            guard.check(good_plan())

    def test_accepts_when_admin_network_is_covered(self) -> None:
        plan = build_iptables_plan(
            "wg0", endpoints=["203.0.113.5:51820"], admin_cidrs=["10.0.0.0/8"]
        )
        LockoutGuard(required_admin_cidrs=("10.1.2.0/24",)).check(plan)

    def test_refuses_a_plan_that_blocks_nothing(self) -> None:
        plan = good_plan()
        plan.rules = [r for r in plan.rules if r.purpose != "default-drop"]
        with pytest.raises(LockoutRiskError, match="never sets a default DROP"):
            LockoutGuard().check(plan)

    def test_refuses_a_plan_with_no_rollback(self) -> None:
        plan = good_plan()
        plan.rollback = []
        with pytest.raises(LockoutRiskError, match="no rollback"):
            LockoutGuard().check(plan)


class TestApplication:
    def test_applies_every_rule_in_order(self) -> None:
        runner = RecordingRunner()
        switch = KillSwitch(runner)
        plan = good_plan()

        state = run(switch.apply(plan, confirm_within=None))

        assert state.engaged is True
        assert len(runner.calls) == len(plan.rules)
        assert runner.calls[-1][-1] == "DROP"

    def test_guard_runs_before_anything_is_applied(self) -> None:
        runner = RecordingRunner()
        unsafe = build_iptables_plan("wg0")  # no endpoint exemption

        with pytest.raises(LockoutRiskError):
            run(KillSwitch(runner).apply(unsafe))

        assert runner.calls == []

    def test_partial_failure_rolls_back_immediately(self) -> None:
        """A half-applied ruleset is the worst state possible: exemptions
        without a policy, or a policy without exemptions."""
        runner = RecordingRunner(
            results={
                "iptables -P": CommandResult(
                    argv=(), returncode=1, stderr="permission denied", executed=True
                )
            }
        )
        with pytest.raises(KillSwitchError, match="rolled back"):
            run(KillSwitch(runner).apply(good_plan(), confirm_within=None))

        assert runner.ran("iptables -P OUTPUT ACCEPT")
        assert runner.ran("iptables -F OUTPUT")

    def test_cannot_apply_twice(self) -> None:
        switch = KillSwitch(RecordingRunner())
        run(switch.apply(good_plan(), confirm_within=None))
        with pytest.raises(KillSwitchError, match="already engaged"):
            run(switch.apply(good_plan(), confirm_within=None))

    def test_release_runs_the_rollback(self) -> None:
        runner = RecordingRunner()
        switch = KillSwitch(runner)
        run(switch.apply(good_plan(), confirm_within=None))
        run(switch.release())

        assert switch.engaged is False
        assert runner.ran("iptables -P OUTPUT ACCEPT")


class TestDeadMansSwitch:
    def test_unconfirmed_rules_roll_back_automatically(self) -> None:
        """If the new policy cut your connection you cannot confirm, so the
        machine must restore itself."""

        async def scenario() -> RecordingRunner:
            runner = RecordingRunner()
            switch = KillSwitch(runner)
            await switch.apply(good_plan(), confirm_within=0.05)
            await asyncio.sleep(0.2)
            return runner

        runner = run(scenario())
        assert runner.ran("iptables -P OUTPUT ACCEPT")

    def test_confirming_cancels_the_rollback(self) -> None:
        async def scenario() -> RecordingRunner:
            runner = RecordingRunner()
            switch = KillSwitch(runner)
            await switch.apply(good_plan(), confirm_within=0.05)
            switch.confirm()
            await asyncio.sleep(0.2)
            return runner

        runner = run(scenario())
        assert not runner.ran("iptables -P OUTPUT ACCEPT")

    def test_confirm_requires_an_engaged_switch(self) -> None:
        with pytest.raises(KillSwitchError, match="not engaged"):
            KillSwitch(RecordingRunner()).confirm()

    def test_state_serializes(self) -> None:
        switch = KillSwitch(RecordingRunner())
        state = run(switch.apply(good_plan(), confirm_within=None))
        payload = state.to_dict()
        assert payload["engaged"] is True
        assert payload["interface"] == "wg0"


class TestConvenience:
    def test_plan_for_status(self) -> None:
        plan = plan_for_status("wg0", "203.0.113.5:51820", admin_cidrs=["10.0.0.0/8"])
        LockoutGuard().check(plan)
        assert plan.allowed_endpoints == ["203.0.113.5"]
