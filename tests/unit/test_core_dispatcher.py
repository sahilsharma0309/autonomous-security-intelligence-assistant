"""Tests for the tool dispatch engine.

The dispatcher is where the safety policy is actually enforced, so the
authorization cases here matter more than the happy path.
"""

from __future__ import annotations

import asyncio

import pytest

from security_assistant.core import (
    AuthorizationScope,
    DispatcherConfig,
    InvocationStatus,
    RiskLevel,
    ToolCategory,
    ToolContext,
    ToolDispatcher,
    ToolInvocation,
    ToolRegistry,
    tool,
)
from security_assistant.core.dispatcher import RateLimiter
from security_assistant.core.exceptions import RateLimitExceededError
from tests.unit.conftest import intrusive_scan, run


@tool(
    name="flaky.tool",
    description="Fails twice, then succeeds.",
    category=ToolCategory.UTILITY,
    risk=RiskLevel.PASSIVE,
    requires_scope=False,
    max_attempts=3,
)
async def flaky(ctx: ToolContext) -> str:
    ctx.state["calls"] = ctx.state.get("calls", 0) + 1
    if ctx.state["calls"] < 3:
        raise RuntimeError("transient failure")
    return "recovered"


@tool(
    name="slow.tool",
    description="Sleeps well past its timeout.",
    category=ToolCategory.UTILITY,
    risk=RiskLevel.PASSIVE,
    requires_scope=False,
    timeout_seconds=0.05,
)
async def slow(ctx: ToolContext) -> str:  # pragma: no cover - always cancelled
    await asyncio.sleep(30)
    return "never returned"


@tool(
    name="always.fails",
    description="Always raises.",
    category=ToolCategory.UTILITY,
    risk=RiskLevel.PASSIVE,
    requires_scope=False,
)
async def always_fails(ctx: ToolContext) -> str:
    raise ValueError("deliberate failure")


@pytest.fixture
def dispatcher(registry: ToolRegistry, scope: AuthorizationScope) -> ToolDispatcher:
    registry.register_all([flaky, slow, always_fails, intrusive_scan])
    return ToolDispatcher(registry, scope, DispatcherConfig(max_concurrency=4))


class TestAuthorizationGate:
    def test_in_scope_target_succeeds(self, dispatcher: ToolDispatcher) -> None:
        result = run(dispatcher.call("recon.dns", None, target="example.com"))
        assert result.ok
        assert result.metadata["authorized_target"] == "example.com"

    def test_out_of_scope_target_denied(self, dispatcher: ToolDispatcher) -> None:
        result = run(dispatcher.call("recon.dns", None, target="unauthorized.net"))
        assert result.status is InvocationStatus.DENIED
        assert result.denied
        assert "not authorized" in (result.error or "")

    def test_risk_above_cap_denied(self, dispatcher: ToolDispatcher) -> None:
        # The scope authorizes ACTIVE; this tool is INTRUSIVE.
        result = run(dispatcher.call("scan.intrusive", None, target="example.com"))
        assert result.status is InvocationStatus.DENIED

    def test_fails_closed_without_a_scope(self, registry: ToolRegistry) -> None:
        unscoped = ToolDispatcher(registry, None, DispatcherConfig())
        result = run(
            unscoped.dispatch(
                ToolInvocation("recon.dns", {"target": "example.com"}),
                ToolContext(scope=None),
            )
        )
        assert result.status is InvocationStatus.DENIED
        assert "no authorization scope is configured" in (result.error or "")

    def test_scope_gated_tool_without_target_is_invalid(self, dispatcher: ToolDispatcher) -> None:
        result = run(dispatcher.call("recon.dns", None))
        assert result.status is InvocationStatus.INVALID

    def test_dry_run_never_executes(self, dispatcher: ToolDispatcher) -> None:
        ctx = ToolContext(scope=dispatcher.scope, dry_run=True)
        result = run(
            dispatcher.dispatch(ToolInvocation("recon.dns", {"target": "example.com"}), ctx)
        )
        assert result.ok
        assert result.value["dry_run"] is True
        assert result.value["tool"] == "recon.dns"


class TestExecutionPolicy:
    def test_unknown_tool_reported(self, dispatcher: ToolDispatcher) -> None:
        result = run(dispatcher.call("does.not.exist", None, target="example.com"))
        assert result.status is InvocationStatus.NOT_FOUND

    def test_retries_transient_failure(self, dispatcher: ToolDispatcher) -> None:
        ctx = ToolContext(scope=dispatcher.scope)
        result = run(dispatcher.dispatch(ToolInvocation("flaky.tool"), ctx))
        assert result.ok
        assert result.attempts == 3

    def test_timeout_reported(self, dispatcher: ToolDispatcher) -> None:
        result = run(dispatcher.call("slow.tool", None))
        assert result.status is InvocationStatus.TIMEOUT
        assert "timed out" in (result.error or "")

    def test_exception_becomes_failed_result(self, dispatcher: ToolDispatcher) -> None:
        result = run(dispatcher.call("always.fails", None))
        assert result.status is InvocationStatus.ERROR
        assert result.error_type == "ValueError"
        assert "deliberate failure" in (result.error or "")

    def test_dispatch_many_preserves_order(self, dispatcher: ToolDispatcher) -> None:
        ctx = ToolContext(scope=dispatcher.scope)
        results = run(
            dispatcher.dispatch_many(
                [
                    ToolInvocation("osint.whois", {"target": "example.com"}),
                    ToolInvocation("recon.dns", {"target": "example.com"}),
                ],
                ctx,
            )
        )
        assert [r.tool_name for r in results] == ["osint.whois", "recon.dns"]
        assert all(r.ok for r in results)

    def test_dispatch_many_handles_empty(self, dispatcher: ToolDispatcher) -> None:
        assert run(dispatcher.dispatch_many([])) == []


class TestObservability:
    def test_audit_trail_and_counters(self, dispatcher: ToolDispatcher) -> None:
        run(dispatcher.call("recon.dns", None, target="example.com"))
        run(dispatcher.call("recon.dns", None, target="unauthorized.net"))
        assert len(dispatcher.audit_trail) == 2
        assert dispatcher.counters["success"] == 1
        assert dispatcher.counters["denied"] == 1

    def test_event_sink_receives_events(
        self, registry: ToolRegistry, scope: AuthorizationScope
    ) -> None:
        seen: list[str] = []
        sink = ToolDispatcher(
            registry, scope, DispatcherConfig(), event_sink=lambda e, p: seen.append(e)
        )
        run(sink.call("recon.dns", None, target="example.com"))
        assert "tool.start" in seen
        assert "tool.success" in seen

    def test_broken_event_sink_does_not_break_dispatch(
        self, registry: ToolRegistry, scope: AuthorizationScope
    ) -> None:
        def exploding(event: str, payload: dict) -> None:
            raise RuntimeError("sink is broken")

        d = ToolDispatcher(registry, scope, DispatcherConfig(), event_sink=exploding)
        result = run(d.call("recon.dns", None, target="example.com"))
        assert result.ok

    def test_result_serializes(self, dispatcher: ToolDispatcher) -> None:
        result = run(dispatcher.call("recon.dns", None, target="example.com"))
        payload = result.to_dict()
        assert payload["status"] == "success"
        assert payload["tool_name"] == "recon.dns"


class TestRateLimiter:
    def test_allows_within_budget(self) -> None:
        limiter = RateLimiter()

        async def scenario() -> None:
            for _ in range(5):
                await limiter.acquire("k", 600)

        run(scenario())

    def test_raises_when_not_waiting(self) -> None:
        limiter = RateLimiter()

        async def scenario() -> None:
            # A budget of 1/min yields a single token; the second must fail.
            await limiter.acquire("k", 1)
            await limiter.acquire("k", 1, wait=False)

        with pytest.raises(RateLimitExceededError):
            run(scenario())

    def test_rejects_invalid_limit(self) -> None:
        limiter = RateLimiter()
        with pytest.raises(ValueError):
            run(limiter.acquire("k", 0))


class TestDispatcherConfig:
    @pytest.mark.parametrize(
        "kwargs",
        [
            {"max_concurrency": 0},
            {"default_timeout_seconds": 0},
            {"default_max_attempts": 0},
        ],
    )
    def test_rejects_invalid_values(self, kwargs: dict) -> None:
        with pytest.raises(ValueError):
            DispatcherConfig(**kwargs)
