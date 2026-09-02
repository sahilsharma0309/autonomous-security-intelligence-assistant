"""The tool dispatch engine.

Everything the agent does against the outside world funnels through
:class:`ToolDispatcher`. Centralizing execution here means the safety and
reliability policies are applied uniformly and cannot be forgotten by an
individual tool author:

1. **Resolve** the tool by name.
2. **Validate** arguments against the declared spec.
3. **Authorize** the target against the engagement scope (hard gate).
4. **Rate limit** per tool, so a scan cannot hammer a third party.
5. **Bound concurrency** across the whole process.
6. **Enforce a timeout** and retry only genuinely transient failures.
7. **Record** the outcome in an immutable audit trail.

Exceptions never escape :meth:`ToolDispatcher.dispatch`; failures come back as
:class:`ToolResult` objects carrying a status. That lets a plan continue past a
failed optional step while still surfacing exactly what went wrong.
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from collections import deque
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from security_assistant.core.authorization import AuthorizationScope
from security_assistant.core.exceptions import (
    AuthorizationError,
    RateLimitExceededError,
    ToolExecutionError,
    ToolNotFoundError,
    ToolTimeoutError,
    ToolValidationError,
)
from security_assistant.core.registry import ToolRegistry
from security_assistant.core.tool import ToolSpec
from security_assistant.core.types import (
    InvocationStatus,
    ToolContext,
    ToolInvocation,
    ToolResult,
    utcnow,
)

logger = logging.getLogger(__name__)

__all__ = [
    "DispatcherConfig",
    "EventSink",
    "RateLimiter",
    "ToolDispatcher",
]

EventSink = Callable[[str, dict[str, Any]], Any]
"""Observer callback: ``(event_name, payload)``. May be sync or async."""


@dataclass(slots=True)
class DispatcherConfig:
    """Tunable execution policy for the dispatcher."""

    max_concurrency: int = 16
    """Ceiling on simultaneously executing tools across the process."""

    default_timeout_seconds: float = 60.0
    """Applied when a tool's spec does not declare its own timeout."""

    default_max_attempts: int = 1
    """Attempt budget for tools that do not declare their own."""

    retry_base_delay: float = 0.5
    retry_max_delay: float = 15.0
    retry_jitter: float = 0.25
    """Fraction of the delay randomized, to avoid synchronized retries."""

    audit_trail_size: int = 1000
    """How many recent results to retain in memory for inspection."""

    fail_closed_without_scope: bool = True
    """Refuse scope-gated tools when no scope is configured.

    Leave this on. Turning it off removes the safety gate entirely.
    """

    def __post_init__(self) -> None:
        if self.max_concurrency < 1:
            raise ValueError("max_concurrency must be >= 1")
        if self.default_timeout_seconds <= 0:
            raise ValueError("default_timeout_seconds must be positive")
        if self.default_max_attempts < 1:
            raise ValueError("default_max_attempts must be >= 1")


class RateLimiter:
    """Async token bucket, keyed by tool name.

    Buckets refill continuously at ``limit/60`` tokens per second and hold at
    most one minute's worth, which permits a modest burst while keeping the
    long-run average within the configured ceiling.
    """

    __slots__ = ("_buckets", "_lock")

    def __init__(self) -> None:
        # name -> (tokens, capacity, refill_per_second, last_updated)
        self._buckets: dict[str, tuple[float, float, float, float]] = {}
        self._lock = asyncio.Lock()

    async def acquire(
        self, key: str, limit_per_minute: float, *, wait: bool = True, timeout: float = 30.0
    ) -> None:
        """Consume one token for ``key``.

        When ``wait`` is true the caller sleeps until a token is available (up
        to ``timeout``); otherwise :class:`RateLimitExceededError` is raised
        immediately.
        """
        if limit_per_minute <= 0:
            raise ValueError("limit_per_minute must be positive")

        deadline = time.monotonic() + timeout
        capacity = max(1.0, limit_per_minute)
        refill_rate = limit_per_minute / 60.0

        while True:
            async with self._lock:
                now = time.monotonic()
                tokens, _cap, _rate, last = self._buckets.get(
                    key, (capacity, capacity, refill_rate, now)
                )
                tokens = min(capacity, tokens + (now - last) * refill_rate)

                if tokens >= 1.0:
                    self._buckets[key] = (tokens - 1.0, capacity, refill_rate, now)
                    return

                deficit = 1.0 - tokens
                sleep_for = deficit / refill_rate if refill_rate > 0 else timeout
                self._buckets[key] = (tokens, capacity, refill_rate, now)

            if not wait:
                raise RateLimitExceededError(key, limit_per_minute)

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RateLimitExceededError(key, limit_per_minute)

            await asyncio.sleep(min(sleep_for, remaining))

    def reset(self, key: str | None = None) -> None:
        """Clear one bucket, or all of them."""
        if key is None:
            self._buckets.clear()
        else:
            self._buckets.pop(key, None)


class ToolDispatcher:
    """Executes tool invocations under a uniform safety and reliability policy."""

    def __init__(
        self,
        registry: ToolRegistry,
        scope: AuthorizationScope | None = None,
        config: DispatcherConfig | None = None,
        *,
        event_sink: EventSink | None = None,
    ) -> None:
        self._registry = registry
        self._scope = scope
        self._config = config or DispatcherConfig()
        self._event_sink = event_sink
        self._limiter = RateLimiter()
        self._semaphore = asyncio.Semaphore(self._config.max_concurrency)
        self._audit: deque[ToolResult] = deque(maxlen=self._config.audit_trail_size)
        self._counters: dict[str, int] = {}

    # -- properties -------------------------------------------------------- #
    @property
    def registry(self) -> ToolRegistry:
        return self._registry

    @property
    def config(self) -> DispatcherConfig:
        return self._config

    @property
    def scope(self) -> AuthorizationScope | None:
        return self._scope

    @scope.setter
    def scope(self, value: AuthorizationScope | None) -> None:
        logger.info(
            "Dispatcher scope updated: %s",
            value.describe() if value is not None else "<none>",
        )
        self._scope = value

    @property
    def audit_trail(self) -> list[ToolResult]:
        """Most recent results, oldest first."""
        return list(self._audit)

    @property
    def counters(self) -> dict[str, int]:
        """Invocation counts by status, for metrics/health reporting."""
        return dict(self._counters)

    # -- dispatch ---------------------------------------------------------- #
    async def dispatch(
        self, invocation: ToolInvocation, ctx: ToolContext | None = None
    ) -> ToolResult:
        """Execute one invocation and return its result.

        Never raises for tool-level failures; inspect
        :attr:`ToolResult.status`.
        """
        context = ctx or ToolContext(scope=self._scope)
        started_at = utcnow()
        started_monotonic = time.perf_counter()

        def finish(
            status: InvocationStatus,
            *,
            value: Any = None,
            error: str | None = None,
            error_type: str | None = None,
            attempts: int = 1,
            metadata: Mapping[str, Any] | None = None,
        ) -> ToolResult:
            result = ToolResult(
                invocation_id=invocation.invocation_id,
                tool_name=invocation.tool_name,
                status=status,
                value=value,
                error=error,
                error_type=error_type,
                started_at=started_at,
                finished_at=utcnow(),
                duration_ms=(time.perf_counter() - started_monotonic) * 1000.0,
                attempts=attempts,
                metadata=dict(metadata or {}),
                step_id=invocation.step_id,
            )
            self._record(result)
            return result

        # 1. Resolve -------------------------------------------------------- #
        try:
            tool = self._registry.get(invocation.tool_name)
        except ToolNotFoundError as exc:
            return finish(
                InvocationStatus.NOT_FOUND, error=str(exc), error_type="ToolNotFoundError"
            )

        spec: ToolSpec = tool.spec

        # 2. Validate ------------------------------------------------------- #
        try:
            arguments = spec.validate_arguments(invocation.arguments)
        except ToolValidationError as exc:
            return finish(
                InvocationStatus.INVALID, error=str(exc), error_type="ToolValidationError"
            )

        # 3. Authorize ------------------------------------------------------ #
        auth_metadata: dict[str, Any] = {}
        if spec.requires_scope:
            target = arguments.get(spec.target_argument)
            if target is None:
                return finish(
                    InvocationStatus.INVALID,
                    error=(
                        f"Tool {spec.name!r} is scope-gated but no "
                        f"{spec.target_argument!r} argument was supplied"
                    ),
                    error_type="ToolValidationError",
                )

            scope = context.scope if context.scope is not None else self._scope
            if scope is None:
                if self._config.fail_closed_without_scope:
                    return finish(
                        InvocationStatus.DENIED,
                        error=(
                            f"Refusing to run scope-gated tool {spec.name!r}: no "
                            "authorization scope is configured"
                        ),
                        error_type="AuthorizationError",
                    )
            else:
                try:
                    decision = scope.check(str(target), spec.risk)
                except AuthorizationError as exc:
                    await self._emit(
                        "tool.denied",
                        {
                            "tool": spec.name,
                            "target": str(target),
                            "risk": str(spec.risk),
                            "reason": str(exc),
                            "correlation_id": context.correlation_id,
                        },
                    )
                    return finish(
                        InvocationStatus.DENIED, error=str(exc), error_type="AuthorizationError"
                    )
                auth_metadata = {
                    "authorized_target": decision.target,
                    "matched_rule": (
                        decision.matched_rule.pattern if decision.matched_rule else None
                    ),
                }

        # Honour dry-run without ever touching the target.
        if context.dry_run:
            return finish(
                InvocationStatus.SUCCESS,
                value={
                    "dry_run": True,
                    "tool": spec.name,
                    "arguments": dict(arguments),
                },
                metadata={**auth_metadata, "dry_run": True},
            )

        # 4. Rate limit ----------------------------------------------------- #
        if spec.rate_limit_per_minute:
            try:
                await self._limiter.acquire(spec.name, spec.rate_limit_per_minute)
            except RateLimitExceededError as exc:
                return finish(
                    InvocationStatus.RATE_LIMITED,
                    error=str(exc),
                    error_type="RateLimitExceededError",
                    metadata=auth_metadata,
                )

        # 5-6. Execute under concurrency + timeout, with bounded retries ----- #
        timeout = spec.timeout_seconds or self._config.default_timeout_seconds
        max_attempts = max(spec.max_attempts, 1)
        if max_attempts == 1 and self._config.default_max_attempts > 1:
            max_attempts = self._config.default_max_attempts

        last_error: BaseException | None = None
        attempt = 0

        await self._emit(
            "tool.start",
            {
                "tool": spec.name,
                "invocation_id": invocation.invocation_id,
                "correlation_id": context.correlation_id,
            },
        )

        while attempt < max_attempts:
            attempt += 1
            try:
                async with self._semaphore:
                    value = await asyncio.wait_for(
                        tool.invoke(context, arguments), timeout=timeout
                    )
            except TimeoutError:
                last_error = ToolTimeoutError(spec.name, timeout)
                logger.warning(
                    "Tool timeout name=%s attempt=%d/%d timeout=%.1fs correlation_id=%s",
                    spec.name,
                    attempt,
                    max_attempts,
                    timeout,
                    context.correlation_id,
                )
            except asyncio.CancelledError:
                # Cooperative cancellation must propagate, not be swallowed.
                result = finish(
                    InvocationStatus.CANCELLED,
                    error="Invocation cancelled",
                    error_type="CancelledError",
                    attempts=attempt,
                    metadata=auth_metadata,
                )
                await self._emit(
                    "tool.cancelled",
                    {"tool": spec.name, "invocation_id": invocation.invocation_id},
                )
                raise
            except AuthorizationError as exc:
                # A tool performing its own secondary scope check (e.g. after
                # resolving a redirect) is a deny, never a retry.
                return finish(
                    InvocationStatus.DENIED,
                    error=str(exc),
                    error_type="AuthorizationError",
                    attempts=attempt,
                    metadata=auth_metadata,
                )
            except Exception as exc:
                last_error = exc
                logger.warning(
                    "Tool error name=%s attempt=%d/%d error=%s correlation_id=%s",
                    spec.name,
                    attempt,
                    max_attempts,
                    exc,
                    context.correlation_id,
                    exc_info=attempt >= max_attempts,
                )
            else:
                result = finish(
                    InvocationStatus.SUCCESS,
                    value=value,
                    attempts=attempt,
                    metadata=auth_metadata,
                )
                await self._emit(
                    "tool.success",
                    {
                        "tool": spec.name,
                        "invocation_id": invocation.invocation_id,
                        "duration_ms": result.duration_ms,
                        "attempts": attempt,
                    },
                )
                return result

            if attempt < max_attempts:
                await asyncio.sleep(self._backoff_delay(attempt))

        # Exhausted the attempt budget.
        timed_out = isinstance(last_error, ToolTimeoutError)
        wrapped: BaseException = (
            last_error
            if timed_out and last_error is not None
            else ToolExecutionError(spec.name, last_error or RuntimeError("unknown failure"))
        )
        result = finish(
            InvocationStatus.TIMEOUT if timed_out else InvocationStatus.ERROR,
            error=str(wrapped),
            error_type=type(last_error).__name__ if last_error else "RuntimeError",
            attempts=attempt,
            metadata=auth_metadata,
        )
        await self._emit(
            "tool.failure",
            {
                "tool": spec.name,
                "invocation_id": invocation.invocation_id,
                "status": result.status.value,
                "error": result.error,
                "attempts": attempt,
            },
        )
        return result

    async def dispatch_many(
        self,
        invocations: Iterable[ToolInvocation],
        ctx: ToolContext | None = None,
        *,
        max_concurrency: int | None = None,
    ) -> list[ToolResult]:
        """Dispatch several invocations concurrently, preserving input order.

        ``max_concurrency`` further narrows the dispatcher-wide ceiling for
        this batch only.
        """
        batch = list(invocations)
        if not batch:
            return []

        context = ctx or ToolContext(scope=self._scope)
        limit = max_concurrency or len(batch)
        gate = asyncio.Semaphore(max(1, limit))

        async def run_one(invocation: ToolInvocation) -> ToolResult:
            async with gate:
                return await self.dispatch(invocation, context)

        return list(await asyncio.gather(*(run_one(i) for i in batch)))

    async def call(
        self, tool_name: str, ctx: ToolContext | None = None, /, **arguments: Any
    ) -> ToolResult:
        """Ergonomic single-call helper.

        >>> await dispatcher.call("dns.resolve", target="example.com")  # doctest: +SKIP
        """
        return await self.dispatch(
            ToolInvocation(tool_name=tool_name, arguments=arguments), ctx
        )

    # -- internals --------------------------------------------------------- #
    def _backoff_delay(self, attempt: int) -> float:
        """Exponential backoff with jitter, capped at ``retry_max_delay``."""
        base = min(
            self._config.retry_base_delay * (2.0 ** (attempt - 1)),
            self._config.retry_max_delay,
        )
        if self._config.retry_jitter <= 0:
            return base
        spread = base * self._config.retry_jitter
        return max(0.0, base + random.uniform(-spread, spread))

    def _record(self, result: ToolResult) -> None:
        self._audit.append(result)
        key = result.status.value
        self._counters[key] = self._counters.get(key, 0) + 1
        logger.info(
            "tool=%s status=%s duration_ms=%.1f attempts=%d invocation_id=%s",
            result.tool_name,
            result.status.value,
            result.duration_ms,
            result.attempts,
            result.invocation_id,
        )

    async def _emit(self, event: str, payload: dict[str, Any]) -> None:
        """Notify the event sink, never letting observers break execution."""
        if self._event_sink is None:
            return
        try:
            outcome = self._event_sink(event, payload)
            if asyncio.iscoroutine(outcome):
                await outcome
        except Exception:
            logger.exception("Event sink raised while handling %s", event)
