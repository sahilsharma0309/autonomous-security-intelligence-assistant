"""Shared value types for the agent core.

These are the vocabulary types that flow between the registry, dispatcher,
planner, memory and orchestrator. They are plain :mod:`dataclasses` and
:mod:`enum` members so the core stays importable with zero third-party
dependencies.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping, MutableMapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import IntEnum, StrEnum
from typing import Any

__all__ = [
    "InvocationStatus",
    "RiskLevel",
    "Severity",
    "TaskStatus",
    "ToolCategory",
    "ToolContext",
    "ToolInvocation",
    "ToolResult",
    "new_id",
    "utcnow",
]


def new_id(prefix: str = "") -> str:
    """Return a short, collision-resistant identifier.

    A ``prefix`` makes identifiers self-describing in logs (``inv_1a2b3c4d``),
    which matters a great deal when correlating an audit trail after the fact.
    """
    token = uuid.uuid4().hex[:12]
    return f"{prefix}_{token}" if prefix else token


def utcnow() -> datetime:
    """Return the current time as a timezone-aware UTC datetime."""
    return datetime.now(UTC)


class Severity(IntEnum):
    """Severity of a finding produced by an analysis tool.

    Ordered so findings can be sorted and filtered numerically.
    """

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.name


class RiskLevel(IntEnum):
    """How much a tool interacts with a third-party target.

    This drives the safety gate in the dispatcher. A scope may cap the maximum
    risk level it authorizes, so an engagement limited to passive collection
    can never accidentally execute an active scan.

    ``PASSIVE``
        Never contacts the target. Reads public datasets, caches, or local
        state only (e.g. querying a threat-intel API about a domain).
    ``ACTIVE``
        Contacts the target directly but non-intrusively (e.g. DNS lookup,
        TCP connect scan, HTTP GET of a homepage).
    ``INTRUSIVE``
        May change target state, generate meaningful load, or trip alerting
        (e.g. authenticated scanning, brute-force enumeration). Requires
        explicit opt-in in the scope.
    """

    PASSIVE = 0
    ACTIVE = 1
    INTRUSIVE = 2

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.name

    @classmethod
    def parse(cls, value: RiskLevel | str | int) -> RiskLevel:
        """Coerce a string/int/enum into a :class:`RiskLevel`."""
        if isinstance(value, cls):
            return value
        if isinstance(value, int):
            return cls(value)
        try:
            return cls[str(value).strip().upper()]
        except KeyError as exc:
            raise ValueError(f"Unknown risk level: {value!r}") from exc


class ToolCategory(StrEnum):
    """Functional grouping used by the planner to order work."""

    NETWORK = "network"
    OSINT = "osint"
    RECON = "recon"
    SCANNING = "scanning"
    ANALYSIS = "analysis"
    MEMORY = "memory"
    UTILITY = "utility"


class InvocationStatus(StrEnum):
    """Terminal state of a single tool invocation."""

    SUCCESS = "success"
    ERROR = "error"
    TIMEOUT = "timeout"
    DENIED = "denied"
    RATE_LIMITED = "rate_limited"
    NOT_FOUND = "not_found"
    INVALID = "invalid"
    CANCELLED = "cancelled"


class TaskStatus(StrEnum):
    """Lifecycle state of a plan step or an orchestrator job."""

    PENDING = "pending"
    PLANNING = "planning"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"

    @property
    def is_terminal(self) -> bool:
        """True once the task can no longer transition."""
        return self in _TERMINAL_STATUSES


_TERMINAL_STATUSES = frozenset(
    {
        TaskStatus.SUCCEEDED,
        TaskStatus.FAILED,
        TaskStatus.SKIPPED,
        TaskStatus.CANCELLED,
    }
)


@dataclass(slots=True)
class ToolContext:
    """Per-run context handed to every tool invocation.

    Tools receive this as their first positional argument. It carries the
    authorization scope they must respect, a correlation id for tracing, and a
    free-form ``state`` mapping that lets cooperating tools in one plan share
    intermediate data without going through global state.
    """

    scope: Any
    """The :class:`~security_assistant.core.authorization.AuthorizationScope`.

    Typed as ``Any`` to avoid a circular import; the dispatcher guarantees a
    real scope instance is present.
    """

    correlation_id: str = field(default_factory=lambda: new_id("run"))
    dry_run: bool = False
    """When true, tools must describe what they would do without doing it."""

    config: Mapping[str, Any] = field(default_factory=dict)
    state: MutableMapping[str, Any] = field(default_factory=dict)
    deadline: float | None = None
    """Optional :func:`time.monotonic` deadline for the whole run."""

    def child(self, **overrides: Any) -> ToolContext:
        """Return a shallow copy with selected fields replaced.

        ``state`` is shared by reference so sibling steps in a plan continue to
        see each other's contributions.
        """
        return ToolContext(
            scope=overrides.get("scope", self.scope),
            correlation_id=overrides.get("correlation_id", self.correlation_id),
            dry_run=overrides.get("dry_run", self.dry_run),
            config=overrides.get("config", self.config),
            state=overrides.get("state", self.state),
            deadline=overrides.get("deadline", self.deadline),
        )


@dataclass(slots=True, frozen=True)
class ToolInvocation:
    """A request to execute one tool with one set of arguments."""

    tool_name: str
    arguments: Mapping[str, Any] = field(default_factory=dict)
    invocation_id: str = field(default_factory=lambda: new_id("inv"))
    requested_at: datetime = field(default_factory=utcnow)
    step_id: str | None = None
    """Links the invocation back to the plan step that produced it."""

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<ToolInvocation {self.invocation_id} {self.tool_name}({dict(self.arguments)!r})>"


@dataclass(slots=True)
class ToolResult:
    """Outcome of a single tool invocation.

    A ``ToolResult`` is always produced -- the dispatcher converts exceptions
    into failed results rather than propagating them, so one misbehaving tool
    can never abort an entire plan unless the caller decides it should.
    """

    invocation_id: str
    tool_name: str
    status: InvocationStatus
    value: Any = None
    error: str | None = None
    error_type: str | None = None
    started_at: datetime = field(default_factory=utcnow)
    finished_at: datetime | None = None
    duration_ms: float = 0.0
    attempts: int = 1
    metadata: MutableMapping[str, Any] = field(default_factory=dict)
    step_id: str | None = None

    @property
    def ok(self) -> bool:
        """True when the tool completed successfully."""
        return self.status is InvocationStatus.SUCCESS

    @property
    def denied(self) -> bool:
        """True when the invocation was blocked by the authorization gate."""
        return self.status is InvocationStatus.DENIED

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable view suitable for reports and logs."""
        return {
            "invocation_id": self.invocation_id,
            "tool_name": self.tool_name,
            "status": self.status.value,
            "value": self.value,
            "error": self.error,
            "error_type": self.error_type,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "duration_ms": round(self.duration_ms, 3),
            "attempts": self.attempts,
            "metadata": dict(self.metadata),
            "step_id": self.step_id,
        }

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        detail = self.error if self.error else type(self.value).__name__
        return (
            f"<ToolResult {self.tool_name} {self.status.value} "
            f"{self.duration_ms:.1f}ms {detail}>"
        )
