"""Exception hierarchy for the agent core.

All exceptions raised deliberately by the core subsystems derive from
:class:`SecurityAssistantError` so callers can catch the whole family with a
single ``except`` while still being able to discriminate on specific failure
modes. Nothing in this module imports third-party packages; the core is
intentionally dependency-free so it can be imported in any environment.
"""

from __future__ import annotations

__all__ = [
    "AuthorizationError",
    "ConfigurationError",
    "MemoryBackendError",
    "OrchestratorError",
    "OrchestratorNotRunningError",
    "PlanValidationError",
    "PlanningError",
    "RateLimitExceededError",
    "SecurityAssistantError",
    "ToolAlreadyRegisteredError",
    "ToolError",
    "ToolExecutionError",
    "ToolNotFoundError",
    "ToolTimeoutError",
    "ToolValidationError",
]


class SecurityAssistantError(Exception):
    """Base class for every error raised by the assistant."""


class ConfigurationError(SecurityAssistantError):
    """Raised when configuration is missing, malformed, or contradictory."""


# --------------------------------------------------------------------------- #
# Tooling
# --------------------------------------------------------------------------- #
class ToolError(SecurityAssistantError):
    """Base class for problems related to tools and their dispatch."""


class ToolNotFoundError(ToolError):
    """Raised when an invocation references a tool that is not registered."""

    def __init__(self, name: str) -> None:
        self.tool_name = name
        super().__init__(f"No tool registered under the name {name!r}")


class ToolAlreadyRegisteredError(ToolError):
    """Raised when registering a tool whose name is already taken."""

    def __init__(self, name: str) -> None:
        self.tool_name = name
        super().__init__(f"A tool named {name!r} is already registered")


class ToolValidationError(ToolError):
    """Raised when the arguments supplied to a tool fail validation."""


class ToolExecutionError(ToolError):
    """Wraps an unexpected exception raised inside a tool's body.

    The original exception is preserved on :attr:`__cause__` and mirrored on
    :attr:`original` for convenience.
    """

    def __init__(self, tool_name: str, original: BaseException) -> None:
        self.tool_name = tool_name
        self.original = original
        super().__init__(f"Tool {tool_name!r} raised {type(original).__name__}: {original}")


class ToolTimeoutError(ToolError):
    """Raised when a tool exceeds its execution deadline."""

    def __init__(self, tool_name: str, timeout: float) -> None:
        self.tool_name = tool_name
        self.timeout = timeout
        super().__init__(f"Tool {tool_name!r} timed out after {timeout:.2f}s")


# --------------------------------------------------------------------------- #
# Authorization / safety
# --------------------------------------------------------------------------- #
class AuthorizationError(SecurityAssistantError):
    """Raised when an action is attempted against an out-of-scope target.

    This is a hard safety boundary: the dispatcher refuses to execute any
    scope-bound tool unless the target has been explicitly authorized.
    """


class RateLimitExceededError(SecurityAssistantError):
    """Raised when a tool's configured rate limit would be exceeded."""

    def __init__(self, tool_name: str, limit_per_minute: float) -> None:
        self.tool_name = tool_name
        self.limit_per_minute = limit_per_minute
        super().__init__(
            f"Rate limit for tool {tool_name!r} exceeded "
            f"({limit_per_minute:g} calls/min)"
        )


# --------------------------------------------------------------------------- #
# Planning
# --------------------------------------------------------------------------- #
class PlanningError(SecurityAssistantError):
    """Raised when a plan cannot be produced for a goal."""


class PlanValidationError(PlanningError):
    """Raised when a plan is structurally invalid (cycles, dangling deps)."""


# --------------------------------------------------------------------------- #
# Memory
# --------------------------------------------------------------------------- #
class MemoryBackendError(SecurityAssistantError):
    """Raised when the long-term memory backend fails."""


# --------------------------------------------------------------------------- #
# Orchestrator
# --------------------------------------------------------------------------- #
class OrchestratorError(SecurityAssistantError):
    """Base class for orchestrator lifecycle errors."""


class OrchestratorNotRunningError(OrchestratorError):
    """Raised when work is submitted to an orchestrator that is not running."""
