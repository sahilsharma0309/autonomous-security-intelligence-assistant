"""Agent core: orchestration, tool dispatch, planning, memory, and authorization.

This package is the engine the security modules plug into. It has no
third-party dependencies, so it imports cleanly in any environment and is
straightforward to test.

The typical wiring is::

    from security_assistant.core import (
        Agent, AgentOrchestrator, AuthorizationScope, ToolRegistry,
        RiskLevel, ToolCategory, ToolParameter, tool,
    )

    @tool(
        name="dns.resolve",
        description="Resolve A records for a hostname.",
        category=ToolCategory.RECON,
        risk=RiskLevel.ACTIVE,
        parameters=[ToolParameter("target", str, description="Hostname")],
    )
    async def dns_resolve(ctx, target: str) -> list[str]:
        ...

    registry = ToolRegistry()
    registry.register(dns_resolve)

    scope = AuthorizationScope(
        allow=["example.com"],
        max_risk=RiskLevel.ACTIVE,
        authorization_reference="ENG-2024-114",
    )

    agent = Agent(registry=registry, scope=scope)
    result = await agent.run("Map external surface", target="example.com")

Nothing here contacts a target that ``scope`` has not authorized.
"""

from __future__ import annotations

from security_assistant.core.agent import (
    Agent,
    AgentConfig,
    AgentRunResult,
    RefinementStrategy,
)
from security_assistant.core.authorization import (
    AuthorizationScope,
    ScopeDecision,
    ScopeRule,
    TargetKind,
    classify_target,
    normalize_target,
)
from security_assistant.core.dispatcher import (
    DispatcherConfig,
    EventSink,
    RateLimiter,
    ToolDispatcher,
)
from security_assistant.core.exceptions import (
    AuthorizationError,
    ConfigurationError,
    MemoryBackendError,
    OrchestratorError,
    OrchestratorNotRunningError,
    PlanningError,
    PlanValidationError,
    RateLimitExceededError,
    SecurityAssistantError,
    ToolAlreadyRegisteredError,
    ToolError,
    ToolExecutionError,
    ToolNotFoundError,
    ToolTimeoutError,
    ToolValidationError,
)
from security_assistant.core.memory import (
    EmbeddingProvider,
    HashingEmbeddingProvider,
    InMemoryVectorStore,
    LongTermMemory,
    MemoryRecord,
    VectorStore,
    cosine_similarity,
)
from security_assistant.core.orchestrator import (
    AgentOrchestrator,
    BackgroundService,
    Job,
    JobPriority,
    OrchestratorConfig,
)
from security_assistant.core.planner import (
    DEFAULT_CATEGORY_ORDER,
    Plan,
    PlannerStrategy,
    PlanStep,
    RuleBasedPlanner,
    SequentialPlanner,
)
from security_assistant.core.registry import ToolRegistry
from security_assistant.core.tool import (
    BaseTool,
    FunctionTool,
    Tool,
    ToolParameter,
    ToolSpec,
    tool,
)
from security_assistant.core.types import (
    InvocationStatus,
    RiskLevel,
    Severity,
    TaskStatus,
    ToolCategory,
    ToolContext,
    ToolInvocation,
    ToolResult,
    new_id,
    utcnow,
)

__all__ = [
    # Agent
    "Agent",
    "AgentConfig",
    "AgentRunResult",
    "RefinementStrategy",
    # Orchestrator
    "AgentOrchestrator",
    "BackgroundService",
    "Job",
    "JobPriority",
    "OrchestratorConfig",
    # Authorization
    "AuthorizationScope",
    "ScopeDecision",
    "ScopeRule",
    "TargetKind",
    "classify_target",
    "normalize_target",
    # Dispatch
    "DispatcherConfig",
    "EventSink",
    "RateLimiter",
    "ToolDispatcher",
    # Registry & tools
    "BaseTool",
    "FunctionTool",
    "Tool",
    "ToolParameter",
    "ToolRegistry",
    "ToolSpec",
    "tool",
    # Planning
    "DEFAULT_CATEGORY_ORDER",
    "Plan",
    "PlanStep",
    "PlannerStrategy",
    "RuleBasedPlanner",
    "SequentialPlanner",
    # Memory
    "EmbeddingProvider",
    "HashingEmbeddingProvider",
    "InMemoryVectorStore",
    "LongTermMemory",
    "MemoryRecord",
    "VectorStore",
    "cosine_similarity",
    # Types
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
    # Exceptions
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
