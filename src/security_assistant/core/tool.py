"""Tool definition, declaration, and argument validation.

A *tool* is the unit of capability the agent can dispatch: a DNS lookup, a
Shodan query, a URL detonation, a VPN health check. This module defines what a
tool looks like and gives two equivalent ways to declare one:

* the :func:`tool` decorator, for simple coroutine functions, and
* the :class:`BaseTool` abstract class, for tools that need construction
  parameters or shared client state.

Both satisfy the :class:`Tool` protocol, so the registry and dispatcher treat
them identically.

Every tool declares metadata that the rest of the core relies on:

* ``risk`` -- how intrusively it touches a target, enforced by the scope gate.
* ``requires_scope`` -- whether it acts on a third party at all.
* ``category`` -- used by the planner to order work.
* ``parameters`` -- validated before the tool body ever runs.

Example::

    @tool(
        name="dns.resolve",
        description="Resolve A/AAAA records for a hostname.",
        category=ToolCategory.RECON,
        risk=RiskLevel.ACTIVE,
        parameters=[ToolParameter("target", str, description="Hostname to resolve")],
    )
    async def dns_resolve(ctx: ToolContext, target: str) -> list[str]:
        ...
"""

from __future__ import annotations

import abc
import inspect
import logging
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from security_assistant.core.exceptions import ToolValidationError
from security_assistant.core.types import RiskLevel, ToolCategory, ToolContext

logger = logging.getLogger(__name__)

__all__ = [
    "BaseTool",
    "FunctionTool",
    "Tool",
    "ToolParameter",
    "ToolSpec",
    "tool",
]

_MISSING = object()

# Types we can validate structurally without third-party schema machinery.
_SIMPLE_TYPES: dict[type, tuple[type, ...]] = {
    str: (str,),
    int: (int,),
    float: (int, float),
    bool: (bool,),
    list: (list, tuple),
    dict: (dict,),
}


@dataclass(frozen=True, slots=True)
class ToolParameter:
    """Declaration of a single tool argument.

    ``type_`` accepts the common builtins (``str``, ``int``, ``float``,
    ``bool``, ``list``, ``dict``). Anything else is accepted but only checked
    for presence, which keeps the validator honest about what it can actually
    guarantee.
    """

    name: str
    type_: type = str
    required: bool = True
    default: Any = None
    description: str = ""
    choices: Sequence[Any] | None = None

    def __post_init__(self) -> None:
        if not self.name.isidentifier():
            raise ValueError(f"Tool parameter name {self.name!r} is not a valid identifier")
        if self.required and self.default is not None:
            raise ValueError(
                f"Parameter {self.name!r} is required but also declares a default; "
                "mark it optional instead"
            )

    def validate(self, value: Any) -> Any:
        """Validate and lightly coerce ``value`` for this parameter."""
        if self.choices is not None and value not in self.choices:
            raise ToolValidationError(
                f"Parameter {self.name!r} must be one of {list(self.choices)!r}, got {value!r}"
            )

        expected = _SIMPLE_TYPES.get(self.type_)
        if expected is None:
            return value

        # bool is a subclass of int; treat them as distinct to avoid silently
        # accepting True where a count was meant.
        if self.type_ is not bool and isinstance(value, bool):
            raise ToolValidationError(
                f"Parameter {self.name!r} expects {self.type_.__name__}, got bool"
            )

        if not isinstance(value, expected):
            raise ToolValidationError(
                f"Parameter {self.name!r} expects {self.type_.__name__}, "
                f"got {type(value).__name__}"
            )

        # Normalize float parameters supplied as ints.
        if self.type_ is float and isinstance(value, int):
            return float(value)
        if self.type_ is list and isinstance(value, tuple):
            return list(value)
        return value

    def to_dict(self) -> dict[str, Any]:
        """JSON-serializable description, suitable for an LLM tool schema."""
        payload: dict[str, Any] = {
            "name": self.name,
            "type": getattr(self.type_, "__name__", str(self.type_)),
            "required": self.required,
            "description": self.description,
        }
        if self.default is not None:
            payload["default"] = self.default
        if self.choices is not None:
            payload["choices"] = list(self.choices)
        return payload


@dataclass(frozen=True, slots=True)
class ToolSpec:
    """Static metadata describing a tool.

    This is what the registry indexes, the planner reasons over, and the
    dispatcher enforces.
    """

    name: str
    description: str
    category: ToolCategory = ToolCategory.UTILITY
    risk: RiskLevel = RiskLevel.PASSIVE
    parameters: Sequence[ToolParameter] = field(default_factory=tuple)

    requires_scope: bool = True
    """Whether this tool acts on a third-party target and must be scope-checked.

    Defaults to ``True``: a tool must opt *out* of the safety gate explicitly,
    so forgetting to think about it fails closed.
    """

    target_argument: str = "target"
    """Which argument carries the target evaluated against the scope."""

    timeout_seconds: float | None = None
    rate_limit_per_minute: float | None = None
    max_attempts: int = 1
    """Attempts for transient failures. ``1`` means no retry."""

    tags: frozenset[str] = field(default_factory=frozenset)
    produces: frozenset[str] = field(default_factory=frozenset)
    """Logical artifact names this tool emits (used for plan dependencies)."""

    consumes: frozenset[str] = field(default_factory=frozenset)
    """Logical artifact names this tool wants before it runs."""

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("Tool name must not be empty")
        if self.max_attempts < 1:
            raise ValueError(f"Tool {self.name!r}: max_attempts must be >= 1")
        if self.timeout_seconds is not None and self.timeout_seconds <= 0:
            raise ValueError(f"Tool {self.name!r}: timeout_seconds must be positive")
        if self.rate_limit_per_minute is not None and self.rate_limit_per_minute <= 0:
            raise ValueError(f"Tool {self.name!r}: rate_limit_per_minute must be positive")

        seen: set[str] = set()
        for param in self.parameters:
            if param.name in seen:
                raise ValueError(f"Tool {self.name!r}: duplicate parameter {param.name!r}")
            seen.add(param.name)

        if self.requires_scope and self.target_argument not in seen:
            raise ValueError(
                f"Tool {self.name!r} requires scope checking but declares no "
                f"{self.target_argument!r} parameter"
            )

    @property
    def parameter_map(self) -> dict[str, ToolParameter]:
        return {p.name: p for p in self.parameters}

    def validate_arguments(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        """Validate ``arguments`` against this spec.

        Returns a new dict with defaults applied. Raises
        :class:`ToolValidationError` for unknown, missing, or ill-typed
        arguments.
        """
        if not isinstance(arguments, Mapping):
            raise ToolValidationError(
                f"Tool {self.name!r}: arguments must be a mapping, "
                f"got {type(arguments).__name__}"
            )

        params = self.parameter_map

        unknown = set(arguments) - set(params)
        if unknown:
            raise ToolValidationError(
                f"Tool {self.name!r}: unknown argument(s) {sorted(unknown)!r}; "
                f"accepted: {sorted(params)!r}"
            )

        validated: dict[str, Any] = {}
        for name, param in params.items():
            value = arguments.get(name, _MISSING)
            if value is _MISSING:
                if param.required:
                    raise ToolValidationError(
                        f"Tool {self.name!r}: missing required argument {name!r}"
                    )
                if param.default is not None:
                    validated[name] = param.default
                continue
            if value is None and not param.required:
                continue
            validated[name] = param.validate(value)

        return validated

    def to_dict(self) -> dict[str, Any]:
        """JSON-serializable description of the tool."""
        return {
            "name": self.name,
            "description": self.description,
            "category": self.category.value,
            "risk": str(self.risk),
            "requires_scope": self.requires_scope,
            "target_argument": self.target_argument if self.requires_scope else None,
            "parameters": [p.to_dict() for p in self.parameters],
            "timeout_seconds": self.timeout_seconds,
            "rate_limit_per_minute": self.rate_limit_per_minute,
            "max_attempts": self.max_attempts,
            "tags": sorted(self.tags),
            "produces": sorted(self.produces),
            "consumes": sorted(self.consumes),
        }


@runtime_checkable
class Tool(Protocol):
    """Structural type every dispatchable tool satisfies."""

    @property
    def spec(self) -> ToolSpec:  # pragma: no cover - protocol declaration
        ...

    async def invoke(
        self, ctx: ToolContext, arguments: Mapping[str, Any]
    ) -> Any:  # pragma: no cover - protocol declaration
        ...


ToolFunc = Callable[..., Awaitable[Any]]


class FunctionTool:
    """Adapts an ``async def`` function to the :class:`Tool` protocol.

    Produced by the :func:`tool` decorator. The wrapped function receives the
    :class:`ToolContext` positionally, followed by validated keyword
    arguments.
    """

    __slots__ = ("_func", "_spec")

    def __init__(self, spec: ToolSpec, func: ToolFunc) -> None:
        if not inspect.iscoroutinefunction(func):
            raise TypeError(
                f"Tool {spec.name!r} must wrap an async function; "
                f"{getattr(func, '__name__', func)!r} is synchronous"
            )
        self._spec = spec
        self._func = func

    @property
    def spec(self) -> ToolSpec:
        return self._spec

    @property
    def func(self) -> ToolFunc:
        return self._func

    async def invoke(self, ctx: ToolContext, arguments: Mapping[str, Any]) -> Any:
        return await self._func(ctx, **arguments)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<FunctionTool {self._spec.name} risk={self._spec.risk}>"


class BaseTool(abc.ABC):
    """Base class for tools that carry state (clients, sessions, caches).

    Subclasses declare :attr:`spec` and implement :meth:`execute`::

        class ShodanHostLookup(BaseTool):
            spec = ToolSpec(name="shodan.host", ...)

            def __init__(self, client): self._client = client

            async def execute(self, ctx, *, target): ...
    """

    #: Subclasses must override with a concrete :class:`ToolSpec`.
    spec: ToolSpec

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        # Allow abstract intermediates, but concrete tools need a spec.
        if not inspect.isabstract(cls) and not isinstance(getattr(cls, "spec", None), ToolSpec):
            raise TypeError(f"{cls.__name__} must define a class-level `spec: ToolSpec`")

    @abc.abstractmethod
    async def execute(self, ctx: ToolContext, **kwargs: Any) -> Any:
        """Run the tool. Arguments are pre-validated against the spec."""
        raise NotImplementedError

    async def invoke(self, ctx: ToolContext, arguments: Mapping[str, Any]) -> Any:
        return await self.execute(ctx, **arguments)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<{type(self).__name__} {self.spec.name} risk={self.spec.risk}>"


def tool(
    *,
    name: str,
    description: str,
    category: ToolCategory = ToolCategory.UTILITY,
    risk: RiskLevel | str | int = RiskLevel.PASSIVE,
    parameters: Sequence[ToolParameter] = (),
    requires_scope: bool = True,
    target_argument: str = "target",
    timeout_seconds: float | None = None,
    rate_limit_per_minute: float | None = None,
    max_attempts: int = 1,
    tags: Sequence[str] = (),
    produces: Sequence[str] = (),
    consumes: Sequence[str] = (),
) -> Callable[[ToolFunc], FunctionTool]:
    """Decorator turning an async function into a registrable tool.

    The decorated function's signature is checked against the declared
    parameters at import time, so a mismatch surfaces immediately rather than
    at dispatch.
    """

    spec = ToolSpec(
        name=name,
        description=description,
        category=category,
        risk=RiskLevel.parse(risk),
        parameters=tuple(parameters),
        requires_scope=requires_scope,
        target_argument=target_argument,
        timeout_seconds=timeout_seconds,
        rate_limit_per_minute=rate_limit_per_minute,
        max_attempts=max_attempts,
        tags=frozenset(tags),
        produces=frozenset(produces),
        consumes=frozenset(consumes),
    )

    def decorator(func: ToolFunc) -> FunctionTool:
        _assert_signature_matches(func, spec)
        return FunctionTool(spec, func)

    return decorator


def _assert_signature_matches(func: ToolFunc, spec: ToolSpec) -> None:
    """Fail fast when a tool's signature disagrees with its declared spec."""
    signature = inspect.signature(func)
    positional = [
        p
        for p in signature.parameters.values()
        if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)
    ]

    if not positional:
        raise TypeError(
            f"Tool {spec.name!r}: function must accept a ToolContext as its first argument"
        )

    accepts_var_kw = any(
        p.kind is p.VAR_KEYWORD for p in signature.parameters.values()
    )
    if accepts_var_kw:
        return

    # Everything after the context must be able to receive the declared params.
    accepted = {
        p.name
        for p in signature.parameters.values()
        if p.kind in (p.POSITIONAL_OR_KEYWORD, p.KEYWORD_ONLY)
    } - {positional[0].name}

    declared = {p.name for p in spec.parameters}
    missing = declared - accepted
    if missing:
        raise TypeError(
            f"Tool {spec.name!r}: function does not accept declared parameter(s) "
            f"{sorted(missing)!r}"
        )
