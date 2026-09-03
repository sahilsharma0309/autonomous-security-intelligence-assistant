"""The tool registry: naming, lookup, and capability introspection.

The registry is the single source of truth for what the agent can do. The
planner queries it to discover capabilities, the dispatcher resolves names
through it, and the LLM-facing layer renders :meth:`ToolRegistry.describe` into
a tool schema.

Registration is strict by default -- re-registering a name raises rather than
silently shadowing an existing tool, because a shadowed security tool is a
genuinely dangerous failure mode.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Iterator, Sequence
from typing import Any

from security_assistant.core.exceptions import (
    ToolAlreadyRegisteredError,
    ToolNotFoundError,
)
from security_assistant.core.tool import BaseTool, FunctionTool, Tool, ToolSpec
from security_assistant.core.types import RiskLevel, ToolCategory

logger = logging.getLogger(__name__)

__all__ = ["ToolRegistry"]


class ToolRegistry:
    """An indexed collection of tools.

    >>> registry = ToolRegistry()
    >>> registry.register(my_tool)          # doctest: +SKIP
    >>> registry.get("dns.resolve")         # doctest: +SKIP
    >>> [t.spec.name for t in registry.by_category(ToolCategory.OSINT)]  # doctest: +SKIP
    """

    __slots__ = ("_by_category", "_name", "_tools")

    def __init__(self, name: str = "default") -> None:
        self._name = name
        self._tools: dict[str, Tool] = {}
        self._by_category: dict[ToolCategory, set[str]] = {c: set() for c in ToolCategory}

    # -- registration ------------------------------------------------------ #
    def register(self, tool: Tool, *, replace: bool = False) -> Tool:
        """Register ``tool``.

        Set ``replace=True`` to deliberately override an existing name; the
        replacement is logged at WARNING because it is rarely intentional.
        """
        spec = _spec_of(tool)
        existing = self._tools.get(spec.name)

        if existing is not None:
            if not replace:
                raise ToolAlreadyRegisteredError(spec.name)
            logger.warning(
                "Replacing already-registered tool %r (%s -> %s)",
                spec.name,
                type(existing).__name__,
                type(tool).__name__,
            )
            self._by_category[_spec_of(existing).category].discard(spec.name)

        self._tools[spec.name] = tool
        self._by_category[spec.category].add(spec.name)
        logger.debug(
            "Registered tool name=%s category=%s risk=%s scope_gated=%s",
            spec.name,
            spec.category,
            spec.risk,
            spec.requires_scope,
        )
        return tool

    def register_all(self, tools: Iterable[Tool], *, replace: bool = False) -> None:
        """Register several tools, failing atomically.

        Nothing is committed unless every tool registers cleanly, so a partial
        toolset never ends up live.
        """
        staged = list(tools)
        if not replace:
            names = [_spec_of(t).name for t in staged]
            duplicates = {n for n in names if names.count(n) > 1}
            if duplicates:
                raise ToolAlreadyRegisteredError(sorted(duplicates)[0])
            for name in names:
                if name in self._tools:
                    raise ToolAlreadyRegisteredError(name)

        for candidate in staged:
            self.register(candidate, replace=replace)

    def unregister(self, name: str) -> Tool:
        """Remove and return the tool registered under ``name``."""
        tool = self._tools.pop(name, None)
        if tool is None:
            raise ToolNotFoundError(name)
        self._by_category[_spec_of(tool).category].discard(name)
        logger.debug("Unregistered tool name=%s", name)
        return tool

    def clear(self) -> None:
        """Drop every registered tool."""
        self._tools.clear()
        for names in self._by_category.values():
            names.clear()

    # -- lookup ------------------------------------------------------------ #
    def get(self, name: str) -> Tool:
        """Return the tool registered under ``name``.

        Raises :class:`ToolNotFoundError` if it is absent.
        """
        try:
            return self._tools[name]
        except KeyError:
            raise ToolNotFoundError(name) from None

    def try_get(self, name: str) -> Tool | None:
        """Return the tool or ``None`` if it is not registered."""
        return self._tools.get(name)

    def spec_for(self, name: str) -> ToolSpec:
        """Return the :class:`ToolSpec` for ``name``."""
        return _spec_of(self.get(name))

    def __contains__(self, name: object) -> bool:
        return isinstance(name, str) and name in self._tools

    def __len__(self) -> int:
        return len(self._tools)

    def __iter__(self) -> Iterator[Tool]:
        return iter(self._tools.values())

    @property
    def names(self) -> list[str]:
        """Registered tool names, sorted."""
        return sorted(self._tools)

    @property
    def specs(self) -> list[ToolSpec]:
        """Specs of every registered tool, sorted by name."""
        return [_spec_of(self._tools[n]) for n in self.names]

    # -- filtered views ---------------------------------------------------- #
    def by_category(self, category: ToolCategory) -> list[Tool]:
        """Tools in ``category``, sorted by name."""
        return [self._tools[n] for n in sorted(self._by_category[category])]

    def by_tag(self, tag: str) -> list[Tool]:
        """Tools carrying ``tag``, sorted by name."""
        return [t for t in self._sorted_tools() if tag in _spec_of(t).tags]

    def at_or_below_risk(self, max_risk: RiskLevel) -> list[Tool]:
        """Tools whose risk does not exceed ``max_risk``.

        Useful for showing an operator exactly which capabilities a given
        engagement scope actually unlocks.
        """
        ceiling = RiskLevel.parse(max_risk)
        return [t for t in self._sorted_tools() if _spec_of(t).risk <= ceiling]

    def producing(self, artifact: str) -> list[Tool]:
        """Tools that declare they emit ``artifact``."""
        return [t for t in self._sorted_tools() if artifact in _spec_of(t).produces]

    def consuming(self, artifact: str) -> list[Tool]:
        """Tools that declare they want ``artifact`` beforehand."""
        return [t for t in self._sorted_tools() if artifact in _spec_of(t).consumes]

    def select(
        self,
        *,
        categories: Sequence[ToolCategory] | None = None,
        max_risk: RiskLevel | None = None,
        tags: Sequence[str] | None = None,
        requires_scope: bool | None = None,
    ) -> list[Tool]:
        """Return tools matching every supplied criterion."""
        results = self._sorted_tools()

        if categories is not None:
            wanted = set(categories)
            results = [t for t in results if _spec_of(t).category in wanted]
        if max_risk is not None:
            ceiling = RiskLevel.parse(max_risk)
            results = [t for t in results if _spec_of(t).risk <= ceiling]
        if tags:
            required = set(tags)
            results = [t for t in results if required <= set(_spec_of(t).tags)]
        if requires_scope is not None:
            results = [t for t in results if _spec_of(t).requires_scope is requires_scope]

        return results

    # -- introspection ----------------------------------------------------- #
    def describe(self) -> list[dict[str, Any]]:
        """Return JSON-serializable specs for every tool.

        This is the payload handed to an LLM planner as its tool schema.
        """
        return [spec.to_dict() for spec in self.specs]

    def summary(self) -> dict[str, Any]:
        """Aggregate counts, handy for startup logging and health endpoints."""
        by_category = {
            category.value: len(names) for category, names in self._by_category.items() if names
        }
        by_risk: dict[str, int] = {}
        for spec in self.specs:
            by_risk[str(spec.risk)] = by_risk.get(str(spec.risk), 0) + 1
        return {
            "registry": self._name,
            "total": len(self._tools),
            "by_category": by_category,
            "by_risk": by_risk,
            "scope_gated": sum(1 for s in self.specs if s.requires_scope),
        }

    def _sorted_tools(self) -> list[Tool]:
        return [self._tools[n] for n in self.names]

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<ToolRegistry {self._name!r} tools={len(self._tools)}>"


def _spec_of(tool: Tool) -> ToolSpec:
    """Extract a spec from any object satisfying the Tool protocol."""
    spec = getattr(tool, "spec", None)
    if not isinstance(spec, ToolSpec):
        raise TypeError(
            f"{type(tool).__name__} is not a valid tool: expected a `spec: ToolSpec` "
            f"attribute, got {type(spec).__name__}. Use @tool(...) or subclass BaseTool."
        )
    if not isinstance(tool, (FunctionTool, BaseTool)) and not callable(
        getattr(tool, "invoke", None)
    ):
        raise TypeError(f"Tool {spec.name!r} does not implement an `invoke` coroutine")
    return spec
