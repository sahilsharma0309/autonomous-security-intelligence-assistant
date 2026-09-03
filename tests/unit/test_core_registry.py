"""Tests for tool declaration, argument validation, and the registry."""

from __future__ import annotations

import pytest

from security_assistant.core import (
    BaseTool,
    RiskLevel,
    ToolCategory,
    ToolContext,
    ToolParameter,
    ToolRegistry,
    ToolSpec,
    tool,
)
from security_assistant.core.exceptions import (
    ToolAlreadyRegisteredError,
    ToolNotFoundError,
    ToolValidationError,
)
from tests.unit.conftest import run, whois_lookup


class TestToolParameter:
    def test_rejects_invalid_identifier(self) -> None:
        with pytest.raises(ValueError, match="not a valid identifier"):
            ToolParameter("not a name")

    def test_required_with_default_is_contradictory(self) -> None:
        with pytest.raises(ValueError, match="required but also declares a default"):
            ToolParameter("x", str, required=True, default="y")

    def test_type_mismatch_rejected(self) -> None:
        with pytest.raises(ToolValidationError):
            ToolParameter("count", int).validate("nope")

    def test_bool_not_accepted_as_int(self) -> None:
        # True == 1 in Python; silently accepting it would mask real bugs.
        with pytest.raises(ToolValidationError):
            ToolParameter("count", int).validate(True)

    def test_int_widens_to_float(self) -> None:
        assert ToolParameter("ratio", float).validate(3) == 3.0

    def test_choices_enforced(self) -> None:
        param = ToolParameter("mode", str, choices=["fast", "deep"])
        assert param.validate("deep") == "deep"
        with pytest.raises(ToolValidationError):
            param.validate("other")


class TestToolSpec:
    def test_scope_gated_tool_must_declare_target(self) -> None:
        with pytest.raises(ValueError, match="declares no 'target' parameter"):
            ToolSpec(name="bad", description="d", requires_scope=True, parameters=())

    def test_duplicate_parameters_rejected(self) -> None:
        with pytest.raises(ValueError, match="duplicate parameter"):
            ToolSpec(
                name="dup",
                description="d",
                requires_scope=False,
                parameters=(ToolParameter("a"), ToolParameter("a")),
            )

    def test_validate_applies_defaults(self) -> None:
        spec = ToolSpec(
            name="t",
            description="d",
            requires_scope=False,
            parameters=(ToolParameter("depth", int, required=False, default=3),),
        )
        assert spec.validate_arguments({}) == {"depth": 3}

    def test_unknown_arguments_rejected(self) -> None:
        with pytest.raises(ToolValidationError, match="unknown argument"):
            whois_lookup.spec.validate_arguments({"target": "example.com", "bogus": 1})

    def test_missing_required_argument_rejected(self) -> None:
        with pytest.raises(ToolValidationError, match="missing required argument"):
            whois_lookup.spec.validate_arguments({})

    def test_non_mapping_arguments_rejected(self) -> None:
        with pytest.raises(ToolValidationError, match="must be a mapping"):
            whois_lookup.spec.validate_arguments(["example.com"])  # type: ignore[arg-type]

    def test_to_dict_is_schema_shaped(self) -> None:
        payload = whois_lookup.spec.to_dict()
        assert payload["name"] == "osint.whois"
        assert payload["risk"] == "PASSIVE"
        assert payload["parameters"][0]["name"] == "target"


class TestToolDecorator:
    def test_rejects_sync_function(self) -> None:
        with pytest.raises(TypeError, match="must wrap an async function"):

            @tool(name="sync", description="d", requires_scope=False)
            def sync_tool(ctx: ToolContext) -> str:  # pragma: no cover
                return "x"

    def test_rejects_signature_mismatch(self) -> None:
        with pytest.raises(TypeError, match="does not accept declared parameter"):

            @tool(
                name="mismatch",
                description="d",
                requires_scope=False,
                parameters=[ToolParameter("depth", int)],
            )
            async def mismatched(ctx: ToolContext) -> str:  # pragma: no cover
                return "x"

    def test_requires_context_parameter(self) -> None:
        with pytest.raises(TypeError, match="ToolContext as its first argument"):

            @tool(name="noctx", description="d", requires_scope=False)
            async def no_ctx() -> str:  # pragma: no cover
                return "x"


class TestBaseTool:
    def test_subclass_requires_spec(self) -> None:
        with pytest.raises(TypeError, match="must define a class-level"):

            class Broken(BaseTool):  # pragma: no cover
                async def execute(self, ctx: ToolContext, **kwargs: object) -> str:
                    return "x"

    def test_class_based_tool_is_dispatchable(self) -> None:
        class Echo(BaseTool):
            spec = ToolSpec(
                name="util.echo",
                description="Echo a value.",
                category=ToolCategory.UTILITY,
                risk=RiskLevel.PASSIVE,
                requires_scope=False,
                parameters=(ToolParameter("value", str),),
            )

            async def execute(self, ctx: ToolContext, *, value: str) -> str:
                return value.upper()

        echo = Echo()
        assert run(echo.invoke(ToolContext(scope=None), {"value": "hi"})) == "HI"


class TestToolRegistry:
    def test_registers_and_looks_up(self, registry: ToolRegistry) -> None:
        assert len(registry) == 4
        assert "recon.dns" in registry
        assert registry.get("recon.dns").spec.name == "recon.dns"

    def test_unknown_tool_raises(self, registry: ToolRegistry) -> None:
        with pytest.raises(ToolNotFoundError):
            registry.get("nope")
        assert registry.try_get("nope") is None

    def test_duplicate_registration_rejected(self, registry: ToolRegistry) -> None:
        with pytest.raises(ToolAlreadyRegisteredError):
            registry.register(whois_lookup)

    def test_replace_is_explicit(self, registry: ToolRegistry) -> None:
        registry.register(whois_lookup, replace=True)
        assert len(registry) == 4

    def test_register_all_is_atomic(self, registry: ToolRegistry) -> None:
        before = set(registry.names)
        with pytest.raises(ToolAlreadyRegisteredError):
            registry.register_all([whois_lookup])
        assert set(registry.names) == before

    def test_unregister(self, registry: ToolRegistry) -> None:
        registry.unregister("recon.dns")
        assert "recon.dns" not in registry
        with pytest.raises(ToolNotFoundError):
            registry.unregister("recon.dns")

    def test_filters(self, registry: ToolRegistry) -> None:
        assert [t.spec.name for t in registry.by_category(ToolCategory.OSINT)] == ["osint.whois"]
        assert {t.spec.name for t in registry.at_or_below_risk(RiskLevel.PASSIVE)} == {
            "net.vpn_up",
            "osint.whois",
            "analysis.correlate",
        }
        assert [t.spec.name for t in registry.producing("hosts")] == ["recon.dns"]
        assert [t.spec.name for t in registry.consuming("hosts")] == ["analysis.correlate"]

    def test_select_combines_criteria(self, registry: ToolRegistry) -> None:
        selected = registry.select(max_risk=RiskLevel.PASSIVE, requires_scope=True)
        assert {t.spec.name for t in selected} == {"osint.whois", "analysis.correlate"}

    def test_rejects_non_tool_objects(self, registry: ToolRegistry) -> None:
        with pytest.raises(TypeError, match="not a valid tool"):
            registry.register(object())  # type: ignore[arg-type]

    def test_summary(self, registry: ToolRegistry) -> None:
        summary = registry.summary()
        assert summary["total"] == 4
        assert summary["scope_gated"] == 3

    def test_describe_returns_schema(self, registry: ToolRegistry) -> None:
        described = registry.describe()
        assert len(described) == 4
        assert all("parameters" in entry for entry in described)
