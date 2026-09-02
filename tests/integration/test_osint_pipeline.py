"""End-to-end integration: the agent core driving the OSINT module.

This exercises the whole path a real engagement takes -- authorization scope,
planner, concurrent dispatch, collectors, graph assembly, correlation, export
-- with every network dependency injected. It is the test that would catch a
regression in how Module 1 and Module 2 fit together, which the unit tests for
either half cannot see on their own.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from security_assistant.core import (
    Agent,
    AgentConfig,
    AgentOrchestrator,
    AuthorizationScope,
    OrchestratorConfig,
    RiskLevel,
    TaskStatus,
    ToolRegistry,
)
from security_assistant.osint import (
    ALL_COLLECTORS,
    Correlator,
    EntityGraph,
    EntityType,
    build_graph_from_payloads,
)
from security_assistant.osint.collectors import PlatformHook, ProbeOutcome


# --------------------------------------------------------------------------- #
# Injected doubles standing in for the network
# --------------------------------------------------------------------------- #
class ScriptedResolver:
    def __init__(self) -> None:
        self.answers: dict[str, dict[str, list[str]]] = {
            "example.com": {
                "A": ["93.184.216.34"],
                "MX": ["10 mail.example.com."],
                "NS": ["ns1.example.com.", "ns2.example.com."],
                "TXT": ["v=DMARC1; rua=mailto:dmarc@example.com; p=none"],
            },
            "www.example.com": {"A": ["93.184.216.34"]},
        }

    async def resolve(self, name: str, record_type: str) -> list[str]:
        return list(self.answers.get(name, {}).get(record_type, []))


class ScriptedWhois:
    async def lookup(self, domain: str) -> dict[str, Any]:
        return {
            "registrar": "Example Registrar, Inc.",
            "org": "Acme Widgets Ltd",
            "emails": ["admin@example.com"],
            "name_servers": ["NS1.EXAMPLE.COM", "ns2.example.com"],
            "creation_date": "2001-01-01T00:00:00",
        }


class ScriptedTls:
    async def fetch(self, host: str, port: int, *, verify: bool) -> dict[str, Any]:
        return {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("organizationName", "Let's Encrypt"),),),
            "subjectAltName": (
                ("DNS", "example.com"),
                ("DNS", "www.example.com"),
                ("DNS", "api.example.com"),
            ),
            "notBefore": "Jun  1 12:00:00 2025 GMT",
            "notAfter": "Sep  1 12:00:00 2035 GMT",
            "_version": "TLSv1.3",
            "_cipher": ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
        }


class ScriptedProbe:
    def __init__(self, hits: set[str]) -> None:
        self.hits = hits

    async def probe(self, url: str) -> ProbeOutcome:
        return ProbeOutcome(url=url, status=200 if url in self.hits else 404)


def osint_registry() -> ToolRegistry:
    registry = ToolRegistry("osint")
    registry.register_all(ALL_COLLECTORS)
    return registry


def engagement_scope(max_risk: RiskLevel = RiskLevel.ACTIVE) -> AuthorizationScope:
    return AuthorizationScope(
        allow=["example.com"],
        max_risk=max_risk,
        authorization_reference="ENG-INTEGRATION-1",
        engagement="integration-test",
    )


def collection_context() -> dict[str, Any]:
    return {
        "dns_resolver": ScriptedResolver(),
        "whois_client": ScriptedWhois(),
        "tls_fetcher": ScriptedTls(),
        "profile_probe": ScriptedProbe({"https://examplehub.test/u/acme"}),
        "social_platforms": [
            PlatformHook(
                name="examplehub", url_template="https://examplehub.test/u/{username}"
            )
        ],
        "username": "acme",
    }


class TestAgentDrivenCollection:
    def test_agent_runs_every_collector_and_builds_a_graph(self) -> None:
        agent = Agent(
            osint_registry(),
            engagement_scope(),
            config=AgentConfig(name="osint-integration", max_parallel_steps=4),
        )
        result = asyncio.run(
            agent.run(
                "Map the external attack surface",
                target="example.com",
                context=collection_context(),
            )
        )

        assert result.status is TaskStatus.SUCCEEDED, result.error
        assert not result.denied
        assert {r.tool_name for r in result.results if r.ok} == {
            "osint.dns",
            "osint.whois",
            "osint.tls",
            "osint.social",
        }

        graph = build_graph_from_payloads(result.values_by_tool().values())

        # Facts from three different collectors landed on one coherent graph.
        assert "domain:example.com" in graph
        assert "ip_address:93.184.216.34" in graph
        assert "email:admin@example.com" in graph
        assert "organization:acme widgets" in graph
        assert "social_handle:examplehub/acme" in graph

    def test_overlapping_observations_merge_with_combined_provenance(self) -> None:
        agent = Agent(osint_registry(), engagement_scope())
        result = asyncio.run(
            agent.run("Map surface", target="example.com", context=collection_context())
        )
        graph = build_graph_from_payloads(result.values_by_tool().values())

        # Every collector observes example.com -- DNS/WHOIS/TLS as their
        # subject, social as the engagement anchor for the handle it found. It
        # must be one node carrying all four sources, not four near-duplicates.
        apex = graph.require("domain:example.com")
        assert set(apex.sources) == {
            "osint.dns",
            "osint.whois",
            "osint.tls",
            "osint.social",
        }
        assert len(graph.by_type(EntityType.DOMAIN)) >= 4

    def test_dmarc_contact_is_extracted_from_txt(self) -> None:
        agent = Agent(osint_registry(), engagement_scope())
        result = asyncio.run(
            agent.run("Map surface", target="example.com", context=collection_context())
        )
        graph = build_graph_from_payloads(result.values_by_tool().values())
        assert "email:dmarc@example.com" in graph


class TestCorrelationOverCollectedData:
    def _correlated(self) -> tuple[EntityGraph, Any]:
        agent = Agent(osint_registry(), engagement_scope())
        result = asyncio.run(
            agent.run("Map surface", target="example.com", context=collection_context())
        )
        graph = build_graph_from_payloads(result.values_by_tool().values())
        report = Correlator().correlate(graph)
        return graph, report

    def test_www_alias_is_resolved_into_the_apex(self) -> None:
        graph, report = self._correlated()
        assert "domain:www.example.com" not in graph
        assert any(c.duplicate_key == "domain:www.example.com" for c in report.merged)

    def test_subdomain_containment_is_inferred(self) -> None:
        graph, _ = self._correlated()
        assert any(
            r.type.value == "subdomain_of" and r.source_key == "domain:api.example.com"
            for r in graph.relationships
        )

    def test_email_is_linked_to_its_own_domain(self) -> None:
        graph, _ = self._correlated()
        assert any(
            r.type.value == "uses_email" and r.target_key == "email:admin@example.com"
            for r in graph.relationships
        )

    def test_registrar_and_issuer_are_not_merged_into_the_registrant(self) -> None:
        # Let's Encrypt and the registrar must stay distinct from Acme, or the
        # graph would claim the target owns its CA.
        graph, _ = self._correlated()
        organizations = {e.canonical for e in graph.by_type(EntityType.ORGANIZATION)}
        assert "acme widgets" in organizations
        assert any("encrypt" in o for o in organizations)
        assert len(organizations) >= 2

    def test_correlated_graph_still_round_trips(self) -> None:
        graph, _ = self._correlated()
        restored = EntityGraph.from_json(graph.to_json())
        assert len(restored) == len(graph)
        assert {e.key for e in restored} == {e.key for e in graph}

    def test_graph_exports_to_parameterized_cypher(self) -> None:
        graph, _ = self._correlated()
        statements = graph.to_cypher()
        assert statements
        assert all("MERGE" in s["query"] for s in statements)
        assert all("example.com" not in s["query"] for s in statements)


class TestAuthorizationAcrossTheStack:
    def test_out_of_scope_target_collects_nothing(self) -> None:
        agent = Agent(osint_registry(), engagement_scope())
        result = asyncio.run(
            agent.run(
                "Map surface", target="not-authorized.net", context=collection_context()
            )
        )

        assert result.status is TaskStatus.FAILED
        assert len(result.denied) == 4
        assert not result.succeeded

        graph = build_graph_from_payloads(result.values_by_tool().values())
        assert len(graph) == 0

    def test_passive_engagement_runs_only_passive_collectors(self) -> None:
        agent = Agent(osint_registry(), engagement_scope(max_risk=RiskLevel.PASSIVE))
        result = asyncio.run(
            agent.run("Passive recon", target="example.com", context=collection_context())
        )

        # The planner only selects tools at or below the scope's risk cap, so
        # a passive engagement plans WHOIS alone.
        assert {r.tool_name for r in result.results} == {"osint.whois"}
        assert result.status is TaskStatus.SUCCEEDED

        graph = build_graph_from_payloads(result.values_by_tool().values())
        assert "organization:acme widgets" in graph
        assert graph.by_type(EntityType.IP_ADDRESS) == []

    def test_dry_run_touches_no_collector(self) -> None:
        resolver = ScriptedResolver()
        context = {**collection_context(), "dns_resolver": resolver}
        calls: list[str] = []

        class CountingResolver(ScriptedResolver):
            async def resolve(self, name: str, record_type: str) -> list[str]:
                calls.append(record_type)
                return await super().resolve(name, record_type)

        context["dns_resolver"] = CountingResolver()
        agent = Agent(
            osint_registry(), engagement_scope(), config=AgentConfig(dry_run=True)
        )
        result = asyncio.run(
            agent.run("Map surface", target="example.com", context=context)
        )

        assert result.status is TaskStatus.SUCCEEDED
        assert calls == []


class TestOrchestratedEngagement:
    def test_orchestrator_runs_osint_jobs_concurrently(self) -> None:
        async def scenario() -> list[Any]:
            registry = osint_registry()
            scope = engagement_scope()
            orchestrator = AgentOrchestrator(
                lambda: Agent(registry, scope), OrchestratorConfig(workers=2)
            )
            async with orchestrator:
                job_ids = await orchestrator.submit_all(
                    [
                        {
                            "goal": f"survey pass {index}",
                            "target": "example.com",
                            "context": collection_context(),
                        }
                        for index in range(3)
                    ]
                )
                return [await orchestrator.wait_for(j, timeout=60) for j in job_ids]

        jobs = asyncio.run(scenario())
        assert all(j.status is TaskStatus.SUCCEEDED for j in jobs)
        assert all(j.result is not None and len(j.result.succeeded) == 4 for j in jobs)


class TestCollectorFailureIsolation:
    def test_one_failing_collector_does_not_sink_the_run(self) -> None:
        class BrokenResolver:
            async def resolve(self, name: str, record_type: str) -> list[str]:
                raise RuntimeError("resolver is down")

        context = {**collection_context(), "dns_resolver": BrokenResolver()}
        agent = Agent(osint_registry(), engagement_scope())
        result = asyncio.run(
            agent.run("Map surface", target="example.com", context=context)
        )

        failed = {r.tool_name for r in result.failures}
        succeeded = {r.tool_name for r in result.succeeded}
        assert failed == {"osint.dns"}
        assert {"osint.whois", "osint.tls"} <= succeeded

        # The graph is still built from whatever did succeed.
        graph = build_graph_from_payloads(result.values_by_tool().values())
        assert "organization:acme widgets" in graph


@pytest.mark.parametrize("record_type", ["A", "MX", "NS", "TXT"])
def test_each_record_type_reaches_the_graph(record_type: str) -> None:
    """Each DNS record type maps to at least one graph element."""
    from security_assistant.core.types import ToolContext
    from security_assistant.osint.collectors import dns_collect

    result = asyncio.run(
        dns_collect.invoke(
            ToolContext(scope=None, config={"dns_resolver": ScriptedResolver()}),
            {"target": "example.com", "record_types": [record_type]},
        )
    )
    assert result["records"].get(record_type)
    assert len(result["entities"]) >= 2
