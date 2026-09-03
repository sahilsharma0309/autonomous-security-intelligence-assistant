"""End-to-end integration: the agent core driving the threat scanner.

The payoff test is :class:`TestCrossModuleGraph`, which asserts that a URL
assessed by Module 4 and infrastructure discovered by Modules 2 and 3 land in
one connected graph without any cross-module wiring -- they meet at the
shared domain and address nodes, which is the whole reason those are
first-class entity types.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from typing import Any

from security_assistant.core import (
    Agent,
    AgentConfig,
    AuthorizationScope,
    RiskLevel,
    TaskStatus,
    ToolRegistry,
)
from security_assistant.osint import (
    ALL_COLLECTORS,
    Correlator,
    EdgeType,
    EntityGraph,
    EntityType,
    build_graph_from_payloads,
)
from security_assistant.threat import ALL_THREAT_TOOLS
from security_assistant.threat.models import SandboxReport
from security_assistant.threat.urlscan import SubmitOptions


# --------------------------------------------------------------------------- #
# Injected doubles
# --------------------------------------------------------------------------- #
class ScriptedVirusTotal:
    def __init__(self, malicious: int = 6) -> None:
        self.malicious = malicious
        self.calls: list[tuple[str, str]] = []

    async def report(self, indicator_type: str, indicator: str) -> Mapping[str, Any]:
        self.calls.append((indicator_type, indicator))
        return {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": self.malicious,
                        "harmless": 60,
                        "undetected": 4,
                    },
                    "categories": {"Sophos": "phishing"},
                    "last_analysis_date": 1735689600,
                }
            }
        }


class ScriptedUrlscan:
    def __init__(self) -> None:
        self.submissions: list[tuple[str, SubmitOptions]] = []

    async def search(self, query: str, *, size: int = 20) -> Mapping[str, Any]:
        return {
            "results": [
                {
                    "verdicts": {"overall": {"malicious": True, "categories": ["phishing"]}},
                    "task": {"time": "2025-06-01T12:00:00Z"},
                }
            ]
        }

    async def submit(self, url: str, options: SubmitOptions) -> Mapping[str, Any]:
        self.submissions.append((url, options))
        return {"uuid": "scan-1", "result": "https://urlscan.io/result/scan-1/"}

    async def result(self, scan_id: str) -> Mapping[str, Any]:
        return {}


class ScriptedInspector:
    """Stands in for the container sandbox."""

    def __init__(self, engine: str = "container") -> None:
        self.engine = engine
        self.inspected: list[str] = []

    async def inspect(self, url: str) -> SandboxReport:
        self.inspected.append(url)
        return SandboxReport(
            initial_url=url,
            final_url="https://collector.example/harvest",
            engine=self.engine,
            status=200,
            chain=[
                {"url": url, "status": 302},  # type: ignore[list-item]
            ]
            and [
                __import__(
                    "security_assistant.threat.models", fromlist=["RedirectHop"]
                ).RedirectHop(url, 302),
                __import__(
                    "security_assistant.threat.models", fromlist=["RedirectHop"]
                ).RedirectHop("https://collector.example/harvest", 200),
            ],
            contacted_domains=["cdn.example", "collector.example"],
            resource_hashes=["da39a3ee5e6b4b0d3255bfef95601890afd80709"],
            has_password_input=True,
            title="Sign in to your account",
            dom_excerpt="<html>...</html>",
        )


class ScriptedResolver:
    """OSINT DNS resolver, so the threat and OSINT graphs can meet."""

    async def resolve(self, name: str, record_type: str) -> list[str]:
        table = {
            "paypa1.com": {"A": ["203.0.113.77"]},
            "collector.example": {"A": ["203.0.113.77"]},
        }
        return list(table.get(name, {}).get(record_type, []))


class ScriptedWhois:
    async def lookup(self, domain: str) -> Mapping[str, Any]:
        return {"registrar": "Cheap Registrar Ltd", "org": "REDACTED FOR PRIVACY"}


class ScriptedTls:
    async def fetch(self, host: str, port: int, *, verify: bool) -> Mapping[str, Any]:
        return {
            "subject": ((("commonName", host),),),
            "issuer": ((("organizationName", "Let's Encrypt"),),),
            "subjectAltName": (("DNS", host),),
            "notBefore": "Jun  1 12:00:00 2025 GMT",
            "notAfter": "Sep  1 12:00:00 2035 GMT",
            "_version": "TLSv1.3",
            "_cipher": ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
        }


PHISH_URL = "https://paypa1.com/login"


def threat_registry() -> ToolRegistry:
    registry = ToolRegistry("threat")
    registry.register_all(ALL_THREAT_TOOLS)
    return registry


def scope(max_risk: RiskLevel = RiskLevel.ACTIVE) -> AuthorizationScope:
    return AuthorizationScope(
        allow=["paypa1.com", "collector.example"],
        max_risk=max_risk,
        authorization_reference="IR-INTEGRATION-1",
        engagement="threat-integration",
    )


def threat_context(engine: str = "container") -> dict[str, Any]:
    return {
        "virustotal_client": ScriptedVirusTotal(),
        "urlscan_client": ScriptedUrlscan(),
        "sandbox_inspector": ScriptedInspector(engine),
    }


class TestAgentDrivenScan:
    def test_agent_runs_the_threat_tools_and_scores_the_url(self) -> None:
        agent = Agent(
            threat_registry(),
            scope(),
            config=AgentConfig(name="threat-integration", max_parallel_steps=4),
        )
        result = asyncio.run(
            agent.run("Assess this link", target=PHISH_URL, context=threat_context())
        )

        assert result.status is TaskStatus.SUCCEEDED, result.error
        assert not result.denied

        names = {r.tool_name for r in result.succeeded}
        assert {"threat.url_analyze", "threat.virustotal", "threat.url_inspect"} <= names

        scored = result.values_by_tool().get("threat.url_score")
        assert scored is not None
        assert scored["risk_score"] > 60
        assert scored["risk_band"] in {"high", "critical"}

    def test_score_rises_once_evidence_is_aggregated(self) -> None:
        agent = Agent(threat_registry(), scope())
        result = asyncio.run(
            agent.run("Assess", target=PHISH_URL, context=threat_context())
        )
        values = result.values_by_tool()

        heuristics_only = values["threat.url_analyze"]["risk_score"]
        aggregated = values["threat.url_score"]["risk_score"]
        # Reputation and behaviour are independent categories, so combining
        # them must move the score above the heuristics alone.
        assert aggregated > heuristics_only

    def test_sandbox_evidence_reaches_the_score(self) -> None:
        agent = Agent(threat_registry(), scope())
        result = asyncio.run(
            agent.run("Assess", target=PHISH_URL, context=threat_context())
        )
        scored = result.values_by_tool()["threat.url_score"]
        codes = {f["code"] for f in scored["findings"]}
        assert "cross_domain_redirect" in codes
        assert "typosquat" in codes
        assert "reputation_virustotal" in codes


class TestGraphProjection:
    def _graph(self, engine: str = "container") -> EntityGraph:
        agent = Agent(threat_registry(), scope())
        result = asyncio.run(
            agent.run("Assess", target=PHISH_URL, context=threat_context(engine))
        )
        return build_graph_from_payloads(result.values_by_tool().values())

    def test_url_host_and_redirect_target_are_all_nodes(self) -> None:
        graph = self._graph()
        keys = {e.key for e in graph}
        assert "url:https://paypa1.com/login" in keys
        assert "domain:paypa1.com" in keys
        assert "url:https://collector.example/harvest" in keys

    def test_redirect_chain_is_traversable(self) -> None:
        graph = self._graph()
        path = graph.shortest_path(
            "url:https://paypa1.com/login", "url:https://collector.example/harvest"
        )
        assert path
        assert any(
            r.type is EdgeType.REDIRECTS_TO for r in graph.relationships
        )

    def test_contacted_hosts_and_file_hashes_are_linked(self) -> None:
        graph = self._graph()
        assert "domain:cdn.example" in graph
        assert (
            "file_hash:da39a3ee5e6b4b0d3255bfef95601890afd80709" in graph
        )
        kinds = {r.type for r in graph.relationships}
        assert EdgeType.CONTACTS in kinds
        assert EdgeType.REFERENCES_FILE in kinds

    def test_graph_round_trips(self) -> None:
        graph = self._graph()
        restored = EntityGraph.from_json(graph.to_json())
        assert {e.key for e in restored} == {e.key for e in graph}

    def test_cypher_export_never_interpolates_the_url(self) -> None:
        graph = self._graph()
        for statement in graph.to_cypher():
            assert "paypa1.com" not in statement["query"]


class TestCrossModuleGraph:
    """Module 2, 3 and 4 findings must converge without cross-module wiring."""

    def test_threat_and_osint_meet_at_the_shared_address(self) -> None:
        osint_registry = ToolRegistry("osint")
        osint_registry.register_all(ALL_COLLECTORS)

        osint_result = asyncio.run(
            Agent(osint_registry, scope()).run(
                "Map infrastructure",
                target="collector.example",
                context={
                    "dns_resolver": ScriptedResolver(),
                    "whois_client": ScriptedWhois(),
                    "tls_fetcher": ScriptedTls(),
                },
            )
        )
        threat_result = asyncio.run(
            Agent(threat_registry(), scope()).run(
                "Assess link", target=PHISH_URL, context=threat_context()
            )
        )

        graph = build_graph_from_payloads(
            [
                *osint_result.values_by_tool().values(),
                *threat_result.values_by_tool().values(),
            ]
        )

        # The phishing URL redirects to collector.example, which OSINT
        # independently resolved to an address. Nothing wired those together.
        assert "url:https://paypa1.com/login" in graph
        assert "ip_address:203.0.113.77" in graph

        path = graph.shortest_path(
            "url:https://paypa1.com/login", "ip_address:203.0.113.77"
        )
        assert path, "threat and OSINT findings should be connected"
        assert len(graph.components()) < len(graph)

    def test_correlation_runs_over_the_combined_graph(self) -> None:
        threat_result = asyncio.run(
            Agent(threat_registry(), scope()).run(
                "Assess", target=PHISH_URL, context=threat_context()
            )
        )
        graph = build_graph_from_payloads(threat_result.values_by_tool().values())
        before = len(graph)

        report = Correlator().correlate(graph)

        # Correlation must not damage the threat nodes.
        assert "url:https://paypa1.com/login" in graph
        assert len(graph) <= before
        assert report.entities_after == len(graph)

    def test_url_nodes_are_never_merged_with_their_host(self) -> None:
        threat_result = asyncio.run(
            Agent(threat_registry(), scope()).run(
                "Assess", target=PHISH_URL, context=threat_context()
            )
        )
        graph = build_graph_from_payloads(threat_result.values_by_tool().values())
        Correlator().correlate(graph)

        assert "url:https://paypa1.com/login" in graph
        assert "domain:paypa1.com" in graph
        urls = graph.by_type(EntityType.URL)
        assert all(u.type is EntityType.URL for u in urls)


class TestAuthorizationAcrossTheStack:
    def test_passive_engagement_never_loads_the_page(self) -> None:
        inspector = ScriptedInspector()
        context = {**threat_context(), "sandbox_inspector": inspector}
        agent = Agent(threat_registry(), scope(max_risk=RiskLevel.PASSIVE))

        result = asyncio.run(
            agent.run("Passive triage", target=PHISH_URL, context=context)
        )

        assert result.status is TaskStatus.SUCCEEDED
        assert inspector.inspected == []
        planned = {r.tool_name for r in result.results}
        assert "threat.url_inspect" not in planned
        assert "threat.urlscan_submit" not in planned
        # Passive analysis still produces a real assessment.
        assert result.values_by_tool()["threat.url_analyze"]["risk_score"] > 0

    def test_passive_engagement_never_submits_to_a_third_party(self) -> None:
        client = ScriptedUrlscan()
        context = {**threat_context(), "urlscan_client": client}
        agent = Agent(threat_registry(), scope(max_risk=RiskLevel.PASSIVE))
        asyncio.run(agent.run("Passive triage", target=PHISH_URL, context=context))
        assert client.submissions == []

    def test_out_of_scope_url_collects_nothing(self) -> None:
        inspector = ScriptedInspector()
        context = {**threat_context(), "sandbox_inspector": inspector}
        agent = Agent(threat_registry(), scope())

        result = asyncio.run(
            agent.run(
                "Assess", target="https://unauthorized.test/login", context=context
            )
        )

        assert result.status is TaskStatus.FAILED
        assert result.denied
        assert inspector.inspected == []
        graph = build_graph_from_payloads(result.values_by_tool().values())
        assert len(graph) == 0

    def test_dry_run_touches_nothing(self) -> None:
        inspector = ScriptedInspector()
        context = {**threat_context(), "sandbox_inspector": inspector}
        agent = Agent(threat_registry(), scope(), config=AgentConfig(dry_run=True))

        result = asyncio.run(agent.run("Assess", target=PHISH_URL, context=context))

        assert result.status is TaskStatus.SUCCEEDED
        assert inspector.inspected == []


class TestDegradedSandbox:
    def test_static_fallback_still_completes_and_declares_itself(self) -> None:
        agent = Agent(threat_registry(), scope())
        result = asyncio.run(
            agent.run("Assess", target=PHISH_URL, context=threat_context("static"))
        )

        assert result.status is TaskStatus.SUCCEEDED
        scored = result.values_by_tool()["threat.url_score"]
        codes = {f["code"] for f in scored["findings"]}
        assert "static_inspection_only" in codes
        # The note is INFO, so reduced coverage never inflates the score.
        note = next(f for f in scored["findings"] if f["code"] == "static_inspection_only")
        assert note["severity"] == "info"


class TestFailureIsolation:
    def test_one_failing_intel_source_does_not_sink_the_run(self) -> None:
        class BrokenVirusTotal:
            async def report(self, indicator_type: str, indicator: str) -> Mapping[str, Any]:
                raise RuntimeError("VT is down")

        context = {**threat_context(), "virustotal_client": BrokenVirusTotal()}
        agent = Agent(threat_registry(), scope())
        result = asyncio.run(agent.run("Assess", target=PHISH_URL, context=context))

        failed = {r.tool_name for r in result.failures}
        assert "threat.virustotal" in failed
        # The rest of the assessment still lands.
        assert "threat.url_analyze" in {r.tool_name for r in result.succeeded}
        graph = build_graph_from_payloads(result.values_by_tool().values())
        assert "url:https://paypa1.com/login" in graph
