"""End-to-end integration: the agent driving OSINT and IoT together.

The point of making IoT assets first-class graph nodes was that a discovered
device and an OSINT finding about the same address should end up connected
without any cross-module wiring. These tests exercise that claim through the
real agent -- authorization, planning, dispatch, projection, correlation --
with every network dependency injected.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from security_assistant.core import (
    Agent,
    AgentConfig,
    AuthorizationScope,
    RiskLevel,
    TaskStatus,
    ToolRegistry,
)
from security_assistant.iot import ALL_IOT_TOOLS
from security_assistant.iot.stream_discovery import ProbeResult
from security_assistant.osint import (
    ALL_COLLECTORS,
    Correlator,
    EntityGraph,
    EntityType,
    build_graph_from_payloads,
)
from security_assistant.osint.models import EdgeType


# --------------------------------------------------------------------------- #
# Injected doubles
# --------------------------------------------------------------------------- #
class ScriptedResolver:
    """DNS that points example.com at the address the camera lives on."""

    async def resolve(self, name: str, record_type: str) -> list[str]:
        answers = {
            "example.com": {"A": ["192.0.2.10"], "MX": ["10 mail.example.com."]},
            "cam1.example.com": {"A": ["192.0.2.10"]},
        }
        return list(answers.get(name, {}).get(record_type, []))


class ScriptedWhois:
    async def lookup(self, domain: str) -> dict[str, Any]:
        return {"org": "Acme Widgets Ltd", "emails": ["admin@example.com"]}


class ScriptedTls:
    async def fetch(self, host: str, port: int, *, verify: bool) -> dict[str, Any]:
        return {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("organizationName", "Let's Encrypt"),),),
            "subjectAltName": (("DNS", "example.com"),),
            "notAfter": "Sep  1 12:00:00 2035 GMT",
        }


class ScriptedSearchClient:
    async def host(self, ip: str) -> dict[str, Any]:
        return {
            "ip_str": "192.0.2.10",
            "hostnames": ["cam1.example.com"],
            "org": "Example ISP",
            "data": [
                {
                    "port": 554,
                    "transport": "tcp",
                    "data": "RTSP/1.0 200 OK\r\nServer: Hikvision Rtsp Server\r\n",
                }
            ],
        }

    async def search(self, query: str, *, limit: int = 100) -> dict[str, Any]:
        return {"total": 0, "matches": []}


class ScriptedProbe:
    """An exposed camera: RTSP open with no auth, web UI behind a login."""

    def __init__(self) -> None:
        self.sent: dict[int, bytes] = {}

    async def probe(self, host: str, port: int, payload: bytes = b"") -> ProbeResult:
        self.sent[port] = payload
        banners = {
            554: "RTSP/1.0 200 OK\r\nCSeq: 1\r\nServer: Hikvision Rtsp Server\r\n\r\n",
            80: (
                "HTTP/1.0 401 Unauthorized\r\n"
                'WWW-Authenticate: Digest realm="cam"\r\n'
                "Server: Hikvision-Webs\r\n\r\n"
            ),
        }
        if port in banners:
            return ProbeResult(host, port, True, banner=banners[port])
        return ProbeResult(host, port, False, error="connection refused")


def full_registry() -> ToolRegistry:
    registry = ToolRegistry("full")
    registry.register_all([*ALL_COLLECTORS, *ALL_IOT_TOOLS])
    return registry


def scope(max_risk: RiskLevel = RiskLevel.ACTIVE) -> AuthorizationScope:
    return AuthorizationScope(
        allow=["example.com", "192.0.2.0/24"],
        max_risk=max_risk,
        authorization_reference="ENG-IOT-INTEGRATION",
        engagement="integration-test",
    )


def context(probe: ScriptedProbe | None = None) -> dict[str, Any]:
    return {
        "dns_resolver": ScriptedResolver(),
        "whois_client": ScriptedWhois(),
        "tls_fetcher": ScriptedTls(),
        "iot_search_client": ScriptedSearchClient(),
        "tcp_probe": probe or ScriptedProbe(),
    }


class TestIoTDiscoveryThroughTheAgent:
    def test_agent_runs_iot_tools_against_an_authorized_address(self) -> None:
        agent = Agent(full_registry(), scope(), config=AgentConfig(max_parallel_steps=4))
        result = asyncio.run(
            agent.run("Inventory the host", target="192.0.2.10", context=context())
        )

        assert result.status is TaskStatus.SUCCEEDED, result.error
        succeeded = {r.tool_name for r in result.succeeded}
        assert "iot.scan" in succeeded
        assert "iot.shodan_host" in succeeded
        # The INTRUSIVE tool is never planned under an ACTIVE engagement.
        assert "iot.control_port_probe" not in {r.tool_name for r in result.results}

    def test_discovered_camera_lands_in_the_graph(self) -> None:
        agent = Agent(full_registry(), scope())
        result = asyncio.run(
            agent.run("Inventory the host", target="192.0.2.10", context=context())
        )
        graph = build_graph_from_payloads(result.values_by_tool().values())

        assert "iot_device:192.0.2.10" in graph
        assert "network_service:192.0.2.10:554/rtsp" in graph
        assert "ip_address:192.0.2.10" in graph

        device = graph.require("iot_device:192.0.2.10")
        assert device.attributes["device_class"] == "ip_camera"

    def test_index_and_live_findings_merge_onto_one_device(self) -> None:
        # Shodan and the live scan both report 192.0.2.10; the graph must hold
        # one device carrying both sources, not two near-duplicates.
        agent = Agent(full_registry(), scope())
        result = asyncio.run(
            agent.run("Inventory the host", target="192.0.2.10", context=context())
        )
        graph = build_graph_from_payloads(result.values_by_tool().values())

        devices = graph.by_type(EntityType.IOT_DEVICE)
        assert len(devices) == 1
        assert {"iot.shodan_host", "iot.scan"} <= set(devices[0].sources)


class TestCrossModuleJoin:
    """The reason IoT assets are graph nodes rather than a separate inventory."""

    def _graph(self) -> EntityGraph:
        agent = Agent(full_registry(), scope(), config=AgentConfig(max_parallel_steps=4))

        # One run over the domain, one over the address it resolves to.
        osint = asyncio.run(
            agent.run("Map the domain", target="example.com", context=context())
        )
        assets = asyncio.run(
            agent.run("Inventory the host", target="192.0.2.10", context=context())
        )

        graph = build_graph_from_payloads(
            [*osint.values_by_tool().values(), *assets.values_by_tool().values()]
        )
        Correlator().correlate(graph)
        return graph

    def test_camera_connects_to_the_domain_through_the_address(self) -> None:
        graph = self._graph()
        path = graph.shortest_path("iot_device:192.0.2.10", "domain:example.com")

        assert [e.key for e in path] == [
            "iot_device:192.0.2.10",
            "ip_address:192.0.2.10",
            "domain:example.com",
        ]

    def test_camera_reaches_the_registrant_organization(self) -> None:
        # "Whose exposed camera is this?" is now a traversal.
        graph = self._graph()
        path = graph.shortest_path("iot_device:192.0.2.10", "organization:acme widgets")
        assert path
        assert len(path) <= 4

    def test_exposed_service_is_visible_from_the_device(self) -> None:
        graph = self._graph()
        services = graph.neighbors(
            "iot_device:192.0.2.10", edge_type=EdgeType.EXPOSES_SERVICE
        )
        assert any(s.canonical == "192.0.2.10:554/rtsp" for s in services)

    def test_joined_graph_round_trips_and_exports(self) -> None:
        graph = self._graph()
        restored = EntityGraph.from_json(graph.to_json())
        assert {e.key for e in restored} == {e.key for e in graph}

        statements = graph.to_cypher()
        assert any(":IotDevice" in s["query"] for s in statements)
        assert all("192.0.2.10" not in s["query"] for s in statements)

    def test_correlation_does_not_fuse_devices_with_domains(self) -> None:
        # Different entity types must never merge, however co-located.
        graph = self._graph()
        assert "iot_device:192.0.2.10" in graph
        assert "domain:example.com" in graph
        assert "ip_address:192.0.2.10" in graph


class TestAuthorizationAcrossTheStack:
    def test_out_of_scope_address_collects_nothing(self) -> None:
        probe = ScriptedProbe()
        agent = Agent(full_registry(), scope())
        result = asyncio.run(
            agent.run("Inventory", target="203.0.113.9", context=context(probe))
        )

        assert result.status is TaskStatus.FAILED
        assert result.denied
        assert not result.succeeded
        assert probe.sent == {}

    def test_passive_engagement_never_touches_the_target(self) -> None:
        probe = ScriptedProbe()
        agent = Agent(full_registry(), scope(max_risk=RiskLevel.PASSIVE))
        result = asyncio.run(
            agent.run("Passive inventory", target="192.0.2.10", context=context(probe))
        )

        planned = {r.tool_name for r in result.results}
        assert "iot.shodan_host" in planned
        assert "iot.scan" not in planned
        assert "iot.stream_probe" not in planned
        # Nothing reached the wire.
        assert probe.sent == {}

    def test_intrusive_engagement_unlocks_control_port_probing(self) -> None:
        probe = ScriptedProbe()
        agent = Agent(full_registry(), scope(max_risk=RiskLevel.INTRUSIVE))
        result = asyncio.run(
            agent.run("Full inventory", target="192.0.2.10", context=context(probe))
        )

        assert "iot.control_port_probe" in {r.tool_name for r in result.results}
        # Even then, control ports receive no protocol bytes.
        for port in (102, 502, 20000, 47808):
            assert probe.sent.get(port, b"") == b""


class TestStreamProbeRestraint:
    """The module must never fetch stream or page content."""

    def test_only_head_and_options_reach_the_wire(self) -> None:
        probe = ScriptedProbe()
        agent = Agent(full_registry(), scope())
        asyncio.run(agent.run("Inventory", target="192.0.2.10", context=context(probe)))

        for port, payload in probe.sent.items():
            if not payload:
                continue
            text = payload.decode()
            assert text.startswith(("HEAD ", "OPTIONS ")), f"port {port} sent {text[:40]!r}"
            assert "DESCRIBE" not in text
            assert "PLAY" not in text
            assert not text.startswith("GET ")

    def test_unauthenticated_rtsp_is_reported_as_a_finding(self) -> None:
        agent = Agent(full_registry(), scope())
        result = asyncio.run(
            agent.run("Inventory", target="192.0.2.10", context=context())
        )

        payloads = result.values_by_tool()
        stream = payloads.get("iot.stream_probe")
        assert stream is not None
        assert stream["content_retrieved"] is False
        assert stream["unauthenticated_endpoints"]
        assert any(e["port"] == 554 for e in stream["unauthenticated_endpoints"])

    def test_authenticated_web_ui_is_not_reported_as_exposed(self) -> None:
        agent = Agent(full_registry(), scope())
        result = asyncio.run(
            agent.run("Inventory", target="192.0.2.10", context=context())
        )
        stream = result.values_by_tool().get("iot.stream_probe")
        assert stream is not None
        assert all(e["port"] != 80 for e in stream["unauthenticated_endpoints"])


class TestFailureIsolation:
    def test_a_broken_probe_does_not_sink_the_run(self) -> None:
        class BrokenProbe:
            async def probe(self, host: str, port: int, payload: bytes = b"") -> ProbeResult:
                raise RuntimeError("network stack is down")

        ctx = {**context(), "tcp_probe": BrokenProbe()}
        agent = Agent(full_registry(), scope())
        result = asyncio.run(agent.run("Inventory", target="192.0.2.10", context=ctx))

        # Index lookups are unaffected by a dead network probe.
        assert "iot.shodan_host" in {r.tool_name for r in result.succeeded}
        graph = build_graph_from_payloads(result.values_by_tool().values())
        assert "iot_device:192.0.2.10" in graph


@pytest.mark.parametrize(
    ("tool_name", "expected_risk"),
    [
        ("iot.shodan_host", RiskLevel.PASSIVE),
        ("iot.shodan_search", RiskLevel.PASSIVE),
        ("iot.scan", RiskLevel.ACTIVE),
        ("iot.stream_probe", RiskLevel.ACTIVE),
        ("iot.control_port_probe", RiskLevel.INTRUSIVE),
    ],
)
def test_registered_risk_levels(tool_name: str, expected_risk: RiskLevel) -> None:
    """The registry is the source of truth the dispatcher enforces."""
    registry = full_registry()
    assert registry.get(tool_name).spec.risk is expected_risk
