"""Tests for the Shodan client and IoT tool registrations.

The dispatch tests matter most here: they prove the risk classifications are
actually enforced by the core gate, in particular that ``INTRUSIVE`` control
port probing cannot run under a routine ``ACTIVE`` engagement.
"""

from __future__ import annotations

from typing import Any

import pytest

from security_assistant.core import (
    AuthorizationScope,
    DispatcherConfig,
    InvocationStatus,
    RiskLevel,
    ToolContext,
    ToolDispatcher,
    ToolRegistry,
)
from security_assistant.iot.fingerprints import INDUSTRIAL_PORTS
from security_assistant.iot.models import DeviceClass, Exposure
from security_assistant.iot.shodan_client import (
    INDEX_CONFIDENCE,
    ShodanCredentialsError,
    ShodanError,
    UnavailableSearchClient,
    api_key_from_env,
    default_search_client,
    parse_shodan_host,
    parse_shodan_search,
)
from security_assistant.iot.stream_discovery import ProbeResult
from security_assistant.iot.tools import (
    ALL_IOT_TOOLS,
    control_port_probe,
    iot_scan,
    shodan_host,
    shodan_search,
    stream_probe,
)
from security_assistant.osint.collectors.base import CollectorError
from tests.unit.conftest import run


class FakeSearchClient:
    def __init__(
        self,
        host_payload: dict[str, Any] | None = None,
        search_payload: dict[str, Any] | None = None,
    ) -> None:
        self.host_payload = host_payload or {}
        self.search_payload = search_payload or {}
        self.calls: list[tuple[str, str]] = []

    async def host(self, ip: str) -> dict[str, Any]:
        self.calls.append(("host", ip))
        return self.host_payload

    async def search(self, query: str, *, limit: int = 100) -> dict[str, Any]:
        self.calls.append(("search", query))
        return self.search_payload


class FakeProbe:
    def __init__(self, responses: dict[int, ProbeResult] | None = None) -> None:
        self.responses = responses or {}
        self.sent: dict[int, bytes] = {}

    async def probe(self, host: str, port: int, payload: bytes = b"") -> ProbeResult:
        self.sent[port] = payload
        return self.responses.get(port) or ProbeResult(host, port, False, error="refused")


def ctx(**config: Any) -> ToolContext:
    return ToolContext(scope=None, config=config)


SHODAN_HOST_PAYLOAD: dict[str, Any] = {
    "ip_str": "192.0.2.10",
    "hostnames": ["cam1.example.com"],
    "org": "Example ISP",
    "last_update": "2026-08-01T00:00:00",
    "data": [
        {
            "port": 554,
            "transport": "tcp",
            "data": "RTSP/1.0 200 OK\r\nServer: Hikvision Rtsp Server\r\n",
            "timestamp": "2026-08-01T00:00:00",
        },
        {
            "port": 80,
            "transport": "tcp",
            "data": "HTTP/1.0 401 Unauthorized\r\nWWW-Authenticate: Digest\r\n",
            "http": {"server": "Hikvision-Webs"},
        },
    ],
}


class TestApiKeyFromEnv:
    def test_reads_the_variable(self) -> None:
        assert api_key_from_env({"SHODAN_API_KEY": " abc123 "}) == "abc123"

    def test_missing_key_fails_with_an_actionable_message(self) -> None:
        with pytest.raises(ShodanCredentialsError, match="SHODAN_API_KEY is not set"):
            api_key_from_env({})

    def test_blank_key_is_treated_as_missing(self) -> None:
        with pytest.raises(ShodanCredentialsError):
            api_key_from_env({"SHODAN_API_KEY": "   "})

    def test_default_client_degrades_without_credentials(self, monkeypatch) -> None:
        monkeypatch.delenv("SHODAN_API_KEY", raising=False)
        assert isinstance(default_search_client(), UnavailableSearchClient)

    def test_unavailable_client_names_the_missing_variable(self) -> None:
        with pytest.raises(ShodanError, match="SHODAN_API_KEY"):
            run(UnavailableSearchClient().host("192.0.2.10"))


class TestParseShodanHost:
    def test_builds_a_device_with_services(self) -> None:
        device = parse_shodan_host(SHODAN_HOST_PAYLOAD)
        assert device is not None
        assert device.host == "192.0.2.10"
        assert device.device_class == DeviceClass.IP_CAMERA
        assert device.vendor == "hikvision"
        assert device.open_ports == [80, 554]
        assert device.hostnames == ["cam1.example.com"]

    def test_index_data_is_scored_below_a_live_observation(self) -> None:
        device = parse_shodan_host(SHODAN_HOST_PAYLOAD)
        assert device is not None
        assert device.confidence == INDEX_CONFIDENCE
        assert all(s.confidence == INDEX_CONFIDENCE for s in device.services)

    def test_carries_the_index_timestamp(self) -> None:
        device = parse_shodan_host(SHODAN_HOST_PAYLOAD)
        assert device is not None
        rtsp = next(s for s in device.services if s.port == 554)
        assert rtsp.attributes["shodan_timestamp"] == "2026-08-01T00:00:00"

    def test_auth_state_is_derived_from_the_banner(self) -> None:
        device = parse_shodan_host(SHODAN_HOST_PAYLOAD)
        assert device is not None
        by_port = {s.port: s for s in device.services}
        assert by_port[80].exposure == Exposure.AUTHENTICATED
        assert by_port[554].exposure == Exposure.UNAUTHENTICATED

    def test_empty_payload_is_none_not_an_empty_device(self) -> None:
        assert parse_shodan_host({}) is None

    def test_malformed_entries_are_skipped(self) -> None:
        device = parse_shodan_host(
            {"ip_str": "192.0.2.10", "data": ["nonsense", {"port": "bad"}, {"port": 99999}]}
        )
        assert device is not None
        assert device.services == []


class TestParseShodanSearch:
    def test_folds_matches_by_host(self) -> None:
        payload = {
            "total": 2,
            "matches": [
                {"ip_str": "192.0.2.10", "port": 80, "data": "HTTP/1.0 200 OK"},
                {"ip_str": "192.0.2.10", "port": 554, "data": "RTSP/1.0 200 OK"},
                {"ip_str": "192.0.2.11", "port": 80, "data": "HTTP/1.0 200 OK"},
            ],
        }
        devices = parse_shodan_search(payload)

        assert len(devices) == 2
        assert devices[0].open_ports == [80, 554]

    def test_empty_search_is_empty_list(self) -> None:
        assert parse_shodan_search({"matches": []}) == []


class TestShodanTools:
    def test_host_lookup_projects_graph_elements(self) -> None:
        client = FakeSearchClient(host_payload=SHODAN_HOST_PAYLOAD)
        result = run(shodan_host.invoke(ctx(iot_search_client=client), {"target": "192.0.2.10"}))

        assert result["indexed"] is True
        keys = {e["key"] for e in result["entities"]}
        assert "iot_device:192.0.2.10" in keys
        assert "network_service:192.0.2.10:554/rtsp" in keys

    def test_no_index_record_is_reported_plainly(self) -> None:
        # Must not read as "nothing is exposed".
        result = run(
            shodan_host.invoke(ctx(iot_search_client=FakeSearchClient()), {"target": "192.0.2.10"})
        )
        assert result["indexed"] is False
        assert "no record" in result["note"]
        assert result["entities"] == []

    def test_search_requires_a_query(self) -> None:
        with pytest.raises(CollectorError, match="must not be empty"):
            run(
                shodan_search.invoke(
                    ctx(iot_search_client=FakeSearchClient()),
                    {"target": "example.com", "query": "   "},
                )
            )

    def test_search_rejects_an_out_of_range_limit(self) -> None:
        with pytest.raises(CollectorError, match="limit must be between"):
            run(
                shodan_search.invoke(
                    ctx(iot_search_client=FakeSearchClient()),
                    {"target": "example.com", "query": "port:554", "limit": 9999},
                )
            )

    def test_search_records_its_scope_anchor(self) -> None:
        client = FakeSearchClient(search_payload={"total": 0, "matches": []})
        result = run(
            shodan_search.invoke(
                ctx(iot_search_client=client),
                {"target": "example.com", "query": "port:554"},
            )
        )
        assert result["scope_anchor"] == "example.com"
        assert client.calls == [("search", "port:554")]

    def test_client_error_becomes_a_collector_error(self) -> None:
        class BrokenClient(FakeSearchClient):
            async def host(self, ip: str) -> dict[str, Any]:
                raise ShodanError("Shodan rate limit exceeded (429)")

        with pytest.raises(CollectorError, match="429"):
            run(shodan_host.invoke(ctx(iot_search_client=BrokenClient()), {"target": "192.0.2.10"}))


class TestScanTools:
    def test_scan_fingerprints_open_ports(self) -> None:
        probe = FakeProbe(
            {80: ProbeResult("192.0.2.10", 80, True, banner="HTTP/1.0 200 OK\r\nServer: Axis\r\n")}
        )
        result = run(
            iot_scan.invoke(ctx(tcp_probe=probe), {"target": "192.0.2.10", "ports": [80, 443]})
        )

        assert result["summary"]["devices"] == 1
        assert "iot_device:192.0.2.10" in {e["key"] for e in result["entities"]}

    def test_scan_refuses_to_reach_control_ports(self) -> None:
        probe = FakeProbe()
        result = run(
            iot_scan.invoke(ctx(tcp_probe=probe), {"target": "192.0.2.10", "ports": [80, 502, 102]})
        )

        assert result["excluded_control_ports"] == [102, 502]
        assert set(probe.sent) == {80}
        assert "control_port_probe" in result["note"]

    def test_scan_rejects_bad_ports(self) -> None:
        with pytest.raises(CollectorError, match="Port out of range"):
            run(iot_scan.invoke(ctx(tcp_probe=FakeProbe()), {"target": "192.0.2.10", "ports": [0]}))

    def test_scan_caps_the_port_count(self) -> None:
        with pytest.raises(CollectorError, match="Refusing to scan"):
            run(
                iot_scan.invoke(
                    ctx(tcp_probe=FakeProbe()),
                    {"target": "192.0.2.10", "ports": list(range(1, 200))},
                )
            )

    def test_stream_probe_reports_unauthenticated_endpoints(self) -> None:
        probe = FakeProbe(
            {554: ProbeResult("192.0.2.10", 554, True, banner="RTSP/1.0 200 OK\r\nCSeq: 1\r\n")}
        )
        result = run(
            stream_probe.invoke(ctx(tcp_probe=probe), {"target": "192.0.2.10", "ports": [554]})
        )

        assert len(result["unauthenticated_endpoints"]) == 1
        assert "responded without requiring authentication" in result["finding"]

    def test_stream_probe_never_retrieves_content(self) -> None:
        probe = FakeProbe({554: ProbeResult("192.0.2.10", 554, True, banner="RTSP/1.0 200 OK\r\n")})
        result = run(
            stream_probe.invoke(ctx(tcp_probe=probe), {"target": "192.0.2.10", "ports": [554]})
        )

        assert result["content_retrieved"] is False
        sent = probe.sent[554].decode()
        assert sent.startswith("OPTIONS")
        assert "DESCRIBE" not in sent and "PLAY" not in sent

    def test_authenticated_endpoint_is_not_a_finding(self) -> None:
        probe = FakeProbe(
            {
                554: ProbeResult(
                    "192.0.2.10",
                    554,
                    True,
                    banner="RTSP/1.0 401 Unauthorized\r\nWWW-Authenticate: Digest\r\n",
                )
            }
        )
        result = run(
            stream_probe.invoke(ctx(tcp_probe=probe), {"target": "192.0.2.10", "ports": [554]})
        )
        assert result["unauthenticated_endpoints"] == []
        assert "finding" not in result


class TestControlPortProbe:
    def test_sends_no_protocol_bytes(self) -> None:
        probe = FakeProbe({502: ProbeResult("192.0.2.10", 502, True, banner="")})
        result = run(
            control_port_probe.invoke(
                ctx(tcp_probe=probe), {"target": "192.0.2.10", "ports": [502]}
            )
        )

        assert probe.sent[502] == b""
        assert result["protocol_data_sent"] is False
        assert result["reachable_control_ports"] == [502]
        assert "warrant immediate review" in result["finding"]

    def test_rejects_non_control_ports(self) -> None:
        with pytest.raises(CollectorError, match=r"belong to iot\.scan"):
            run(
                control_port_probe.invoke(
                    ctx(tcp_probe=FakeProbe()), {"target": "192.0.2.10", "ports": [80]}
                )
            )

    def test_defaults_to_the_industrial_port_set(self) -> None:
        probe = FakeProbe()
        run(control_port_probe.invoke(ctx(tcp_probe=probe), {"target": "192.0.2.10"}))
        assert set(probe.sent) == set(INDUSTRIAL_PORTS)


class TestToolSpecContract:
    def test_risk_levels_match_what_each_tool_does(self) -> None:
        risks = {t.spec.name: t.spec.risk for t in ALL_IOT_TOOLS}
        assert risks["iot.shodan_host"] is RiskLevel.PASSIVE
        assert risks["iot.shodan_search"] is RiskLevel.PASSIVE
        assert risks["iot.scan"] is RiskLevel.ACTIVE
        assert risks["iot.stream_probe"] is RiskLevel.ACTIVE
        assert risks["iot.control_port_probe"] is RiskLevel.INTRUSIVE

    def test_all_are_scope_gated(self) -> None:
        assert all(t.spec.requires_scope for t in ALL_IOT_TOOLS)
        assert all(t.spec.target_argument == "target" for t in ALL_IOT_TOOLS)

    def test_all_declare_rate_limits_and_timeouts(self) -> None:
        for iot_tool in ALL_IOT_TOOLS:
            assert iot_tool.spec.rate_limit_per_minute, iot_tool.spec.name
            assert iot_tool.spec.timeout_seconds, iot_tool.spec.name

    def test_all_register_cleanly(self) -> None:
        registry = ToolRegistry("iot")
        registry.register_all(ALL_IOT_TOOLS)
        assert len(registry) == 5


class TestDispatchEnforcement:
    """The risk classifications must be enforced by the core, not by docs."""

    @staticmethod
    def _dispatcher(max_risk: RiskLevel) -> ToolDispatcher:
        registry = ToolRegistry("iot")
        registry.register_all(ALL_IOT_TOOLS)
        scope = AuthorizationScope(
            allow=["192.0.2.0/24"], max_risk=max_risk, authorization_reference="ENG-IOT"
        )
        return ToolDispatcher(registry, scope, DispatcherConfig())

    def test_out_of_scope_host_never_reaches_the_probe(self) -> None:
        dispatcher = self._dispatcher(RiskLevel.ACTIVE)
        probe = FakeProbe()
        context = ToolContext(scope=dispatcher.scope, config={"tcp_probe": probe})

        result = run(dispatcher.call("iot.scan", context, target="203.0.113.5"))

        assert result.status is InvocationStatus.DENIED
        assert probe.sent == {}

    def test_passive_scope_blocks_active_scanning(self) -> None:
        dispatcher = self._dispatcher(RiskLevel.PASSIVE)
        context = ToolContext(scope=dispatcher.scope, config={"tcp_probe": FakeProbe()})
        result = run(dispatcher.call("iot.scan", context, target="192.0.2.10"))
        assert result.status is InvocationStatus.DENIED

    def test_passive_scope_still_allows_index_lookups(self) -> None:
        dispatcher = self._dispatcher(RiskLevel.PASSIVE)
        context = ToolContext(
            scope=dispatcher.scope,
            config={"iot_search_client": FakeSearchClient(host_payload=SHODAN_HOST_PAYLOAD)},
        )
        result = run(dispatcher.call("iot.shodan_host", context, target="192.0.2.10"))
        assert result.status is InvocationStatus.SUCCESS

    def test_active_scope_blocks_control_port_probing(self) -> None:
        # The whole point of the INTRUSIVE level: a routine engagement must
        # not reach industrial control systems.
        dispatcher = self._dispatcher(RiskLevel.ACTIVE)
        probe = FakeProbe()
        context = ToolContext(scope=dispatcher.scope, config={"tcp_probe": probe})

        result = run(dispatcher.call("iot.control_port_probe", context, target="192.0.2.10"))

        assert result.status is InvocationStatus.DENIED
        assert probe.sent == {}

    def test_intrusive_scope_permits_control_port_probing(self) -> None:
        dispatcher = self._dispatcher(RiskLevel.INTRUSIVE)
        probe = FakeProbe({502: ProbeResult("192.0.2.10", 502, True, banner="")})
        context = ToolContext(scope=dispatcher.scope, config={"tcp_probe": probe})

        result = run(
            dispatcher.call("iot.control_port_probe", context, target="192.0.2.10", ports=[502])
        )
        assert result.status is InvocationStatus.SUCCESS

    def test_scan_failure_becomes_a_failed_result_not_an_exception(self) -> None:
        dispatcher = self._dispatcher(RiskLevel.ACTIVE)
        context = ToolContext(scope=dispatcher.scope, config={"tcp_probe": FakeProbe()})
        result = run(dispatcher.call("iot.scan", context, target="192.0.2.10", ports=[0]))

        assert result.status is InvocationStatus.ERROR
        assert result.error_type == "CollectorError"
