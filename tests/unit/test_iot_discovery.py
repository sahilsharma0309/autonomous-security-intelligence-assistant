"""Tests for live discovery, asset models, and graph projection.

The probe is injected throughout, so nothing here opens a socket. The payload
tests are the safety-relevant ones: they pin that the scanner sends HEAD and
OPTIONS rather than GET/DESCRIBE/PLAY, and that control ports receive no
protocol bytes at all.
"""

from __future__ import annotations

import asyncio

import pytest

from security_assistant.iot.fingerprints import INDUSTRIAL_PORTS
from security_assistant.iot.models import (
    DeviceClass,
    DiscoveredDevice,
    DiscoveredService,
    Exposure,
    ServiceProtocol,
    assets_to_graph_elements,
    devices_from_mappings,
    merge_devices,
    summarize,
)
from security_assistant.iot.stream_discovery import (
    ProbeResult,
    ScanConfig,
    build_probe_payload,
    discover_device,
    discover_many,
    scan_host,
)
from security_assistant.osint.graph import EntityGraph
from security_assistant.osint.models import EdgeType, EntityType


class FakeProbe:
    """Serves canned probe results and records what was sent to each port."""

    def __init__(self, responses: dict[int, ProbeResult] | None = None) -> None:
        self.responses = responses or {}
        self.sent: dict[int, bytes] = {}

    async def probe(self, host: str, port: int, payload: bytes = b"") -> ProbeResult:
        self.sent[port] = payload
        canned = self.responses.get(port)
        if canned is not None:
            return canned
        return ProbeResult(host, port, False, error="connection refused")


def open_port(host: str, port: int, banner: str) -> ProbeResult:
    return ProbeResult(host, port, True, banner=banner)


def run(coro):  # type: ignore[no-untyped-def]
    return asyncio.run(coro)


# --------------------------------------------------------------------------- #
class TestProbePayloads:
    """What the scanner puts on the wire is a safety property, so it is pinned."""

    def test_http_uses_head_not_get(self) -> None:
        payload = build_probe_payload("192.0.2.10", 80).decode()
        assert payload.startswith("HEAD / HTTP/1.0")
        assert "GET " not in payload

    def test_rtsp_uses_options_and_never_describe_or_play(self) -> None:
        payload = build_probe_payload("192.0.2.10", 554).decode()
        assert payload.startswith("OPTIONS rtsp://192.0.2.10:554/ RTSP/1.0")
        assert "DESCRIBE" not in payload
        assert "PLAY" not in payload

    @pytest.mark.parametrize("port", INDUSTRIAL_PORTS)
    def test_control_ports_receive_no_bytes(self, port: int) -> None:
        # Speaking Modbus/S7/DNP3/BACnet to a live PLC is exactly what this
        # module must never do.
        assert build_probe_payload("192.0.2.10", port) == b""

    def test_unknown_ports_send_nothing_and_let_the_server_speak(self) -> None:
        assert build_probe_payload("192.0.2.10", 9999) == b""

    def test_https_port_also_uses_head(self) -> None:
        assert build_probe_payload("192.0.2.10", 8443).decode().startswith("HEAD ")


class TestScanConfig:
    def test_excludes_industrial_ports_by_default(self) -> None:
        config = ScanConfig(ports=[80, 502, 554])
        assert config.effective_ports() == [80, 554]

    def test_includes_them_when_explicitly_enabled(self) -> None:
        config = ScanConfig(ports=[80, 502], include_industrial=True)
        assert config.effective_ports() == [80, 502]

    def test_deduplicates_and_sorts(self) -> None:
        assert ScanConfig(ports=[554, 80, 80]).effective_ports() == [80, 554]

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"connect_timeout": 0},
            {"read_timeout": -1},
            {"max_concurrency": 0},
            {"ports": [0]},
            {"ports": [70000]},
        ],
    )
    def test_rejects_invalid_config(self, kwargs: dict) -> None:
        with pytest.raises(ValueError):
            ScanConfig(**kwargs)


class TestScanHost:
    def test_probes_every_configured_port(self) -> None:
        probe = FakeProbe()
        results = run(scan_host("192.0.2.10", probe, ScanConfig(ports=[80, 443, 554])))
        assert {r.port for r in results} == {80, 443, 554}

    def test_never_probes_control_ports_unless_enabled(self) -> None:
        probe = FakeProbe()
        run(scan_host("192.0.2.10", probe, ScanConfig(ports=[80, 502, 102])))
        assert set(probe.sent) == {80}

    def test_a_raising_probe_does_not_sink_the_scan(self) -> None:
        class HalfBrokenProbe(FakeProbe):
            async def probe(self, host: str, port: int, payload: bytes = b"") -> ProbeResult:
                if port == 443:
                    raise RuntimeError("socket exploded")
                return open_port(host, port, "HTTP/1.0 200 OK\r\n\r\n")

        results = run(scan_host("192.0.2.10", HalfBrokenProbe(), ScanConfig(ports=[80, 443])))
        by_port = {r.port: r for r in results}
        assert by_port[80].is_open is True
        assert by_port[443].is_open is False
        assert "socket exploded" in (by_port[443].error or "")


class TestDiscoverDevice:
    def test_builds_a_device_from_open_ports(self) -> None:
        probe = FakeProbe(
            {
                80: open_port(
                    "192.0.2.10",
                    80,
                    "HTTP/1.0 401 Unauthorized\r\nWWW-Authenticate: Digest\r\n"
                    "Server: Hikvision-Webs\r\n\r\n",
                ),
                554: open_port("192.0.2.10", 554, "RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n"),
            }
        )
        device = run(discover_device("192.0.2.10", probe, ScanConfig(ports=[80, 443, 554])))

        assert device.host == "192.0.2.10"
        assert device.device_class == DeviceClass.IP_CAMERA
        assert device.vendor == "hikvision"
        assert device.open_ports == [80, 554]

    def test_records_authentication_state_per_service(self) -> None:
        probe = FakeProbe(
            {
                80: open_port("192.0.2.10", 80, "HTTP/1.0 401 Unauthorized\r\n\r\n"),
                8080: open_port("192.0.2.10", 8080, "HTTP/1.0 200 OK\r\n\r\n"),
            }
        )
        device = run(discover_device("192.0.2.10", probe, ScanConfig(ports=[80, 8080])))
        by_port = {s.port: s for s in device.services}

        assert by_port[80].exposure == Exposure.AUTHENTICATED
        assert by_port[8080].exposure == Exposure.UNAUTHENTICATED
        assert [s.port for s in device.unauthenticated_services] == [8080]

    def test_closed_host_yields_a_low_confidence_empty_device(self) -> None:
        device = run(discover_device("192.0.2.10", FakeProbe(), ScanConfig(ports=[80])))
        assert device.services == []
        assert device.confidence < 0.5

    def test_open_port_with_no_banner_is_still_recorded(self) -> None:
        # An open control port that says nothing is exactly the case here.
        probe = FakeProbe({502: open_port("192.0.2.10", 502, "")})
        device = run(
            discover_device("192.0.2.10", probe, ScanConfig(ports=[502], include_industrial=True))
        )
        assert device.open_ports == [502]
        assert device.services[0].exposure == Exposure.UNKNOWN
        assert device.services[0].attributes["control_port"] is True

    def test_discover_many_skips_unusable_hosts(self) -> None:
        probe = FakeProbe({80: open_port("192.0.2.10", 80, "HTTP/1.0 200 OK\r\n\r\n")})
        devices = run(
            discover_many(["192.0.2.10", "  ", "192.0.2.11"], probe, ScanConfig(ports=[80]))
        )
        assert {d.host for d in devices} == {"192.0.2.10", "192.0.2.11"}


class TestServiceModel:
    def test_canonical_address(self) -> None:
        service = DiscoveredService(host="192.0.2.10", port=554, protocol="rtsp")
        assert service.address == "192.0.2.10:554/rtsp"

    def test_ipv6_address_is_bracketed(self) -> None:
        service = DiscoveredService(host="2001:db8::1", port=80, protocol="http")
        assert service.address == "[2001:db8::1]:80/http"

    def test_rejects_out_of_range_port(self) -> None:
        with pytest.raises(ValueError, match="Port out of range"):
            DiscoveredService(host="192.0.2.10", port=70000)

    def test_hostile_banner_is_truncated(self) -> None:
        # The peer controls these bytes; one hostile response must not bloat
        # the graph or a report.
        service = DiscoveredService(host="192.0.2.10", port=80, banner="A" * 5000)
        assert len(service.banner) < 2200
        assert service.banner.endswith("[truncated]")

    def test_host_is_normalized(self) -> None:
        assert DiscoveredService(host="Cam.Example.COM.", port=80).host == "cam.example.com"


class TestMergeDevices:
    def test_folds_devices_sharing_a_host(self) -> None:
        first = DiscoveredDevice(
            host="192.0.2.10",
            services=[DiscoveredService(host="192.0.2.10", port=80)],
            source="iot.shodan_host",
        )
        second = DiscoveredDevice(
            host="192.0.2.10",
            device_class=DeviceClass.IP_CAMERA,
            services=[DiscoveredService(host="192.0.2.10", port=554, protocol="rtsp")],
            source="iot.scan",
        )
        merged = merge_devices([first, second])

        assert len(merged) == 1
        assert merged[0].open_ports == [80, 554]
        # The specific classification wins over `unknown`.
        assert merged[0].device_class == DeviceClass.IP_CAMERA
        assert "iot.scan" in merged[0].source

    def test_does_not_duplicate_the_same_service(self) -> None:
        service = DiscoveredService(host="192.0.2.10", port=80)
        merged = merge_devices(
            [
                DiscoveredDevice(host="192.0.2.10", services=[service]),
                DiscoveredDevice(host="192.0.2.10", services=[service]),
            ]
        )
        assert len(merged[0].services) == 1

    def test_distinct_hosts_stay_separate(self) -> None:
        merged = merge_devices(
            [DiscoveredDevice(host="192.0.2.10"), DiscoveredDevice(host="192.0.2.11")]
        )
        assert len(merged) == 2


class TestGraphProjection:
    @staticmethod
    def _device() -> DiscoveredDevice:
        return DiscoveredDevice(
            host="192.0.2.10",
            device_class=DeviceClass.IP_CAMERA,
            vendor="hikvision",
            hostnames=["cam1.example.com"],
            services=[
                DiscoveredService(
                    host="192.0.2.10",
                    port=554,
                    protocol="rtsp",
                    exposure=Exposure.UNAUTHENTICATED,
                ),
                DiscoveredService(host="192.0.2.10", port=80, protocol="http"),
            ],
            source="iot.scan",
        )

    def test_projects_device_service_and_address_nodes(self) -> None:
        entities, _ = assets_to_graph_elements([self._device()])
        keys = {e.key for e in entities}

        assert "iot_device:192.0.2.10" in keys
        assert "network_service:192.0.2.10:554/rtsp" in keys
        assert "network_service:192.0.2.10:80/http" in keys
        assert "ip_address:192.0.2.10" in keys
        assert "organization:hikvision" in keys
        assert "domain:cam1.example.com" in keys

    def test_projects_the_expected_edges(self) -> None:
        _, relationships = assets_to_graph_elements([self._device()])
        edges = {(r.source_key, r.type, r.target_key) for r in relationships}

        assert ("iot_device:192.0.2.10", EdgeType.RUNS_ON, "ip_address:192.0.2.10") in edges
        assert (
            "iot_device:192.0.2.10",
            EdgeType.EXPOSES_SERVICE,
            "network_service:192.0.2.10:554/rtsp",
        ) in edges
        assert (
            "network_service:192.0.2.10:554/rtsp",
            EdgeType.SERVICE_ON,
            "ip_address:192.0.2.10",
        ) in edges
        assert (
            "iot_device:192.0.2.10",
            EdgeType.MANUFACTURED_BY,
            "organization:hikvision",
        ) in edges

    def test_vendor_is_scored_below_direct_observation(self) -> None:
        # A banner is self-reported; the open port is a fact.
        _, relationships = assets_to_graph_elements([self._device()])
        by_type = {r.type: r.confidence for r in relationships}
        assert by_type[EdgeType.MANUFACTURED_BY] < by_type[EdgeType.RUNS_ON]

    def test_hostname_device_has_no_address_node(self) -> None:
        # Nothing to join on until DNS supplies an address.
        device = DiscoveredDevice(host="cam.example.com")
        entities, _ = assets_to_graph_elements([device])
        assert not [e for e in entities if e.type is EntityType.IP_ADDRESS]

    def test_assets_join_osint_findings_at_the_address_node(self) -> None:
        """The whole reason IoT nodes live in the same graph."""
        from security_assistant.osint.models import Entity, Relationship

        graph = EntityGraph("joined")

        # An OSINT finding: a domain resolving to an address.
        domain = graph.add_entity(Entity.create(EntityType.DOMAIN, "example.com"))
        address = graph.add_entity(Entity.create(EntityType.IP_ADDRESS, "192.0.2.10"))
        graph.add_relationship(Relationship.create(domain, address, EdgeType.RESOLVES_TO))

        # An IoT finding at the same address.
        entities, relationships = assets_to_graph_elements([self._device()])
        graph.add_entities(entities)
        for relationship in relationships:
            graph.add_relationship(relationship)

        # The camera and the domain are now connected through the address.
        path = graph.shortest_path("iot_device:192.0.2.10", "domain:example.com")
        assert [e.key for e in path] == [
            "iot_device:192.0.2.10",
            "ip_address:192.0.2.10",
            "domain:example.com",
        ]

    def test_projected_graph_round_trips(self) -> None:
        graph = EntityGraph()
        entities, relationships = assets_to_graph_elements([self._device()])
        graph.add_entities(entities)
        for relationship in relationships:
            graph.add_relationship(relationship)

        restored = EntityGraph.from_json(graph.to_json())
        assert {e.key for e in restored} == {e.key for e in graph}

    def test_projected_graph_exports_to_cypher(self) -> None:
        graph = EntityGraph()
        entities, _ = assets_to_graph_elements([self._device()])
        graph.add_entities(entities)
        statements = graph.to_cypher()

        queries = " ".join(s["query"] for s in statements)
        assert ":IotDevice" in queries
        assert ":NetworkService" in queries
        # Values stay parameterized.
        assert all("192.0.2.10" not in s["query"] for s in statements)


class TestSummarize:
    def test_counts_by_class_and_protocol(self) -> None:
        devices = [
            DiscoveredDevice(
                host="192.0.2.10",
                device_class=DeviceClass.IP_CAMERA,
                services=[
                    DiscoveredService(
                        host="192.0.2.10",
                        port=554,
                        protocol="rtsp",
                        exposure=Exposure.UNAUTHENTICATED,
                    )
                ],
            ),
            DiscoveredDevice(host="192.0.2.11", device_class=DeviceClass.ROUTER),
        ]
        summary = summarize(devices)

        assert summary["devices"] == 2
        assert summary["services"] == 1
        assert summary["unauthenticated_services"] == 1
        assert summary["by_device_class"]["ip_camera"] == 1
        assert summary["by_protocol"]["rtsp"] == 1


class TestRoundTrip:
    def test_devices_survive_serialization(self) -> None:
        original = DiscoveredDevice(
            host="192.0.2.10",
            device_class=DeviceClass.IP_CAMERA,
            vendor="axis",
            services=[
                DiscoveredService(
                    host="192.0.2.10",
                    port=554,
                    protocol=ServiceProtocol.RTSP,
                    banner="RTSP/1.0 200 OK",
                    exposure=Exposure.UNAUTHENTICATED,
                )
            ],
        )
        restored = devices_from_mappings([original.to_dict()])

        assert len(restored) == 1
        assert restored[0].host == original.host
        assert restored[0].device_class == original.device_class
        assert restored[0].open_ports == original.open_ports
        assert restored[0].services[0].exposure == Exposure.UNAUTHENTICATED
