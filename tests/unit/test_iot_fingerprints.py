"""Tests for service and device fingerprinting.

These pin the two rules the module claims: a port is only a hint, and a banner
is only self-reported evidence. Both matter downstream, because confidence
scoring in the graph depends on them.
"""

from __future__ import annotations

import pytest

from security_assistant.iot.fingerprints import (
    DEFAULT_IOT_PORTS,
    INDUSTRIAL_PORTS,
    classify_device,
    extract_vendor,
    fingerprint_service,
    protocol_for_port,
)
from security_assistant.iot.models import DeviceClass, ServiceProtocol


class TestProtocolForPort:
    @pytest.mark.parametrize(
        ("port", "expected"),
        [
            (80, ServiceProtocol.HTTP),
            (443, ServiceProtocol.HTTPS),
            (554, ServiceProtocol.RTSP),
            (22, ServiceProtocol.SSH),
            (502, ServiceProtocol.MODBUS),
            (102, ServiceProtocol.S7),
            (47808, ServiceProtocol.BACNET),
        ],
    )
    def test_known_ports(self, port: int, expected: str) -> None:
        assert protocol_for_port(port) == expected

    def test_unknown_port_falls_back_to_transport(self) -> None:
        assert protocol_for_port(9999) == "tcp"
        assert protocol_for_port(9999, "udp") == "udp"


class TestClassifyDevice:
    @pytest.mark.parametrize(
        ("banner", "expected"),
        [
            ("Server: Hikvision-Webs", DeviceClass.IP_CAMERA),
            ("DAHUA rtsp server", DeviceClass.IP_CAMERA),
            ("gSOAP/2.8 ONVIF", DeviceClass.IP_CAMERA),
            ("Server: Boa/0.94 NVR", DeviceClass.NVR),
            ("RouterOS 6.48 (MikroTik)", DeviceClass.ROUTER),
            ("HP JetDirect", DeviceClass.PRINTER),
            ("Synology DiskStation", DeviceClass.NAS),
            ("SIMATIC S7-1200 Siemens", DeviceClass.INDUSTRIAL),
            ("Tridium Niagara station", DeviceClass.BUILDING_AUTOMATION),
        ],
    )
    def test_banner_patterns(self, banner: str, expected: str) -> None:
        assert classify_device(banner) == expected

    def test_protocol_implies_class_without_a_banner(self) -> None:
        assert classify_device("", ServiceProtocol.RTSP, 554) == DeviceClass.IP_CAMERA
        assert classify_device("", ServiceProtocol.MODBUS, 502) == DeviceClass.INDUSTRIAL

    def test_banner_evidence_beats_protocol_convention(self) -> None:
        # Port 554 suggests a camera, but the banner says otherwise.
        assert classify_device("Synology DiskStation", ServiceProtocol.RTSP, 554) == DeviceClass.NAS

    def test_unknown_stays_unknown(self) -> None:
        # Refusing to guess is the correct behaviour here.
        assert classify_device("", "tcp", 9999) == DeviceClass.UNKNOWN
        assert classify_device("some opaque bytes", "tcp", 9999) == DeviceClass.UNKNOWN

    def test_industrial_port_alone_classifies(self) -> None:
        assert classify_device("", "tcp", 502) == DeviceClass.INDUSTRIAL


class TestExtractVendor:
    def test_finds_known_vendors(self) -> None:
        assert extract_vendor("Server: Hikvision-Webs") == "hikvision"
        assert extract_vendor("MikroTik RouterOS") == "mikrotik"

    def test_case_insensitive(self) -> None:
        assert extract_vendor("DAHUA Technology") == "dahua"

    def test_unknown_vendor_is_empty(self) -> None:
        assert extract_vendor("Server: nginx/1.24") == ""
        assert extract_vendor("") == ""


class TestFingerprintService:
    def test_parses_http_server_header(self) -> None:
        banner = "HTTP/1.0 200 OK\r\nServer: Hikvision-Webs/1.2.3\r\n\r\n"
        result = fingerprint_service(80, banner)

        assert result.protocol == ServiceProtocol.HTTP
        assert result.device_class == DeviceClass.IP_CAMERA
        assert result.vendor == "hikvision"
        assert result.product == "Hikvision-Webs/1.2.3"
        assert result.version == "1.2.3"
        assert result.status_code == 200

    def test_401_means_authentication_is_enforced(self) -> None:
        banner = 'HTTP/1.0 401 Unauthorized\r\nWWW-Authenticate: Digest realm="cam"\r\n\r\n'
        assert fingerprint_service(80, banner).requires_auth is True

    def test_403_counts_as_protected(self) -> None:
        assert fingerprint_service(80, "HTTP/1.1 403 Forbidden\r\n\r\n").requires_auth is True

    def test_200_means_no_authentication(self) -> None:
        assert fingerprint_service(80, "HTTP/1.0 200 OK\r\n\r\n").requires_auth is False

    def test_rtsp_options_response(self) -> None:
        banner = (
            "RTSP/1.0 200 OK\r\nCSeq: 1\r\n"
            "Public: OPTIONS, DESCRIBE, PLAY\r\nServer: Dahua Rtsp Server\r\n\r\n"
        )
        result = fingerprint_service(554, banner)

        assert result.protocol == ServiceProtocol.RTSP
        assert result.device_class == DeviceClass.IP_CAMERA
        assert result.requires_auth is False

    def test_rtsp_401_is_authenticated(self) -> None:
        banner = 'RTSP/1.0 401 Unauthorized\r\nWWW-Authenticate: Digest realm="cam"\r\n\r\n'
        assert fingerprint_service(554, banner).requires_auth is True

    def test_unrecognized_response_leaves_auth_unknown(self) -> None:
        # Guessing here would turn "we don't know" into a false finding.
        assert fingerprint_service(9999, "some opaque bytes").requires_auth is None

    def test_empty_banner_is_all_unknown(self) -> None:
        result = fingerprint_service(9999, "")
        assert result.requires_auth is None
        assert result.status_code is None
        assert result.device_class == DeviceClass.UNKNOWN

    def test_serializes(self) -> None:
        payload = fingerprint_service(80, "HTTP/1.0 200 OK\r\nServer: nginx\r\n\r\n").to_dict()
        assert payload["protocol"] == "http"
        assert payload["status_code"] == 200


class TestPortSets:
    def test_industrial_ports_are_not_in_the_default_sweep(self) -> None:
        # The routine scan must never reach control systems by default.
        assert not set(DEFAULT_IOT_PORTS) & set(INDUSTRIAL_PORTS)

    def test_industrial_ports_cover_the_major_protocols(self) -> None:
        assert set(INDUSTRIAL_PORTS) == {102, 502, 20000, 47808}
