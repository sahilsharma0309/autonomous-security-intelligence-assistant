"""IoT & Asset Reconnaissance module.

Discovers devices and services on authorized targets -- via the Shodan index
without touching them, or by live connect-scanning them -- and projects the
results into the Module 2 entity graph as first-class ``iot_device`` and
``network_service`` nodes.

Assets and OSINT findings join at the shared ``ip_address`` node, so a camera
discovered at an address and a domain resolving to that address end up
connected without any cross-module wiring::

    from security_assistant.core import Agent, AuthorizationScope, RiskLevel, ToolRegistry
    from security_assistant.iot import ALL_IOT_TOOLS
    from security_assistant.osint import ALL_COLLECTORS, Correlator, build_graph_from_payloads

    registry = ToolRegistry()
    registry.register_all([*ALL_COLLECTORS, *ALL_IOT_TOOLS])

    scope = AuthorizationScope(
        allow=["example.com", "192.0.2.0/24"],
        max_risk=RiskLevel.ACTIVE,
        authorization_reference="ENG-2024-114",
    )
    result = await Agent(registry, scope).run("Inventory the perimeter", target="192.0.2.10")

    graph = build_graph_from_payloads(result.values_by_tool().values())
    Correlator().correlate(graph)

Risk levels are enforced by the core dispatcher, not by anything here:
index lookups are ``PASSIVE``, live scanning is ``ACTIVE``, and touching
industrial control ports is ``INTRUSIVE`` and needs an engagement that
explicitly opted in.
"""

from __future__ import annotations

from security_assistant.iot.fingerprints import (
    DEFAULT_IOT_PORTS,
    INDUSTRIAL_PORTS,
    Fingerprint,
    classify_device,
    extract_vendor,
    fingerprint_service,
    protocol_for_port,
)
from security_assistant.iot.models import (
    DeviceClass,
    DiscoveredDevice,
    DiscoveredService,
    Exposure,
    ServiceProtocol,
    assets_to_graph_elements,
    merge_devices,
    summarize,
)
from security_assistant.iot.shodan_client import (
    IoTSearchClient,
    ShodanCredentialsError,
    ShodanError,
    ShodanHttpClient,
    UnavailableSearchClient,
    api_key_from_env,
    default_search_client,
    parse_shodan_host,
    parse_shodan_search,
)
from security_assistant.iot.stream_discovery import (
    AsyncioTcpProbe,
    ProbeResult,
    ScanConfig,
    TcpProbe,
    build_probe_payload,
    discover_device,
    discover_many,
    scan_host,
)
from security_assistant.iot.tools import (
    ALL_IOT_TOOLS,
    STREAM_PORTS,
    control_port_probe,
    iot_scan,
    shodan_host,
    shodan_search,
    stream_probe,
)

__all__ = [
    # Tools
    "ALL_IOT_TOOLS",
    "STREAM_PORTS",
    "control_port_probe",
    "iot_scan",
    "shodan_host",
    "shodan_search",
    "stream_probe",
    # Models
    "DeviceClass",
    "DiscoveredDevice",
    "DiscoveredService",
    "Exposure",
    "ServiceProtocol",
    "assets_to_graph_elements",
    "merge_devices",
    "summarize",
    # Fingerprinting
    "DEFAULT_IOT_PORTS",
    "INDUSTRIAL_PORTS",
    "Fingerprint",
    "classify_device",
    "extract_vendor",
    "fingerprint_service",
    "protocol_for_port",
    # Search index
    "IoTSearchClient",
    "ShodanCredentialsError",
    "ShodanError",
    "ShodanHttpClient",
    "UnavailableSearchClient",
    "api_key_from_env",
    "default_search_client",
    "parse_shodan_host",
    "parse_shodan_search",
    # Live discovery
    "AsyncioTcpProbe",
    "ProbeResult",
    "ScanConfig",
    "TcpProbe",
    "build_probe_payload",
    "discover_device",
    "discover_many",
    "scan_host",
]
