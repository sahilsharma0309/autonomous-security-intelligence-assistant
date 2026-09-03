"""IoT reconnaissance tools.

Registers asset discovery as ``@tool``s so the planner orders them and the
dispatcher's authorization gate covers them, exactly as the OSINT collectors
are covered. Nothing here re-implements a scope check: the gate above the
dispatcher is the only one, so a tool author cannot forget it.

Risk classification
-------------------

===========================  ==========  =====================================
Tool                         Risk        Why
===========================  ==========  =====================================
``iot.shodan_host``          PASSIVE     Queries Shodan's index; never the target
``iot.shodan_search``        PASSIVE     Same, for a search query
``iot.scan``                 ACTIVE      TCP connect + banner grab on the target
``iot.stream_probe``         ACTIVE      HEAD/OPTIONS against HTTP/RTSP endpoints
``iot.control_port_probe``   INTRUSIVE   Touches PLC/BAS control ports at all
===========================  ==========  =====================================

The last one is the reason ``INTRUSIVE`` exists as a level. Opening a TCP
connection to a Modbus or S7 port is not dangerous in the way that *speaking*
those protocols is -- and this tool never sends a byte to them -- but control
systems are unforgiving enough that merely touching them should require an
engagement that opted in explicitly. A default ``ACTIVE`` scope will not run it.

Every tool reaches its I/O through an injectable provider in
``ToolContext.config``:

=====================  ==========================
Context key            Provider protocol
=====================  ==========================
``iot_search_client``  ``IoTSearchClient``
``tcp_probe``          ``TcpProbe``
=====================  ==========================
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from typing import Any

from security_assistant.core.tool import ToolParameter, tool
from security_assistant.core.types import RiskLevel, ToolCategory, ToolContext
from security_assistant.iot.fingerprints import DEFAULT_IOT_PORTS, INDUSTRIAL_PORTS
from security_assistant.iot.models import (
    DiscoveredDevice,
    assets_to_graph_elements,
    merge_devices,
    summarize,
)
from security_assistant.iot.shodan_client import (
    IoTSearchClient,
    ShodanError,
    default_search_client,
    parse_shodan_host,
    parse_shodan_search,
)
from security_assistant.iot.stream_discovery import (
    AsyncioTcpProbe,
    ScanConfig,
    TcpProbe,
    discover_device,
)
from security_assistant.osint.collectors.base import CollectorError, provider_from
from security_assistant.osint.models import normalize_host

logger = logging.getLogger(__name__)

__all__ = [
    "ALL_IOT_TOOLS",
    "control_port_probe",
    "iot_scan",
    "shodan_host",
    "shodan_search",
    "stream_probe",
]

#: Endpoints worth checking when looking specifically for exposed streams and
#: web interfaces (cameras, NVRs, embedded admin panels).
STREAM_PORTS: tuple[int, ...] = (80, 443, 554, 8000, 8080, 8443, 8554, 8888)

_MAX_PORTS_PER_SCAN = 128
_MAX_SEARCH_LIMIT = 500


def _default_probe() -> TcpProbe:
    return AsyncioTcpProbe()


def _project(devices: Sequence[DiscoveredDevice], source: str) -> dict[str, Any]:
    """Build the standard tool payload: findings plus graph elements."""
    entities, relationships = assets_to_graph_elements(devices, source=source)
    return {
        "devices": [d.to_dict() for d in devices],
        "summary": summarize(devices),
        "entities": [e.to_dict() for e in entities],
        "relationships": [r.to_dict() for r in relationships],
    }


def _coerce_ports(raw: Sequence[Any] | None, fallback: Sequence[int]) -> list[int]:
    """Validate a caller-supplied port list."""
    if not raw:
        return list(fallback)

    ports: list[int] = []
    for item in raw:
        if isinstance(item, bool) or not isinstance(item, (int, str)):
            raise CollectorError(f"Invalid port value: {item!r}")
        try:
            port = int(item)
        except (TypeError, ValueError) as exc:
            raise CollectorError(f"Invalid port value: {item!r}") from exc
        if not 1 <= port <= 65535:
            raise CollectorError(f"Port out of range: {port}")
        ports.append(port)

    if len(ports) > _MAX_PORTS_PER_SCAN:
        raise CollectorError(
            f"Refusing to scan {len(ports)} ports in one call; the limit is {_MAX_PORTS_PER_SCAN}"
        )
    return sorted(set(ports))


# --------------------------------------------------------------------------- #
# Index lookups (PASSIVE -- never contacts the target)
# --------------------------------------------------------------------------- #
@tool(
    name="iot.shodan_host",
    description=(
        "Look up an address in the Shodan index and return the devices and "
        "services it recorded, without contacting the target."
    ),
    category=ToolCategory.OSINT,
    risk=RiskLevel.PASSIVE,
    parameters=[ToolParameter("target", str, description="IP address to look up")],
    timeout_seconds=45.0,
    rate_limit_per_minute=55.0,
    produces=["assets", "services"],
    tags=["iot", "shodan", "index"],
)
async def shodan_host(ctx: ToolContext, target: str) -> dict[str, Any]:
    """Fetch what the index knows about ``target``."""
    try:
        host = normalize_host(target)
    except ValueError as exc:
        raise CollectorError(f"Invalid host {target!r}: {exc}") from exc

    client: IoTSearchClient = provider_from(ctx, "iot_search_client", default_search_client)
    try:
        payload = await client.host(host)
    except ShodanError as exc:
        raise CollectorError(str(exc)) from exc

    device = parse_shodan_host(payload)
    devices = [device] if device is not None else []
    result = _project(devices, "iot.shodan_host")
    # An empty index record is a valid answer, not a failure -- say so plainly
    # so it is not read as "nothing is exposed".
    result["indexed"] = device is not None
    if device is None:
        result["note"] = f"The index holds no record for {host}."
    return result


@tool(
    name="iot.shodan_search",
    description=(
        "Run a Shodan search query and return matching devices. Results come "
        "from the index; the target is never contacted."
    ),
    category=ToolCategory.OSINT,
    risk=RiskLevel.PASSIVE,
    parameters=[
        ToolParameter("target", str, description="Authorized scope this search belongs to"),
        ToolParameter("query", str, description="Shodan search query"),
        ToolParameter("limit", int, required=False, default=100, description="Maximum results"),
    ],
    timeout_seconds=60.0,
    rate_limit_per_minute=30.0,
    produces=["assets", "services"],
    tags=["iot", "shodan", "index"],
)
async def shodan_search(
    ctx: ToolContext, target: str, query: str, limit: int = 100
) -> dict[str, Any]:
    """Search the index, anchored to an authorized engagement scope.

    ``target`` is the authorized asset the search relates to. A Shodan query
    is free text and cannot itself be scope-checked, so binding the call to a
    scoped target keeps index searching inside a declared engagement -- the
    same pattern ``osint.social`` uses for usernames.

    Results are *not* filtered to the scope: a search legitimately discovers
    assets the operator did not know they had. They are returned as index
    findings, and any live follow-up goes through ``iot.scan``, which is
    scope-checked per host.
    """
    if not query.strip():
        raise CollectorError("Search query must not be empty")
    if not 1 <= limit <= _MAX_SEARCH_LIMIT:
        raise CollectorError(f"limit must be between 1 and {_MAX_SEARCH_LIMIT}")

    client: IoTSearchClient = provider_from(ctx, "iot_search_client", default_search_client)
    try:
        payload = await client.search(query.strip(), limit=limit)
    except ShodanError as exc:
        raise CollectorError(str(exc)) from exc

    devices = parse_shodan_search(payload)
    result = _project(devices, "iot.shodan_search")
    result["query"] = query.strip()
    result["total"] = int(payload.get("total", len(devices)) or 0)
    result["scope_anchor"] = target
    return result


# --------------------------------------------------------------------------- #
# Live discovery (ACTIVE -- contacts the target)
# --------------------------------------------------------------------------- #
@tool(
    name="iot.scan",
    description=(
        "TCP connect-scan an authorized host across common IoT ports, grab "
        "banners, and fingerprint the device."
    ),
    category=ToolCategory.SCANNING,
    risk=RiskLevel.ACTIVE,
    parameters=[
        ToolParameter("target", str, description="Host or IP to scan"),
        ToolParameter(
            "ports",
            list,
            required=False,
            description="Ports to scan; defaults to common IoT ports",
        ),
        ToolParameter(
            "connect_timeout",
            float,
            required=False,
            default=3.0,
            description="Per-port connect timeout in seconds",
        ),
    ],
    timeout_seconds=180.0,
    rate_limit_per_minute=20.0,
    produces=["assets", "services", "banners"],
    tags=["iot", "scan", "active"],
)
async def iot_scan(
    ctx: ToolContext,
    target: str,
    ports: Sequence[Any] | None = None,
    connect_timeout: float = 3.0,
) -> dict[str, Any]:
    """Connect-scan ``target`` and fingerprint whatever answers.

    Industrial control ports are excluded here even if explicitly listed;
    reaching them requires ``iot.control_port_probe`` and an ``INTRUSIVE``
    engagement.
    """
    try:
        host = normalize_host(target)
    except ValueError as exc:
        raise CollectorError(f"Invalid host {target!r}: {exc}") from exc

    requested = _coerce_ports(ports, DEFAULT_IOT_PORTS)
    excluded = sorted(set(requested) & set(INDUSTRIAL_PORTS))
    if connect_timeout <= 0:
        raise CollectorError("connect_timeout must be positive")

    config = ScanConfig(
        connect_timeout=connect_timeout,
        read_timeout=connect_timeout,
        ports=requested,
        include_industrial=False,
    )
    probe = provider_from(ctx, "tcp_probe", _default_probe)
    device = await discover_device(host, probe, config, source="iot.scan")

    result = _project([device], "iot.scan")
    result["ports_scanned"] = config.effective_ports()
    if excluded:
        result["excluded_control_ports"] = excluded
        result["note"] = (
            f"Control ports {excluded} were not scanned. Use "
            "iot.control_port_probe within an INTRUSIVE-authorized engagement."
        )
    return result


@tool(
    name="iot.stream_probe",
    description=(
        "Check authorized HTTP and RTSP endpoints for exposure, reporting "
        "whether each demands authentication. Retrieves no stream or page "
        "content."
    ),
    category=ToolCategory.SCANNING,
    risk=RiskLevel.ACTIVE,
    parameters=[
        ToolParameter("target", str, description="Host or IP to probe"),
        ToolParameter(
            "ports",
            list,
            required=False,
            description="Endpoint ports; defaults to common stream/web ports",
        ),
    ],
    timeout_seconds=120.0,
    rate_limit_per_minute=20.0,
    produces=["assets", "services", "exposures"],
    consumes=["assets"],
    tags=["iot", "stream", "camera", "active"],
)
async def stream_probe(
    ctx: ToolContext, target: str, ports: Sequence[Any] | None = None
) -> dict[str, Any]:
    """Determine whether stream and web endpoints enforce authentication.

    Sends ``HEAD`` to HTTP endpoints and ``OPTIONS`` to RTSP ones -- enough to
    establish that an endpoint exists and whether it challenges for
    credentials. It never issues ``GET``, ``DESCRIBE`` or ``PLAY``, so no page
    body is downloaded and no media session is ever opened.

    The finding is the exposure, not the footage.
    """
    try:
        host = normalize_host(target)
    except ValueError as exc:
        raise CollectorError(f"Invalid host {target!r}: {exc}") from exc

    requested = _coerce_ports(ports, STREAM_PORTS)
    config = ScanConfig(ports=requested, include_industrial=False)
    probe = provider_from(ctx, "tcp_probe", _default_probe)
    device = await discover_device(host, probe, config, source="iot.stream_probe")

    unauthenticated = [s.to_dict() for s in device.unauthenticated_services]
    result = _project([device], "iot.stream_probe")
    result["unauthenticated_endpoints"] = unauthenticated
    result["content_retrieved"] = False
    """Always false: this tool inspects headers only, by design."""
    if unauthenticated:
        result["finding"] = (
            f"{len(unauthenticated)} endpoint(s) on {host} responded without "
            "requiring authentication."
        )
    return result


# --------------------------------------------------------------------------- #
# Control systems (INTRUSIVE -- requires explicit opt-in)
# --------------------------------------------------------------------------- #
@tool(
    name="iot.control_port_probe",
    description=(
        "Check whether industrial/building-automation control ports (Modbus, "
        "S7, DNP3, BACnet) are reachable. Opens a connection and closes it "
        "without sending any protocol data."
    ),
    category=ToolCategory.SCANNING,
    risk=RiskLevel.INTRUSIVE,
    parameters=[
        ToolParameter("target", str, description="Host or IP to check"),
        ToolParameter(
            "ports",
            list,
            required=False,
            description="Control ports; defaults to Modbus/S7/DNP3/BACnet",
        ),
    ],
    timeout_seconds=120.0,
    rate_limit_per_minute=10.0,
    produces=["assets", "services", "control_systems"],
    tags=["iot", "ics", "intrusive"],
)
async def control_port_probe(
    ctx: ToolContext, target: str, ports: Sequence[Any] | None = None
) -> dict[str, Any]:
    """Report reachability of control ports, without speaking their protocols.

    Classified ``INTRUSIVE`` deliberately. The probe itself is minimal -- a
    TCP connect and an immediate close, with no protocol bytes sent, because
    malformed input to a PLC can have physical consequences. But control
    systems are unforgiving enough that touching them at all should require an
    engagement that opted in, rather than riding along with a routine scan.
    """
    try:
        host = normalize_host(target)
    except ValueError as exc:
        raise CollectorError(f"Invalid host {target!r}: {exc}") from exc

    requested = _coerce_ports(ports, INDUSTRIAL_PORTS)
    non_control = sorted(set(requested) - set(INDUSTRIAL_PORTS))
    if non_control:
        raise CollectorError(
            f"iot.control_port_probe only handles control ports; {non_control} belong to iot.scan"
        )

    config = ScanConfig(ports=requested, include_industrial=True)
    probe = provider_from(ctx, "tcp_probe", _default_probe)
    device = await discover_device(host, probe, config, source="iot.control_port_probe")

    reachable = [s.to_dict() for s in device.services]
    result = _project([device], "iot.control_port_probe")
    result["reachable_control_ports"] = [s["port"] for s in reachable]
    result["protocol_data_sent"] = False
    if reachable:
        result["finding"] = (
            f"{len(reachable)} control port(s) on {host} are reachable. "
            "Exposed control systems warrant immediate review."
        )
    return result


#: Every IoT tool, ready for ``ToolRegistry.register_all``.
ALL_IOT_TOOLS = (
    shodan_host,
    shodan_search,
    iot_scan,
    stream_probe,
    control_port_probe,
)


def devices_from_results(payloads: Sequence[dict[str, Any]]) -> list[DiscoveredDevice]:
    """Fold several tool payloads into one deduplicated device list."""
    from security_assistant.iot.models import devices_from_mappings

    collected: list[DiscoveredDevice] = []
    for payload in payloads:
        if isinstance(payload, dict):
            collected.extend(devices_from_mappings(payload.get("devices", []) or []))
    return merge_devices(collected)
