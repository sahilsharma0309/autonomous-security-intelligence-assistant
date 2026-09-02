"""Asset models and their projection into the entity graph.

An IoT reconnaissance run produces two things: **devices** (something answering
at an address) and **services** (an open port on one). This module normalizes
both and projects them into the Module 2 :class:`~security_assistant.osint.graph.EntityGraph`,
so discovered infrastructure and OSINT findings share one picture rather than
sitting in separate inventories.

The join happens at the ``ip_address`` node. A camera found at ``192.0.2.10``
and a domain whose A record points at ``192.0.2.10`` both attach to the same
node, so "which of our hostnames is this exposed camera behind?" becomes a
graph traversal instead of a manual cross-reference.

Confidence reflects how the fact was learned, and the gap is deliberate:

* a completed TCP connect is :attr:`Confidence.OBSERVED` -- the port is open,
  full stop;
* a device *type* or vendor inferred from a banner is at most
  :attr:`Confidence.STRONG`, because banners are self-reported and trivially
  spoofed;
* anything derived from a third-party index rather than a live check inherits
  that index's staleness and is scored lower still.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from security_assistant.osint.models import (
    Confidence,
    EdgeType,
    Entity,
    EntityType,
    Relationship,
    normalize_host,
)

logger = logging.getLogger(__name__)

__all__ = [
    "DeviceClass",
    "DiscoveredDevice",
    "DiscoveredService",
    "Exposure",
    "ServiceProtocol",
    "assets_to_graph_elements",
    "merge_devices",
]


class DeviceClass:
    """Coarse device categories used for triage.

    Plain string constants rather than an enum: fingerprint data is
    open-ended, and a closed enum would force every unrecognized banner into a
    wrong bucket.
    """

    UNKNOWN = "unknown"
    IP_CAMERA = "ip_camera"
    NVR = "nvr"
    ROUTER = "router"
    PRINTER = "printer"
    NAS = "nas"
    INDUSTRIAL = "industrial"
    BUILDING_AUTOMATION = "building_automation"
    MEDIA = "media"
    SERVER = "server"

    ALL = frozenset(
        {
            UNKNOWN, IP_CAMERA, NVR, ROUTER, PRINTER, NAS, INDUSTRIAL,
            BUILDING_AUTOMATION, MEDIA, SERVER,
        }
    )


class ServiceProtocol:
    """Application protocols this module recognizes."""

    HTTP = "http"
    HTTPS = "https"
    RTSP = "rtsp"
    SSH = "ssh"
    TELNET = "telnet"
    FTP = "ftp"
    MODBUS = "modbus"
    S7 = "s7"
    BACNET = "bacnet"
    DNP3 = "dnp3"
    MQTT = "mqtt"
    COAP = "coap"
    UPNP = "upnp"
    TCP = "tcp"


class Exposure:
    """How exposed a discovered service is.

    This is the finding that matters in an assessment: not that a camera
    exists, but that it answers without authentication.
    """

    UNKNOWN = "unknown"
    AUTHENTICATED = "authenticated"
    """The service demanded credentials -- the expected, healthy state."""

    UNAUTHENTICATED = "unauthenticated"
    """The service answered without asking for credentials."""

    ERROR = "error"


@dataclass(slots=True)
class DiscoveredService:
    """One open port on one host."""

    host: str
    port: int
    protocol: str = ServiceProtocol.TCP
    transport: str = "tcp"
    banner: str = ""
    product: str = ""
    version: str = ""
    exposure: str = Exposure.UNKNOWN
    source: str = ""
    confidence: float = Confidence.OBSERVED
    attributes: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not 1 <= self.port <= 65535:
            raise ValueError(f"Port out of range: {self.port}")
        self.host = normalize_host(self.host)
        self.protocol = (self.protocol or ServiceProtocol.TCP).strip().lower()
        self.transport = (self.transport or "tcp").strip().lower()
        # Banners are attacker-controlled text; cap them so one hostile
        # response cannot bloat the graph or a report.
        if len(self.banner) > 2048:
            self.banner = self.banner[:2048] + "...[truncated]"

    @property
    def address(self) -> str:
        """``host:port/protocol`` -- the canonical service identity."""
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{host}:{self.port}/{self.protocol}"

    @property
    def is_unauthenticated(self) -> bool:
        return self.exposure == Exposure.UNAUTHENTICATED

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol,
            "transport": self.transport,
            "address": self.address,
            "banner": self.banner,
            "product": self.product,
            "version": self.version,
            "exposure": self.exposure,
            "source": self.source,
            "confidence": round(self.confidence, 4),
            "attributes": dict(self.attributes),
        }


@dataclass(slots=True)
class DiscoveredDevice:
    """Something answering at an address, with the services it exposes."""

    host: str
    device_class: str = DeviceClass.UNKNOWN
    vendor: str = ""
    model: str = ""
    hostnames: list[str] = field(default_factory=list)
    services: list[DiscoveredService] = field(default_factory=list)
    source: str = ""
    confidence: float = Confidence.OBSERVED
    attributes: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.host = normalize_host(self.host)
        if self.device_class not in DeviceClass.ALL:
            logger.debug("Unrecognized device class %r; recording as-is", self.device_class)

    @property
    def open_ports(self) -> list[int]:
        return sorted({s.port for s in self.services})

    @property
    def unauthenticated_services(self) -> list[DiscoveredService]:
        """The services that answered without demanding credentials."""
        return [s for s in self.services if s.is_unauthenticated]

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "device_class": self.device_class,
            "vendor": self.vendor,
            "model": self.model,
            "hostnames": list(self.hostnames),
            "open_ports": self.open_ports,
            "services": [s.to_dict() for s in self.services],
            "unauthenticated_count": len(self.unauthenticated_services),
            "source": self.source,
            "confidence": round(self.confidence, 4),
            "attributes": dict(self.attributes),
        }


def merge_devices(devices: Iterable[DiscoveredDevice]) -> list[DiscoveredDevice]:
    """Combine devices sharing a host into one record per address.

    Shodan and a live scan will both report the same box; this folds them
    together, unions their services, and prefers the more specific
    classification over ``unknown``.
    """
    by_host: dict[str, DiscoveredDevice] = {}

    for device in devices:
        existing = by_host.get(device.host)
        if existing is None:
            by_host[device.host] = device
            continue

        seen = {s.address for s in existing.services}
        for service in device.services:
            if service.address not in seen:
                existing.services.append(service)
                seen.add(service.address)

        if existing.device_class == DeviceClass.UNKNOWN:
            existing.device_class = device.device_class
        existing.vendor = existing.vendor or device.vendor
        existing.model = existing.model or device.model
        for hostname in device.hostnames:
            if hostname not in existing.hostnames:
                existing.hostnames.append(hostname)
        for key, value in device.attributes.items():
            existing.attributes.setdefault(key, value)
        if device.source and device.source not in existing.source:
            existing.source = f"{existing.source}+{device.source}".strip("+")

    return [by_host[h] for h in sorted(by_host)]


def assets_to_graph_elements(
    devices: Sequence[DiscoveredDevice], *, source: str = "iot"
) -> tuple[list[Entity], list[Relationship]]:
    """Project discovered assets into graph entities and relationships.

    The shape produced per device::

        iot_device --RUNS_ON--> ip_address        (when the host is an IP)
        iot_device --EXPOSES_SERVICE--> network_service
        network_service --SERVICE_ON--> ip_address
        iot_device --MANUFACTURED_BY--> organization   (when a vendor is known)

    Emitting the ``ip_address`` node is what lets an IoT finding meet an OSINT
    finding: a domain that resolves to the same address already attaches
    there, so the two subgraphs connect without any explicit cross-module
    wiring.
    """
    entities: list[Entity] = []
    relationships: list[Relationship] = []

    for device in devices:
        try:
            device_entity = Entity.create(
                EntityType.IOT_DEVICE,
                device.host,
                source=source,
                detail=f"discovered via {device.source or source}",
                confidence=device.confidence,
                attributes={
                    k: v
                    for k, v in (
                        ("device_class", device.device_class),
                        ("vendor", device.vendor or None),
                        ("model", device.model or None),
                        ("open_ports", device.open_ports or None),
                        ("hostnames", device.hostnames or None),
                        ("unauthenticated_services",
                         len(device.unauthenticated_services) or None),
                        *device.attributes.items(),
                    )
                    if v is not None
                },
            )
        except ValueError as exc:
            logger.debug("Skipping device with unusable host %r: %s", device.host, exc)
            continue
        entities.append(device_entity)

        address_entity = _address_entity(device.host, source)
        if address_entity is not None:
            entities.append(address_entity)
            relationships.append(
                Relationship.create(
                    device_entity,
                    address_entity,
                    EdgeType.RUNS_ON,
                    confidence=Confidence.OBSERVED,
                    source_tool=source,
                    detail="device answers at this address",
                )
            )

        # A hostname the device reports is a weaker signal than DNS: it is
        # self-declared, and reverse records are frequently stale.
        for hostname in device.hostnames:
            try:
                domain_entity = Entity.create(
                    EntityType.DOMAIN, hostname, source=source, detail="device hostname"
                )
            except ValueError:
                continue
            entities.append(domain_entity)
            if address_entity is not None:
                relationships.append(
                    Relationship.create(
                        domain_entity,
                        address_entity,
                        EdgeType.RESOLVES_TO,
                        confidence=Confidence.MODERATE,
                        source_tool=source,
                        detail="hostname reported by asset discovery",
                    )
                )

        if device.vendor:
            try:
                vendor_entity = Entity.create(
                    EntityType.ORGANIZATION,
                    device.vendor,
                    source=source,
                    detail="vendor inferred from banner",
                )
            except ValueError:
                vendor_entity = None
            if vendor_entity is not None:
                entities.append(vendor_entity)
                relationships.append(
                    Relationship.create(
                        device_entity,
                        vendor_entity,
                        EdgeType.MANUFACTURED_BY,
                        # Banners are self-reported and trivially spoofed.
                        confidence=Confidence.STRONG,
                        source_tool=source,
                        detail="vendor string in service banner",
                    )
                )

        for service in device.services:
            try:
                service_entity = Entity.create(
                    EntityType.NETWORK_SERVICE,
                    service.address,
                    source=source,
                    detail=f"open {service.protocol} service",
                    confidence=service.confidence,
                    attributes={
                        k: v
                        for k, v in (
                            ("port", service.port),
                            ("protocol", service.protocol),
                            ("transport", service.transport),
                            ("exposure", service.exposure),
                            ("product", service.product or None),
                            ("version", service.version or None),
                            ("banner", service.banner or None),
                            *service.attributes.items(),
                        )
                        if v is not None
                    },
                )
            except ValueError as exc:
                logger.debug("Skipping unusable service %r: %s", service.address, exc)
                continue

            entities.append(service_entity)
            relationships.append(
                Relationship.create(
                    device_entity,
                    service_entity,
                    EdgeType.EXPOSES_SERVICE,
                    confidence=service.confidence,
                    source_tool=source,
                    detail=f"port {service.port}/{service.transport} open",
                )
            )
            if address_entity is not None:
                relationships.append(
                    Relationship.create(
                        service_entity,
                        address_entity,
                        EdgeType.SERVICE_ON,
                        confidence=Confidence.OBSERVED,
                        source_tool=source,
                        detail="service reachable at this address",
                    )
                )

    return entities, relationships


def _address_entity(host: str, source: str) -> Entity | None:
    """Build the ``ip_address`` node for a host, or ``None`` if it is a name.

    A device addressed by hostname has no address node to join on until DNS
    resolution supplies one, which is exactly what ``osint.dns`` produces.
    """
    try:
        return Entity.create(
            EntityType.IP_ADDRESS, host, source=source, detail="asset address"
        )
    except ValueError:
        return None


def summarize(devices: Sequence[DiscoveredDevice]) -> dict[str, Any]:
    """Aggregate counts for a discovery run."""
    by_class: dict[str, int] = {}
    by_protocol: dict[str, int] = {}
    unauthenticated = 0

    for device in devices:
        by_class[device.device_class] = by_class.get(device.device_class, 0) + 1
        for service in device.services:
            by_protocol[service.protocol] = by_protocol.get(service.protocol, 0) + 1
            if service.is_unauthenticated:
                unauthenticated += 1

    return {
        "devices": len(devices),
        "services": sum(len(d.services) for d in devices),
        "unauthenticated_services": unauthenticated,
        "by_device_class": dict(sorted(by_class.items())),
        "by_protocol": dict(sorted(by_protocol.items())),
    }


def devices_from_mappings(raw: Iterable[Mapping[str, Any]]) -> list[DiscoveredDevice]:
    """Rebuild devices from serialized form (e.g. a cached scan result)."""
    devices: list[DiscoveredDevice] = []
    for item in raw:
        services = [
            DiscoveredService(
                host=str(s.get("host", item.get("host", ""))),
                port=int(s["port"]),
                protocol=str(s.get("protocol", ServiceProtocol.TCP)),
                transport=str(s.get("transport", "tcp")),
                banner=str(s.get("banner", "")),
                product=str(s.get("product", "")),
                version=str(s.get("version", "")),
                exposure=str(s.get("exposure", Exposure.UNKNOWN)),
                source=str(s.get("source", "")),
                confidence=float(s.get("confidence", Confidence.OBSERVED)),
                attributes=dict(s.get("attributes", {})),
            )
            for s in item.get("services", []) or []
        ]
        devices.append(
            DiscoveredDevice(
                host=str(item["host"]),
                device_class=str(item.get("device_class", DeviceClass.UNKNOWN)),
                vendor=str(item.get("vendor", "")),
                model=str(item.get("model", "")),
                hostnames=[str(h) for h in item.get("hostnames", []) or []],
                services=services,
                source=str(item.get("source", "")),
                confidence=float(item.get("confidence", Confidence.OBSERVED)),
                attributes=dict(item.get("attributes", {})),
            )
        )
    return devices
