"""Live device, service, and stream-endpoint discovery.

Connect-scans authorized hosts, grabs banners, and determines whether exposed
HTTP and RTSP endpoints demand authentication. Built on :mod:`asyncio` and
nothing else, so it is fully functional with no optional dependencies.

Scope of what this does -- and deliberately does not -- do
---------------------------------------------------------

**It detects exposure. It never retrieves content.** For an HTTP endpoint it
sends ``HEAD``, not ``GET``; for RTSP it sends ``OPTIONS``, never ``DESCRIBE``
or ``PLAY``. Both reveal exactly the thing an assessment needs -- the endpoint
exists, and here is whether it enforces authentication -- while retrieving no
page body and setting up no media session.

That line is deliberate. "This camera is reachable from the internet with no
credentials" is the entire finding; watching the feed adds nothing to the
assessment and is the part that harms the people in front of the lens. The
module therefore has no code path that fetches a stream, and the RTSP prober
stops at the capability handshake.

**Industrial control ports are probed by connection only.** For the ports in
:data:`~security_assistant.iot.fingerprints.INDUSTRIAL_PORTS` -- Modbus, S7,
DNP3, BACnet -- the scanner opens a TCP connection, records that it opened,
and closes it without sending a single protocol byte. Malformed or unexpected
input to a PLC can have physical consequences, so the tool that touches these
is classified ``INTRUSIVE`` and never speaks their protocols.

**Concurrency is bounded and connections are always closed.** A scan that
exhausts file descriptors or leaves sockets in ``CLOSE_WAIT`` on the target is
its own kind of incident.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from security_assistant.iot.fingerprints import (
    DEFAULT_IOT_PORTS,
    INDUSTRIAL_PORTS,
    fingerprint_service,
    protocol_for_port,
)
from security_assistant.iot.models import (
    DeviceClass,
    DiscoveredDevice,
    DiscoveredService,
    Exposure,
    ServiceProtocol,
)
from security_assistant.osint.models import Confidence, normalize_host

logger = logging.getLogger(__name__)

__all__ = [
    "AsyncioTcpProbe",
    "ProbeResult",
    "ScanConfig",
    "TcpProbe",
    "build_probe_payload",
    "discover_device",
    "scan_host",
]

#: Never read more than this from a banner: the peer controls the bytes.
MAX_BANNER_BYTES = 4096

_USER_AGENT = "security-assistant-iot/1.0"


@dataclass(frozen=True, slots=True)
class ProbeResult:
    """The outcome of probing one port."""

    host: str
    port: int
    is_open: bool
    banner: str = ""
    error: str | None = None
    elapsed_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "is_open": self.is_open,
            "banner": self.banner,
            "error": self.error,
            "elapsed_ms": round(self.elapsed_ms, 2),
        }


@runtime_checkable
class TcpProbe(Protocol):
    """Opens a TCP connection and optionally exchanges a probe payload."""

    async def probe(
        self, host: str, port: int, payload: bytes = b""
    ) -> ProbeResult:  # pragma: no cover - protocol declaration
        ...


@dataclass(slots=True)
class ScanConfig:
    """Tunables for a scan."""

    connect_timeout: float = 3.0
    read_timeout: float = 3.0
    max_concurrency: int = 32
    ports: Sequence[int] = field(default_factory=lambda: list(DEFAULT_IOT_PORTS))
    include_industrial: bool = False
    """Whether to touch PLC/BAS control ports at all. Off by default."""

    def __post_init__(self) -> None:
        if self.connect_timeout <= 0 or self.read_timeout <= 0:
            raise ValueError("Timeouts must be positive")
        if self.max_concurrency < 1:
            raise ValueError("max_concurrency must be >= 1")
        for port in self.ports:
            if not 1 <= int(port) <= 65535:
                raise ValueError(f"Port out of range: {port}")

    def effective_ports(self) -> list[int]:
        """Ports to scan, with industrial ports filtered unless enabled."""
        ports = [int(p) for p in self.ports]
        if not self.include_industrial:
            ports = [p for p in ports if p not in INDUSTRIAL_PORTS]
        # Deduplicate while keeping a stable, predictable order.
        return sorted(set(ports))


class AsyncioTcpProbe:
    """TCP prober built on :mod:`asyncio` streams."""

    __slots__ = ("_connect_timeout", "_read_timeout")

    def __init__(self, connect_timeout: float = 3.0, read_timeout: float = 3.0) -> None:
        self._connect_timeout = connect_timeout
        self._read_timeout = read_timeout

    async def probe(self, host: str, port: int, payload: bytes = b"") -> ProbeResult:
        started = time.monotonic()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=self._connect_timeout
            )
        except TimeoutError:
            return ProbeResult(
                host,
                port,
                False,
                error="connect timeout",
                elapsed_ms=(time.monotonic() - started) * 1000,
            )
        except OSError as exc:
            return ProbeResult(
                host,
                port,
                False,
                error=f"{type(exc).__name__}: {exc}",
                elapsed_ms=(time.monotonic() - started) * 1000,
            )

        banner = ""
        error: str | None = None
        try:
            if payload:
                writer.write(payload)
                await asyncio.wait_for(writer.drain(), timeout=self._read_timeout)

            # A server that speaks first (SSH, FTP, Telnet) yields a banner
            # with no payload sent; one that does not simply times out, which
            # is a normal outcome rather than an error.
            try:
                raw = await asyncio.wait_for(
                    reader.read(MAX_BANNER_BYTES), timeout=self._read_timeout
                )
                banner = raw.decode("utf-8", errors="replace").strip()
            except TimeoutError:
                banner = ""
        except OSError as exc:
            error = f"{type(exc).__name__}: {exc}"
        finally:
            writer.close()
            with contextlib.suppress(OSError, asyncio.TimeoutError, TimeoutError):
                await asyncio.wait_for(writer.wait_closed(), timeout=self._read_timeout)

        return ProbeResult(
            host=host,
            port=port,
            is_open=True,
            banner=banner,
            error=error,
            elapsed_ms=(time.monotonic() - started) * 1000,
        )


def build_probe_payload(host: str, port: int) -> bytes:
    """Return the bytes to send when probing ``port``, possibly none.

    The choice of payload is the safety-relevant part of this module:

    * **Industrial control ports get nothing.** Connect, observe, disconnect.
      Speaking Modbus or S7 to a live PLC is not something a discovery tool
      should do.
    * **HTTP gets ``HEAD``**, which returns status and headers -- enough to
      tell whether authentication is enforced -- and no body.
    * **RTSP gets ``OPTIONS``**, the capability handshake. Not ``DESCRIBE``,
      which returns the media description, and not ``PLAY``, which would open
      a stream.
    * **Everything else gets nothing**, letting servers that speak first
      identify themselves on their own.
    """
    if port in INDUSTRIAL_PORTS:
        return b""

    protocol = protocol_for_port(port)

    if protocol in (ServiceProtocol.HTTP, ServiceProtocol.HTTPS):
        return (
            f"HEAD / HTTP/1.0\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {_USER_AGENT}\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()

    if protocol == ServiceProtocol.RTSP:
        return (
            f"OPTIONS rtsp://{host}:{port}/ RTSP/1.0\r\n"
            f"CSeq: 1\r\n"
            f"User-Agent: {_USER_AGENT}\r\n\r\n"
        ).encode()

    return b""


def _exposure_from(banner: str, requires_auth: bool | None, port: int) -> str:
    """Decide how exposed a service is from what it said."""
    if not banner:
        return Exposure.UNKNOWN
    if requires_auth is True:
        return Exposure.AUTHENTICATED
    if requires_auth is False:
        return Exposure.UNAUTHENTICATED
    # Industrial ports answer without any HTTP-style status; an open control
    # port is reported as unknown rather than guessed either way.
    if port in INDUSTRIAL_PORTS:
        return Exposure.UNKNOWN
    return Exposure.UNKNOWN


async def scan_host(
    host: str,
    probe: TcpProbe,
    config: ScanConfig | None = None,
) -> list[ProbeResult]:
    """Connect-scan ``host`` across the configured ports, concurrently."""
    settings = config or ScanConfig()
    normalized = normalize_host(host)
    ports = settings.effective_ports()

    semaphore = asyncio.Semaphore(settings.max_concurrency)

    async def one(port: int) -> ProbeResult:
        async with semaphore:
            payload = build_probe_payload(normalized, port)
            try:
                return await probe.probe(normalized, port, payload)
            except Exception as exc:  # noqa: BLE001 - one port must not sink the scan
                logger.debug("Probe of %s:%d raised: %s", normalized, port, exc)
                return ProbeResult(normalized, port, False, error=f"{type(exc).__name__}: {exc}")

    results = await asyncio.gather(*(one(p) for p in ports))
    return list(results)


async def discover_device(
    host: str,
    probe: TcpProbe,
    config: ScanConfig | None = None,
    *,
    source: str = "iot.scan",
) -> DiscoveredDevice:
    """Scan a host and assemble a :class:`DiscoveredDevice` from what answered."""
    settings = config or ScanConfig()
    normalized = normalize_host(host)
    results = await scan_host(normalized, probe, settings)

    services: list[DiscoveredService] = []
    device_class = DeviceClass.UNKNOWN
    vendor = ""
    model = ""

    for result in results:
        if not result.is_open:
            continue

        fingerprint = fingerprint_service(result.port, result.banner)
        services.append(
            DiscoveredService(
                host=normalized,
                port=result.port,
                protocol=fingerprint.protocol,
                transport="tcp",
                banner=result.banner,
                product=fingerprint.product,
                version=fingerprint.version,
                exposure=_exposure_from(result.banner, fingerprint.requires_auth, result.port),
                source=source,
                # A completed TCP connect is a direct observation.
                confidence=Confidence.OBSERVED,
                attributes={
                    k: v
                    for k, v in (
                        ("status_code", fingerprint.status_code),
                        ("elapsed_ms", round(result.elapsed_ms, 2)),
                        ("probe_error", result.error),
                        (
                            "control_port",
                            True if result.port in INDUSTRIAL_PORTS else None,
                        ),
                    )
                    if v is not None
                },
            )
        )

        if device_class == DeviceClass.UNKNOWN:
            device_class = fingerprint.device_class
        vendor = vendor or fingerprint.vendor
        model = model or fingerprint.product

    return DiscoveredDevice(
        host=normalized,
        device_class=device_class,
        vendor=vendor,
        model=model,
        services=services,
        source=source,
        confidence=Confidence.OBSERVED if services else Confidence.WEAK,
        attributes={
            "ports_scanned": len(results),
            "ports_open": len(services),
        },
    )


async def discover_many(
    hosts: Sequence[str],
    probe: TcpProbe,
    config: ScanConfig | None = None,
    *,
    max_hosts_in_parallel: int = 8,
    source: str = "iot.scan",
) -> list[DiscoveredDevice]:
    """Scan several hosts, bounding how many run at once."""
    settings = config or ScanConfig()
    semaphore = asyncio.Semaphore(max(1, max_hosts_in_parallel))

    async def one(host: str) -> DiscoveredDevice | None:
        async with semaphore:
            try:
                return await discover_device(host, probe, settings, source=source)
            except ValueError as exc:
                logger.debug("Skipping unscannable host %r: %s", host, exc)
                return None

    found = await asyncio.gather(*(one(h) for h in hosts))
    return [d for d in found if d is not None]
