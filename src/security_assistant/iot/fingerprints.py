"""Service and device fingerprinting.

Turns a port number and a banner into a protocol guess, a device class, and a
vendor. Kept in its own module with no I/O so the classification rules are
testable directly -- this is where the domain knowledge lives, and it is the
part most likely to need tuning against real data.

Two rules govern how confident the output is allowed to be:

**A port number is a hint, not an identification.** Port 554 is
conventionally RTSP, but anything may listen anywhere. The port only seeds a
guess that banner evidence can override.

**A banner is self-reported.** Any device can claim to be anything, so a
vendor or model derived from banner text is evidence, never proof. Nothing
here returns certainty, and callers score banner-derived facts below directly
observed ones.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from security_assistant.iot.models import DeviceClass, ServiceProtocol

__all__ = [
    "DEFAULT_IOT_PORTS",
    "INDUSTRIAL_PORTS",
    "Fingerprint",
    "classify_device",
    "extract_vendor",
    "fingerprint_service",
    "protocol_for_port",
]

#: Conventional protocol per port. A starting guess only.
_PORT_PROTOCOLS: dict[int, str] = {
    21: ServiceProtocol.FTP,
    22: ServiceProtocol.SSH,
    23: ServiceProtocol.TELNET,
    80: ServiceProtocol.HTTP,
    443: ServiceProtocol.HTTPS,
    554: ServiceProtocol.RTSP,
    1883: ServiceProtocol.MQTT,
    1900: ServiceProtocol.UPNP,
    5683: ServiceProtocol.COAP,
    8000: ServiceProtocol.HTTP,
    8080: ServiceProtocol.HTTP,
    8081: ServiceProtocol.HTTP,
    8443: ServiceProtocol.HTTPS,
    8554: ServiceProtocol.RTSP,
    8888: ServiceProtocol.HTTP,
    # Industrial / building automation
    102: ServiceProtocol.S7,
    502: ServiceProtocol.MODBUS,
    20000: ServiceProtocol.DNP3,
    47808: ServiceProtocol.BACNET,
}

#: Ports worth checking on a general IoT sweep.
DEFAULT_IOT_PORTS: tuple[int, ...] = (
    21, 22, 23, 80, 443, 554, 1883, 8000, 8080, 8443, 8554, 8888,
)

#: Industrial and building-automation control ports.
#:
#: These are called out separately because they front systems where an
#: ill-considered probe has physical consequences. Tools that touch them
#: classify higher on the risk scale.
INDUSTRIAL_PORTS: tuple[int, ...] = (102, 502, 20000, 47808)

# Banner substring -> device class. Ordered most specific first; the first
# match wins, so "hikvision" beats a bare "server" hint.
_DEVICE_PATTERNS: tuple[tuple[str, str], ...] = (
    ("hikvision", DeviceClass.IP_CAMERA),
    ("dahua", DeviceClass.IP_CAMERA),
    ("axis", DeviceClass.IP_CAMERA),
    ("foscam", DeviceClass.IP_CAMERA),
    ("vivotek", DeviceClass.IP_CAMERA),
    ("mobotix", DeviceClass.IP_CAMERA),
    ("ubiquiti", DeviceClass.IP_CAMERA),
    ("netcam", DeviceClass.IP_CAMERA),
    ("ipcamera", DeviceClass.IP_CAMERA),
    ("ip camera", DeviceClass.IP_CAMERA),
    ("webcam", DeviceClass.IP_CAMERA),
    ("gsoap", DeviceClass.IP_CAMERA),  # ONVIF stack, near-ubiquitous on cameras
    ("onvif", DeviceClass.IP_CAMERA),
    ("nvr", DeviceClass.NVR),
    ("dvr", DeviceClass.NVR),
    ("surveillance", DeviceClass.NVR),
    ("mikrotik", DeviceClass.ROUTER),
    ("routeros", DeviceClass.ROUTER),
    ("dd-wrt", DeviceClass.ROUTER),
    ("openwrt", DeviceClass.ROUTER),
    ("draytek", DeviceClass.ROUTER),
    ("tp-link", DeviceClass.ROUTER),
    ("netgear", DeviceClass.ROUTER),
    ("router", DeviceClass.ROUTER),
    ("jetdirect", DeviceClass.PRINTER),
    ("printer", DeviceClass.PRINTER),
    ("cups", DeviceClass.PRINTER),
    ("synology", DeviceClass.NAS),
    ("qnap", DeviceClass.NAS),
    ("freenas", DeviceClass.NAS),
    ("truenas", DeviceClass.NAS),
    ("siemens", DeviceClass.INDUSTRIAL),
    ("simatic", DeviceClass.INDUSTRIAL),
    ("modbus", DeviceClass.INDUSTRIAL),
    ("schneider", DeviceClass.INDUSTRIAL),
    ("allen-bradley", DeviceClass.INDUSTRIAL),
    ("rockwell", DeviceClass.INDUSTRIAL),
    ("bacnet", DeviceClass.BUILDING_AUTOMATION),
    ("niagara", DeviceClass.BUILDING_AUTOMATION),
    ("tridium", DeviceClass.BUILDING_AUTOMATION),
    ("plex", DeviceClass.MEDIA),
    ("kodi", DeviceClass.MEDIA),
    ("sonos", DeviceClass.MEDIA),
)

# Protocols that, on their own, imply a device category.
_PROTOCOL_CLASSES: dict[str, str] = {
    ServiceProtocol.RTSP: DeviceClass.IP_CAMERA,
    ServiceProtocol.MODBUS: DeviceClass.INDUSTRIAL,
    ServiceProtocol.S7: DeviceClass.INDUSTRIAL,
    ServiceProtocol.DNP3: DeviceClass.INDUSTRIAL,
    ServiceProtocol.BACNET: DeviceClass.BUILDING_AUTOMATION,
}

_VENDORS: tuple[str, ...] = (
    "hikvision", "dahua", "axis", "foscam", "vivotek", "mobotix", "ubiquiti",
    "mikrotik", "tp-link", "netgear", "draytek", "synology", "qnap", "siemens",
    "schneider", "rockwell", "honeywell", "bosch", "panasonic", "sony",
    "d-link", "linksys", "asus", "zyxel", "tenda", "reolink", "amcrest",
)

_SERVER_HEADER_RE = re.compile(r"^server:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
_RTSP_SERVER_RE = re.compile(r"^(?:server|public):\s*(.+)$", re.IGNORECASE | re.MULTILINE)
_WWW_AUTH_RE = re.compile(r"^www-authenticate:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
_STATUS_RE = re.compile(r"^(?:HTTP|RTSP)/\d\.\d\s+(\d{3})", re.IGNORECASE)
_VERSION_RE = re.compile(r"[/ ]v?(\d+(?:\.\d+){1,3})")


def protocol_for_port(port: int, transport: str = "tcp") -> str:
    """Conventional protocol for ``port``, or the transport name.

    >>> protocol_for_port(554)
    'rtsp'
    >>> protocol_for_port(9999)
    'tcp'
    """
    if transport.lower() == "udp" and port not in _PORT_PROTOCOLS:
        return "udp"
    return _PORT_PROTOCOLS.get(port, transport.lower())


def extract_vendor(banner: str) -> str:
    """Best-guess vendor name from banner text, or ``""``.

    >>> extract_vendor("Server: Hikvision-Webs")
    'hikvision'
    """
    lowered = banner.casefold()
    for vendor in _VENDORS:
        if vendor in lowered:
            return vendor
    return ""


def classify_device(banner: str, protocol: str = "", port: int = 0) -> str:
    """Classify a device from banner text, protocol, and port.

    Banner evidence wins over protocol convention, which wins over nothing:

    >>> classify_device("Server: Hikvision-Webs", "http", 80)
    'ip_camera'
    >>> classify_device("", "rtsp", 554)
    'ip_camera'
    >>> classify_device("", "tcp", 9999)
    'unknown'
    """
    lowered = banner.casefold()
    for needle, device_class in _DEVICE_PATTERNS:
        if needle in lowered:
            return device_class

    by_protocol = _PROTOCOL_CLASSES.get(protocol.lower())
    if by_protocol is not None:
        return by_protocol

    if port in INDUSTRIAL_PORTS:
        return DeviceClass.INDUSTRIAL
    return DeviceClass.UNKNOWN


@dataclass(frozen=True, slots=True)
class Fingerprint:
    """What a banner revealed about a service."""

    protocol: str
    device_class: str
    vendor: str = ""
    product: str = ""
    version: str = ""
    status_code: int | None = None
    requires_auth: bool | None = None
    """``True``/``False`` when the response settles it; ``None`` when unknown."""

    def to_dict(self) -> dict[str, object]:
        return {
            "protocol": self.protocol,
            "device_class": self.device_class,
            "vendor": self.vendor,
            "product": self.product,
            "version": self.version,
            "status_code": self.status_code,
            "requires_auth": self.requires_auth,
        }


def fingerprint_service(port: int, banner: str, transport: str = "tcp") -> Fingerprint:
    """Derive a :class:`Fingerprint` from a port and its banner.

    ``requires_auth`` is the field an assessment actually turns on, so it is
    only set when the response genuinely settles the question: a 401/403 means
    authentication is enforced, a 200 on a protocol that should be protected
    means it is not, and anything else stays ``None`` rather than guessing.
    """
    protocol = protocol_for_port(port, transport)
    product = ""

    header_match = _SERVER_HEADER_RE.search(banner) or _RTSP_SERVER_RE.search(banner)
    if header_match:
        product = header_match.group(1).strip()

    version = ""
    if product:
        version_match = _VERSION_RE.search(product)
        if version_match:
            version = version_match.group(1)

    status_code: int | None = None
    status_match = _STATUS_RE.search(banner)
    if status_match:
        status_code = int(status_match.group(1))

    requires_auth: bool | None = None
    if _WWW_AUTH_RE.search(banner) or status_code in (401, 407):
        requires_auth = True
    elif status_code in (200, 204):
        requires_auth = False
    elif status_code == 403:
        # Forbidden means access control exists, even if not a credential
        # prompt -- reported as protected rather than open.
        requires_auth = True

    return Fingerprint(
        protocol=protocol,
        device_class=classify_device(banner, protocol, port),
        vendor=extract_vendor(banner),
        product=product,
        version=version,
        status_code=status_code,
        requires_auth=requires_auth,
    )
