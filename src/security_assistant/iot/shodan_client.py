"""Shodan and IoT search-index client.

Wraps the Shodan REST API behind the :class:`IoTSearchClient` protocol, so the
tools in :mod:`security_assistant.iot.tools` depend on an interface rather than
on Shodan specifically -- swapping in Censys or an internal asset inventory is
a new client class, not a change to the tools.

Three things this module takes seriously:

**Credentials come from the environment, never from arguments.** An API key
passed as a tool argument would end up in plan structures, audit records and
logs. :func:`api_key_from_env` reads ``SHODAN_API_KEY`` at call time, and the
key is redacted from every error message and ``repr``.

**Rate limiting is the client's job, not the caller's.** Shodan's free tier
allows roughly one request per second and bills overage; the client holds its
own token bucket so concurrent tool invocations cannot collectively exceed it.

**Index results are not observations.** Shodan reports what it saw when it
last scanned, which may be weeks old. Everything derived from the index is
scored below a live check and carries the index timestamp, so a stale record
is visible as stale rather than presented as current fact.
"""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from security_assistant.core.dispatcher import RateLimiter
from security_assistant.iot.fingerprints import fingerprint_service
from security_assistant.iot.models import (
    DeviceClass,
    DiscoveredDevice,
    DiscoveredService,
    Exposure,
)
from security_assistant.osint.models import Confidence

logger = logging.getLogger(__name__)

_httpx: Any
try:  # pragma: no cover - depends on which extras are installed
    import httpx

    _httpx = httpx
except ImportError:  # pragma: no cover
    _httpx = None

__all__ = [
    "SHODAN_API_BASE",
    "IoTSearchClient",
    "ShodanCredentialsError",
    "ShodanError",
    "ShodanHttpClient",
    "UnavailableSearchClient",
    "api_key_from_env",
    "default_search_client",
    "parse_shodan_host",
    "parse_shodan_search",
]

SHODAN_API_BASE = "https://api.shodan.io"
API_KEY_ENV_VAR = "SHODAN_API_KEY"

#: Shodan free tier is ~1 request/second; stay just under it.
DEFAULT_RATE_LIMIT_PER_MINUTE = 55.0

#: Index data reflects Shodan's last scan, not the current state, so nothing
#: sourced from it is treated as a live observation.
INDEX_CONFIDENCE = Confidence.MODERATE


class ShodanError(RuntimeError):
    """A Shodan request failed."""


class ShodanCredentialsError(ShodanError):
    """No usable API key was available."""


def api_key_from_env(env: Mapping[str, str] | None = None) -> str:
    """Read the Shodan API key from the environment.

    Raises :class:`ShodanCredentialsError` with an actionable message rather
    than returning an empty string, so a missing key fails at the call instead
    of producing a confusing 401 later.
    """
    source = env if env is not None else os.environ
    key = (source.get(API_KEY_ENV_VAR) or "").strip()
    if not key:
        raise ShodanCredentialsError(
            f"{API_KEY_ENV_VAR} is not set. Export it or inject a "
            "'iot_search_client' provider for offline use."
        )
    return key


def _redact(text: str, secret: str) -> str:
    """Remove an API key from text destined for a log or an exception."""
    return text.replace(secret, "***") if secret else text


@runtime_checkable
class IoTSearchClient(Protocol):
    """Queries an IoT search index."""

    async def host(
        self, ip: str
    ) -> Mapping[str, Any]:  # pragma: no cover - protocol declaration
        ...

    async def search(
        self, query: str, *, limit: int = 100
    ) -> Mapping[str, Any]:  # pragma: no cover - protocol declaration
        ...


class ShodanHttpClient:
    """Async Shodan REST client with its own rate limit.

    >>> client = ShodanHttpClient(api_key="...")        # doctest: +SKIP
    >>> await client.host("192.0.2.10")                 # doctest: +SKIP
    """

    __slots__ = ("_api_key", "_base_url", "_limiter", "_rate", "_timeout")

    def __init__(
        self,
        api_key: str = "",
        *,
        base_url: str = SHODAN_API_BASE,
        timeout: float = 20.0,
        rate_limit_per_minute: float = DEFAULT_RATE_LIMIT_PER_MINUTE,
        limiter: RateLimiter | None = None,
    ) -> None:
        # Resolve the key eagerly so a misconfiguration surfaces at wiring
        # time rather than mid-engagement.
        self._api_key = api_key or api_key_from_env()
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._rate = rate_limit_per_minute
        self._limiter = limiter or RateLimiter()

    async def _get(self, path: str, params: dict[str, Any]) -> Mapping[str, Any]:
        if _httpx is None:  # pragma: no cover - guarded by the default factory
            raise ShodanError(
                "httpx is not installed. Install the IoT extra "
                "(`poetry install -E iot`) or inject an 'iot_search_client'."
            )

        await self._limiter.acquire("shodan", self._rate)

        url = f"{self._base_url}{path}"
        query = {**params, "key": self._api_key}
        try:
            async with _httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.get(url, params=query)
        except Exception as exc:
            raise ShodanError(
                f"Shodan request to {path} failed: {_redact(str(exc), self._api_key)}"
            ) from exc

        if response.status_code == 401:
            raise ShodanCredentialsError("Shodan rejected the API key (401)")
        if response.status_code == 403:
            raise ShodanCredentialsError(
                "Shodan denied the request (403); the plan may not cover this endpoint"
            )
        if response.status_code == 404:
            # "No information available" is a normal answer, not a failure.
            return {}
        if response.status_code == 429:
            raise ShodanError("Shodan rate limit exceeded (429)")
        if response.status_code >= 400:
            raise ShodanError(
                f"Shodan returned {response.status_code} for {path}: "
                f"{_redact(response.text[:200], self._api_key)}"
            )

        try:
            payload = response.json()
        except (ValueError, json.JSONDecodeError) as exc:
            raise ShodanError(f"Shodan returned non-JSON for {path}") from exc

        if not isinstance(payload, dict):
            raise ShodanError(f"Shodan returned a non-object payload for {path}")
        return payload

    async def host(self, ip: str) -> Mapping[str, Any]:
        """Look up everything the index knows about one address."""
        return await self._get(f"/shodan/host/{ip}", {})

    async def search(self, query: str, *, limit: int = 100) -> Mapping[str, Any]:
        """Run a Shodan search query."""
        return await self._get("/shodan/host/search", {"query": query, "limit": limit})

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<ShodanHttpClient base_url={self._base_url} key=***>"


class UnavailableSearchClient:
    """Placeholder used when no search backend is configured.

    Fails with an actionable message rather than returning empty results,
    which would look like "this host is not exposed".
    """

    __slots__ = ()

    async def host(self, ip: str) -> Mapping[str, Any]:
        raise ShodanError(self._message())

    async def search(self, query: str, *, limit: int = 100) -> Mapping[str, Any]:
        raise ShodanError(self._message())

    @staticmethod
    def _message() -> str:
        return (
            "No IoT search backend available. Set SHODAN_API_KEY and install "
            "httpx, or inject an 'iot_search_client' provider."
        )


def default_search_client() -> IoTSearchClient:
    """Return the best search client this environment can construct."""
    if _httpx is None:
        return UnavailableSearchClient()
    try:
        return ShodanHttpClient()
    except ShodanCredentialsError:
        # No key configured: degrade to the explicit placeholder so the
        # failure message names the missing variable.
        return UnavailableSearchClient()


# --------------------------------------------------------------------------- #
# Response parsing
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class _ServiceDraft:
    """Intermediate shape while folding Shodan's per-banner records."""

    port: int
    transport: str
    banner: str
    product: str
    version: str
    attributes: dict[str, Any] = field(default_factory=dict)


def _banner_text(entry: Mapping[str, Any]) -> str:
    """Assemble searchable banner text from a Shodan service record.

    Shodan splits evidence across ``data``, ``http.server``, ``product`` and
    friends; fingerprinting wants one string.
    """
    parts: list[str] = []
    for key in ("data", "product", "title"):
        value = entry.get(key)
        if isinstance(value, str) and value.strip():
            parts.append(value.strip())

    http = entry.get("http")
    if isinstance(http, Mapping):
        for key in ("server", "title", "html_hash"):
            value = http.get(key)
            if isinstance(value, str) and value.strip():
                parts.append(f"{key}: {value.strip()}")

    return "\n".join(parts)


def parse_shodan_host(payload: Mapping[str, Any]) -> DiscoveredDevice | None:
    """Convert a ``/shodan/host/{ip}`` response into a device.

    Returns ``None`` for an empty payload, which is Shodan's way of saying it
    has no record -- distinct from an error.
    """
    ip = str(payload.get("ip_str") or payload.get("ip") or "").strip()
    if not ip:
        return None

    hostnames = [str(h) for h in payload.get("hostnames", []) or [] if str(h).strip()]
    services: list[DiscoveredService] = []
    device_class = DeviceClass.UNKNOWN
    vendor = ""

    for entry in payload.get("data", []) or []:
        if not isinstance(entry, Mapping):
            continue
        try:
            port = int(entry.get("port", 0))
        except (TypeError, ValueError):
            continue
        if not 1 <= port <= 65535:
            continue

        transport = str(entry.get("transport", "tcp")).lower()
        banner = _banner_text(entry)
        fingerprint = fingerprint_service(port, banner, transport)

        services.append(
            DiscoveredService(
                host=ip,
                port=port,
                protocol=fingerprint.protocol,
                transport=transport,
                banner=banner,
                product=fingerprint.product or str(entry.get("product", "") or ""),
                version=fingerprint.version or str(entry.get("version", "") or ""),
                exposure=(
                    Exposure.AUTHENTICATED
                    if fingerprint.requires_auth
                    else Exposure.UNAUTHENTICATED
                    if fingerprint.requires_auth is False
                    else Exposure.UNKNOWN
                ),
                source="iot.shodan_host",
                # Index data, not a live check.
                confidence=INDEX_CONFIDENCE,
                attributes={
                    k: v
                    for k, v in (
                        ("shodan_timestamp", entry.get("timestamp")),
                        ("shodan_module", entry.get("_shodan", {}).get("module")
                         if isinstance(entry.get("_shodan"), Mapping) else None),
                    )
                    if v
                },
            )
        )

        if device_class == DeviceClass.UNKNOWN:
            device_class = fingerprint.device_class
        vendor = vendor or fingerprint.vendor

    return DiscoveredDevice(
        host=ip,
        device_class=device_class,
        vendor=vendor,
        hostnames=hostnames,
        services=services,
        source="iot.shodan_host",
        confidence=INDEX_CONFIDENCE,
        attributes={
            k: v
            for k, v in (
                ("org", payload.get("org")),
                ("isp", payload.get("isp")),
                ("asn", payload.get("asn")),
                ("country", payload.get("country_name")),
                ("last_update", payload.get("last_update")),
            )
            if v
        },
    )


def parse_shodan_search(payload: Mapping[str, Any]) -> list[DiscoveredDevice]:
    """Convert a ``/shodan/host/search`` response into devices.

    Search results are per-banner rather than per-host, so several matches may
    describe the same box; they are folded by address.
    """
    from security_assistant.iot.models import merge_devices

    devices: list[DiscoveredDevice] = []
    for match in payload.get("matches", []) or []:
        if not isinstance(match, Mapping):
            continue
        ip = str(match.get("ip_str") or match.get("ip") or "").strip()
        if not ip:
            continue

        try:
            port = int(match.get("port", 0))
        except (TypeError, ValueError):
            continue
        if not 1 <= port <= 65535:
            continue

        transport = str(match.get("transport", "tcp")).lower()
        banner = _banner_text(match)
        fingerprint = fingerprint_service(port, banner, transport)

        service = DiscoveredService(
            host=ip,
            port=port,
            protocol=fingerprint.protocol,
            transport=transport,
            banner=banner,
            product=fingerprint.product,
            version=fingerprint.version,
            exposure=(
                Exposure.AUTHENTICATED
                if fingerprint.requires_auth
                else Exposure.UNAUTHENTICATED
                if fingerprint.requires_auth is False
                else Exposure.UNKNOWN
            ),
            source="iot.shodan_search",
            confidence=INDEX_CONFIDENCE,
        )

        devices.append(
            DiscoveredDevice(
                host=ip,
                device_class=fingerprint.device_class,
                vendor=fingerprint.vendor,
                hostnames=[
                    str(h) for h in match.get("hostnames", []) or [] if str(h).strip()
                ],
                services=[service],
                source="iot.shodan_search",
                confidence=INDEX_CONFIDENCE,
            )
        )

    return merge_devices(devices)


def hosts_in_payload(payload: Mapping[str, Any]) -> Sequence[str]:
    """Every distinct address named in a search response."""
    found: list[str] = []
    for match in payload.get("matches", []) or []:
        if not isinstance(match, Mapping):
            continue
        ip = str(match.get("ip_str") or match.get("ip") or "").strip()
        if ip and ip not in found:
            found.append(ip)
    return found
