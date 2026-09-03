"""VirusTotal client and response parsing.

**Risk classification: PASSIVE.** Every call here asks VirusTotal what it
already knows. Nothing in this module contacts the indicator being asked
about, so it is available to passive-only engagements.

The public API allows 4 requests/minute, which is low enough that exceeding
it is the normal failure mode rather than an edge case. The client therefore
carries its own token bucket sized for that tier, independent of the
dispatcher's per-tool limit: the dispatcher protects the *target*, this
protects the *credential*, and a burst of tool calls that the dispatcher is
happy to allow can still exhaust an API quota.

``VIRUSTOTAL_API_KEY`` is read from the environment at call time and never
accepted as a tool argument, so it cannot end up in a plan, an audit record,
or a log line. It is redacted from error text.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import os
import time
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, Protocol, runtime_checkable

from security_assistant.threat.models import ReputationVerdict

logger = logging.getLogger(__name__)

_httpx: Any
try:  # pragma: no cover - depends on which extras are installed
    import httpx

    _httpx = httpx
except ImportError:  # pragma: no cover
    _httpx = None

__all__ = [
    "API_KEY_ENV_VAR",
    "PUBLIC_TIER_PER_MINUTE",
    "TokenBucket",
    "UnavailableVirusTotalClient",
    "VirusTotalClient",
    "VirusTotalCredentialsError",
    "VirusTotalError",
    "VirusTotalHttpClient",
    "api_key_from_env",
    "default_virustotal_client",
    "parse_domain_report",
    "parse_file_report",
    "parse_ip_report",
    "parse_url_report",
    "url_identifier",
]

API_KEY_ENV_VAR = "VIRUSTOTAL_API_KEY"
API_BASE = "https://www.virustotal.com/api/v3"
PUBLIC_TIER_PER_MINUTE = 4.0


class VirusTotalError(RuntimeError):
    """A VirusTotal lookup could not be completed."""


class VirusTotalCredentialsError(VirusTotalError):
    """No API key is configured."""


def api_key_from_env(env: Mapping[str, str] | None = None) -> str:
    """Read the API key from the environment.

    Read at call time rather than import time so a key added after start-up
    is picked up, and so tests can supply one without touching global state.
    """
    source = env if env is not None else os.environ
    key = (source.get(API_KEY_ENV_VAR) or "").strip()
    if not key:
        raise VirusTotalCredentialsError(
            f"{API_KEY_ENV_VAR} is not set. Export it or inject a "
            "'virustotal_client' provider."
        )
    return key


def _redact(text: str, secret: str) -> str:
    """Remove an API key from text bound for a log or an error."""
    if secret and secret in text:
        return text.replace(secret, "***redacted***")
    return text


class TokenBucket:
    """A simple async token bucket.

    Refills continuously at ``rate`` tokens per minute up to ``capacity``.
    Callers await :meth:`acquire`, so a burst is smoothed into compliance
    rather than rejected -- the alternative, failing the call, turns a quota
    limit into a lost lookup.
    """

    __slots__ = ("_capacity", "_lock", "_rate_per_second", "_tokens", "_updated")

    def __init__(self, rate_per_minute: float, capacity: float | None = None) -> None:
        if rate_per_minute <= 0:
            raise ValueError("rate_per_minute must be positive")
        self._rate_per_second = rate_per_minute / 60.0
        self._capacity = capacity if capacity is not None else rate_per_minute
        self._tokens = self._capacity
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, tokens: float = 1.0) -> float:
        """Wait until ``tokens`` are available; return the seconds waited."""
        if tokens > self._capacity:
            raise ValueError(
                f"Cannot acquire {tokens} tokens from a bucket of capacity "
                f"{self._capacity}"
            )
        waited = 0.0
        async with self._lock:
            while True:
                now = time.monotonic()
                elapsed = now - self._updated
                self._updated = now
                self._tokens = min(
                    self._capacity, self._tokens + elapsed * self._rate_per_second
                )
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return waited
                deficit = tokens - self._tokens
                delay = deficit / self._rate_per_second
                waited += delay
                await asyncio.sleep(delay)

    @property
    def available(self) -> float:
        """Approximate tokens available right now (for tests and reporting)."""
        elapsed = time.monotonic() - self._updated
        return min(self._capacity, self._tokens + elapsed * self._rate_per_second)


@runtime_checkable
class VirusTotalClient(Protocol):
    """Fetches a report for one indicator."""

    async def report(
        self, indicator_type: str, indicator: str
    ) -> Mapping[str, Any]:  # pragma: no cover - protocol declaration
        ...


def url_identifier(url: str) -> str:
    """VirusTotal's URL id: unpadded URL-safe base64 of the URL."""
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")


_PATHS = {
    "url": "urls",
    "domain": "domains",
    "ip_address": "ip_addresses",
    "file_hash": "files",
}


class VirusTotalHttpClient:
    """VirusTotal v3 client backed by ``httpx``."""

    __slots__ = ("_api_key", "_base", "_bucket", "_timeout")

    def __init__(
        self,
        api_key: str,
        *,
        timeout: float = 20.0,
        rate_per_minute: float = PUBLIC_TIER_PER_MINUTE,
        base_url: str = API_BASE,
        bucket: TokenBucket | None = None,
    ) -> None:
        self._api_key = api_key
        self._timeout = timeout
        self._base = base_url.rstrip("/")
        self._bucket = bucket or TokenBucket(rate_per_minute)

    async def report(self, indicator_type: str, indicator: str) -> Mapping[str, Any]:
        if _httpx is None:  # pragma: no cover - guarded by the default factory
            raise VirusTotalError("httpx is not installed")

        path = _PATHS.get(indicator_type)
        if path is None:
            raise VirusTotalError(f"Unsupported indicator type: {indicator_type!r}")

        identifier = url_identifier(indicator) if indicator_type == "url" else indicator
        waited = await self._bucket.acquire()
        if waited > 0:
            logger.debug("Throttled VirusTotal request for %.2fs", waited)

        try:
            async with _httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.get(
                    f"{self._base}/{path}/{identifier}",
                    headers={"x-apikey": self._api_key, "accept": "application/json"},
                )
        except Exception as exc:
            raise VirusTotalError(
                f"VirusTotal request failed: {_redact(str(exc), self._api_key)}"
            ) from exc

        if response.status_code == 404:
            # Not an error: VirusTotal simply has no record of this indicator.
            return {}
        if response.status_code == 401:
            raise VirusTotalCredentialsError("VirusTotal rejected the API key")
        if response.status_code == 429:
            raise VirusTotalError("VirusTotal quota exceeded (HTTP 429)")
        if response.status_code >= 400:
            raise VirusTotalError(
                f"VirusTotal returned HTTP {response.status_code}: "
                f"{_redact(response.text[:200], self._api_key)}"
            )

        try:
            payload = response.json()
        except ValueError as exc:
            raise VirusTotalError("VirusTotal returned malformed JSON") from exc
        return dict(payload) if isinstance(payload, dict) else {}

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<VirusTotalHttpClient key=***redacted***>"


class UnavailableVirusTotalClient:
    """Placeholder used when no credentials or HTTP client are available.

    Fails loudly rather than returning an empty report, which would read as
    "VirusTotal knows nothing about this" -- a dangerously reassuring answer
    to give when the truth is that nobody asked.
    """

    __slots__ = ("_reason",)

    def __init__(self, reason: str) -> None:
        self._reason = reason

    async def report(self, indicator_type: str, indicator: str) -> Mapping[str, Any]:
        raise VirusTotalCredentialsError(self._reason)


def default_virustotal_client(
    env: Mapping[str, str] | None = None,
) -> VirusTotalClient:
    """Build the best VirusTotal client this environment allows."""
    if _httpx is None:
        return UnavailableVirusTotalClient(
            "httpx is not installed; install the threat extra "
            "(`poetry install -E threat`) or inject a 'virustotal_client' provider."
        )
    try:
        return VirusTotalHttpClient(api_key_from_env(env))
    except VirusTotalCredentialsError as exc:
        return UnavailableVirusTotalClient(str(exc))


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #
def _attributes(payload: Mapping[str, Any]) -> Mapping[str, Any]:
    data = payload.get("data")
    if isinstance(data, Mapping):
        attributes = data.get("attributes")
        if isinstance(attributes, Mapping):
            return attributes
    return {}


def _analysis_counts(attributes: Mapping[str, Any]) -> tuple[int, int, int, int]:
    stats = attributes.get("last_analysis_stats")
    if not isinstance(stats, Mapping):
        return (0, 0, 0, 0)
    return (
        int(stats.get("malicious", 0) or 0),
        int(stats.get("suspicious", 0) or 0),
        int(stats.get("harmless", 0) or 0),
        int(stats.get("undetected", 0) or 0),
    )


def _timestamp(attributes: Mapping[str, Any], *names: str) -> datetime | None:
    for name in names:
        value = attributes.get(name)
        if isinstance(value, (int, float)) and value > 0:
            return datetime.fromtimestamp(float(value), tz=UTC)
    return None


def _categories(attributes: Mapping[str, Any]) -> tuple[str, ...]:
    raw = attributes.get("categories")
    if not isinstance(raw, Mapping):
        return ()
    found: list[str] = []
    for value in raw.values():
        text = str(value).strip().lower()
        if text and text not in found:
            found.append(text)
    return tuple(sorted(found))


def _verdict(
    payload: Mapping[str, Any], indicator: str, indicator_type: str
) -> ReputationVerdict:
    attributes = _attributes(payload)
    malicious, suspicious, harmless, undetected = _analysis_counts(attributes)
    reputation = attributes.get("reputation")

    return ReputationVerdict(
        source="virustotal",
        indicator=indicator,
        indicator_type=indicator_type,
        malicious=malicious,
        suspicious=suspicious,
        harmless=harmless,
        undetected=undetected,
        categories=_categories(attributes),
        reputation=int(reputation) if isinstance(reputation, (int, float)) else None,
        as_of=_timestamp(attributes, "last_analysis_date", "last_modification_date"),
        raw_verdict="malicious" if malicious else ("suspicious" if suspicious else ""),
    )


def parse_url_report(payload: Mapping[str, Any], url: str) -> ReputationVerdict:
    """Normalize a VirusTotal URL report."""
    return _verdict(payload, url, "url")


def parse_domain_report(payload: Mapping[str, Any], domain: str) -> ReputationVerdict:
    """Normalize a VirusTotal domain report."""
    return _verdict(payload, domain, "domain")


def parse_ip_report(payload: Mapping[str, Any], address: str) -> ReputationVerdict:
    """Normalize a VirusTotal IP report."""
    return _verdict(payload, address, "ip_address")


def parse_file_report(payload: Mapping[str, Any], digest: str) -> ReputationVerdict:
    """Normalize a VirusTotal file report."""
    return _verdict(payload, digest, "file_hash")


def passive_dns(payload: Mapping[str, Any]) -> list[str]:
    """Extract resolved addresses from a domain report, if present.

    VirusTotal exposes passive DNS through a separate relationship endpoint;
    when a caller has fetched it and merged it in, this reads the addresses
    out. Returns an empty list rather than failing when absent.
    """
    attributes = _attributes(payload)
    found: list[str] = []

    resolutions = attributes.get("last_dns_records")
    if isinstance(resolutions, list):
        for record in resolutions:
            if not isinstance(record, Mapping):
                continue
            if str(record.get("type", "")).upper() in {"A", "AAAA"}:
                value = str(record.get("value", "")).strip()
                if value and value not in found:
                    found.append(value)

    relationships = payload.get("relationships")
    if isinstance(relationships, Mapping):
        entry = relationships.get("resolutions")
        if isinstance(entry, Mapping):
            for item in entry.get("data", []) or []:
                if not isinstance(item, Mapping):
                    continue
                value = str(item.get("id", "")).strip()
                # Resolution ids are "<address><domain>"; the useful part is
                # in attributes when the caller asked for them.
                item_attributes = item.get("attributes")
                if isinstance(item_attributes, Mapping):
                    value = str(item_attributes.get("ip_address", value)).strip()
                if value and value not in found:
                    found.append(value)

    return found
