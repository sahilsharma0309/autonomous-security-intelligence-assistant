"""URLScan.io client and response parsing.

URLScan has two modes, and they do not carry the same risk:

* **Search** queries scans that already exist. Nothing is fetched, and the
  URL's owner learns nothing. This is ``PASSIVE``.
* **Submit** asks urlscan.io to load the URL. The target's server receives a
  request and its logs record a visit. That the request comes from urlscan's
  infrastructure rather than ours changes who appears in the logs, not
  whether the target was contacted -- so submission is ``ACTIVE``, and the
  two are separate tools rather than one tool with a flag.

Submission visibility is a second, independent concern. A public submission
is listed on urlscan.io where anyone can read it, so submitting an internal
or client URL can itself disclose an engagement. :class:`SubmitOptions`
therefore defaults to ``unlisted`` and the tool layer makes ``public`` a
deliberate choice.

``URLSCAN_API_KEY`` is read from the environment at call time, never taken as
a tool argument, and redacted from errors.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol, runtime_checkable

from security_assistant.threat.models import RedirectHop, ReputationVerdict
from security_assistant.threat.virustotal import TokenBucket

logger = logging.getLogger(__name__)

_httpx: Any
try:  # pragma: no cover - depends on which extras are installed
    import httpx

    _httpx = httpx
except ImportError:  # pragma: no cover
    _httpx = None

__all__ = [
    "API_KEY_ENV_VAR",
    "SubmitOptions",
    "UnavailableUrlscanClient",
    "UrlscanClient",
    "UrlscanCredentialsError",
    "UrlscanError",
    "UrlscanHttpClient",
    "api_key_from_env",
    "default_urlscan_client",
    "parse_result",
    "parse_search",
]

API_KEY_ENV_VAR = "URLSCAN_API_KEY"
API_BASE = "https://urlscan.io/api/v1"
DEFAULT_PER_MINUTE = 30.0


class UrlscanError(RuntimeError):
    """A URLScan operation could not be completed."""


class UrlscanCredentialsError(UrlscanError):
    """No API key is configured."""


def api_key_from_env(env: Mapping[str, str] | None = None) -> str:
    """Read the API key from the environment at call time."""
    source = env if env is not None else os.environ
    key = (source.get(API_KEY_ENV_VAR) or "").strip()
    if not key:
        raise UrlscanCredentialsError(
            f"{API_KEY_ENV_VAR} is not set. Export it or inject a 'urlscan_client' provider."
        )
    return key


def _redact(text: str, secret: str) -> str:
    if secret and secret in text:
        return text.replace(secret, "***redacted***")
    return text


@dataclass(frozen=True, slots=True)
class SubmitOptions:
    """How a submission should be made.

    ``visibility`` defaults to ``unlisted``: a public scan is published on
    urlscan.io, so defaulting to public would let a routine lookup disclose
    which URLs an engagement is looking at.
    """

    visibility: str = "unlisted"
    tags: tuple[str, ...] = ()
    country: str = ""

    def __post_init__(self) -> None:
        if self.visibility not in {"public", "unlisted", "private"}:
            raise ValueError(
                f"Unknown urlscan visibility {self.visibility!r}; "
                "expected public, unlisted or private"
            )

    def to_payload(self, url: str) -> dict[str, Any]:
        payload: dict[str, Any] = {"url": url, "visibility": self.visibility}
        if self.tags:
            payload["tags"] = list(self.tags)
        if self.country:
            payload["country"] = self.country
        return payload


@runtime_checkable
class UrlscanClient(Protocol):
    """Searches existing scans and submits new ones."""

    async def search(
        self, query: str, *, size: int = 20
    ) -> Mapping[str, Any]:  # pragma: no cover - protocol declaration
        ...

    async def submit(
        self, url: str, options: SubmitOptions
    ) -> Mapping[str, Any]:  # pragma: no cover - protocol declaration
        ...

    async def result(
        self, scan_id: str
    ) -> Mapping[str, Any]:  # pragma: no cover - protocol declaration
        ...


class UrlscanHttpClient:
    """URLScan client backed by ``httpx``."""

    __slots__ = ("_api_key", "_base", "_bucket", "_timeout")

    def __init__(
        self,
        api_key: str,
        *,
        timeout: float = 30.0,
        rate_per_minute: float = DEFAULT_PER_MINUTE,
        base_url: str = API_BASE,
        bucket: TokenBucket | None = None,
    ) -> None:
        self._api_key = api_key
        self._timeout = timeout
        self._base = base_url.rstrip("/")
        self._bucket = bucket or TokenBucket(rate_per_minute)

    async def _request(self, method: str, path: str, **kwargs: Any) -> Mapping[str, Any]:
        if _httpx is None:  # pragma: no cover - guarded by the default factory
            raise UrlscanError("httpx is not installed")

        await self._bucket.acquire()
        headers = {"API-Key": self._api_key, "accept": "application/json"}
        try:
            async with _httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.request(
                    method, f"{self._base}{path}", headers=headers, **kwargs
                )
        except Exception as exc:
            raise UrlscanError(
                f"URLScan request failed: {_redact(str(exc), self._api_key)}"
            ) from exc

        if response.status_code == 404:
            return {}
        if response.status_code in (401, 403):
            raise UrlscanCredentialsError("URLScan rejected the API key")
        if response.status_code == 429:
            raise UrlscanError("URLScan quota exceeded (HTTP 429)")
        if response.status_code >= 400:
            raise UrlscanError(
                f"URLScan returned HTTP {response.status_code}: "
                f"{_redact(response.text[:200], self._api_key)}"
            )

        try:
            payload = response.json()
        except ValueError as exc:
            raise UrlscanError("URLScan returned malformed JSON") from exc
        return dict(payload) if isinstance(payload, dict) else {}

    async def search(self, query: str, *, size: int = 20) -> Mapping[str, Any]:
        return await self._request(
            "GET", "/search/", params={"q": query, "size": max(1, min(size, 100))}
        )

    async def submit(self, url: str, options: SubmitOptions) -> Mapping[str, Any]:
        return await self._request("POST", "/scan/", json=options.to_payload(url))

    async def result(self, scan_id: str) -> Mapping[str, Any]:
        return await self._request("GET", f"/result/{scan_id}/")

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<UrlscanHttpClient key=***redacted***>"


class UnavailableUrlscanClient:
    """Placeholder that fails loudly when URLScan cannot be reached."""

    __slots__ = ("_reason",)

    def __init__(self, reason: str) -> None:
        self._reason = reason

    async def search(self, query: str, *, size: int = 20) -> Mapping[str, Any]:
        raise UrlscanCredentialsError(self._reason)

    async def submit(self, url: str, options: SubmitOptions) -> Mapping[str, Any]:
        raise UrlscanCredentialsError(self._reason)

    async def result(self, scan_id: str) -> Mapping[str, Any]:
        raise UrlscanCredentialsError(self._reason)


def default_urlscan_client(env: Mapping[str, str] | None = None) -> UrlscanClient:
    """Build the best URLScan client this environment allows."""
    if _httpx is None:
        return UnavailableUrlscanClient(
            "httpx is not installed; install the threat extra "
            "(`poetry install -E threat`) or inject a 'urlscan_client' provider."
        )
    try:
        return UrlscanHttpClient(api_key_from_env(env))
    except UrlscanCredentialsError as exc:
        return UnavailableUrlscanClient(str(exc))


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #
def _as_datetime(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def parse_search(payload: Mapping[str, Any], indicator: str) -> ReputationVerdict:
    """Summarize search results into a verdict.

    URLScan search does not return engine counts, so malicious/harmless are
    derived from how many returned scans were flagged. A scan nobody flagged
    is weak evidence of safety, which is why it lands in ``harmless`` rather
    than reducing the score directly.
    """
    results = payload.get("results")
    malicious = 0
    harmless = 0
    categories: list[str] = []
    latest: datetime | None = None

    if isinstance(results, list):
        for item in results:
            if not isinstance(item, Mapping):
                continue
            verdicts = item.get("verdicts")
            flagged = False
            if isinstance(verdicts, Mapping):
                overall = verdicts.get("overall")
                if isinstance(overall, Mapping):
                    flagged = bool(overall.get("malicious"))
                    for tag in overall.get("categories", []) or []:
                        text = str(tag).strip().lower()
                        if text and text not in categories:
                            categories.append(text)
            if flagged:
                malicious += 1
            else:
                harmless += 1

            task = item.get("task")
            if isinstance(task, Mapping):
                seen = _as_datetime(task.get("time"))
                if seen is not None and (latest is None or seen > latest):
                    latest = seen

    return ReputationVerdict(
        source="urlscan",
        indicator=indicator,
        indicator_type="url",
        malicious=malicious,
        harmless=harmless,
        categories=tuple(sorted(categories)),
        as_of=latest,
        raw_verdict="malicious" if malicious else "",
    )


@dataclass(slots=True)
class ScanResult:
    """The useful parts of a completed URLScan result."""

    scan_id: str = ""
    url: str = ""
    final_url: str = ""
    malicious: bool = False
    score: int = 0
    categories: tuple[str, ...] = ()
    chain: list[RedirectHop] = None  # type: ignore[assignment]
    contacted_domains: list[str] = None  # type: ignore[assignment]
    ip_addresses: list[str] = None  # type: ignore[assignment]
    screenshot_url: str = ""
    submitted_at: datetime | None = None

    def __post_init__(self) -> None:
        if self.chain is None:
            self.chain = []
        if self.contacted_domains is None:
            self.contacted_domains = []
        if self.ip_addresses is None:
            self.ip_addresses = []

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "url": self.url,
            "final_url": self.final_url,
            "malicious": self.malicious,
            "score": self.score,
            "categories": list(self.categories),
            "chain": [hop.to_dict() for hop in self.chain],
            "contacted_domains": list(self.contacted_domains),
            "ip_addresses": list(self.ip_addresses),
            "screenshot_url": self.screenshot_url,
            "submitted_at": self.submitted_at.isoformat() if self.submitted_at else None,
        }


def parse_result(payload: Mapping[str, Any]) -> ScanResult:
    """Normalize a URLScan ``/result/`` document."""
    result = ScanResult()

    task = payload.get("task")
    if isinstance(task, Mapping):
        result.scan_id = str(task.get("uuid", "") or "")
        result.url = str(task.get("url", "") or "")
        result.screenshot_url = str(task.get("screenshotURL", "") or "")
        result.submitted_at = _as_datetime(task.get("time"))

    page = payload.get("page")
    if isinstance(page, Mapping):
        result.final_url = str(page.get("url", "") or result.url)

    verdicts = payload.get("verdicts")
    if isinstance(verdicts, Mapping):
        overall = verdicts.get("overall")
        if isinstance(overall, Mapping):
            result.malicious = bool(overall.get("malicious"))
            raw_score = overall.get("score")
            result.score = int(raw_score) if isinstance(raw_score, (int, float)) else 0
            categories: list[str] = []
            for tag in overall.get("categories", []) or []:
                text = str(tag).strip().lower()
                if text and text not in categories:
                    categories.append(text)
            result.categories = tuple(sorted(categories))

    data = payload.get("data")
    if isinstance(data, Mapping):
        for request in data.get("requests", []) or []:
            if not isinstance(request, Mapping):
                continue
            inner = request.get("request")
            if isinstance(inner, Mapping):
                nested = inner.get("request")
                if isinstance(nested, Mapping):
                    hop_url = str(nested.get("url", "") or "")
                    if hop_url and hop_url not in {h.url for h in result.chain}:
                        result.chain.append(RedirectHop(url=hop_url))
            response = request.get("response")
            if isinstance(response, Mapping):
                address = str(response.get("remoteIPAddress", "") or "").strip()
                if address and address not in result.ip_addresses:
                    result.ip_addresses.append(address)

    lists = payload.get("lists")
    if isinstance(lists, Mapping):
        for domain in lists.get("domains", []) or []:
            text = str(domain).strip().lower()
            if text and text not in result.contacted_domains:
                result.contacted_domains.append(text)
        for address in lists.get("ips", []) or []:
            text = str(address).strip()
            if text and text not in result.ip_addresses:
                result.ip_addresses.append(text)

    return result


def result_to_verdict(result: ScanResult) -> ReputationVerdict:
    """Express a completed scan as a reputation verdict."""
    return ReputationVerdict(
        source="urlscan",
        indicator=result.url or result.final_url,
        indicator_type="url",
        malicious=1 if result.malicious else 0,
        harmless=0 if result.malicious else 1,
        categories=result.categories,
        reputation=result.score or None,
        as_of=result.submitted_at,
        raw_verdict="malicious" if result.malicious else "",
    )


def domains_in_results(results: Sequence[ScanResult]) -> list[str]:
    """Every distinct contacted domain across several scans."""
    found: list[str] = []
    for result in results:
        for domain in result.contacted_domains:
            if domain not in found:
                found.append(domain)
    return found


def _utcnow() -> datetime:  # pragma: no cover - trivial
    return datetime.now(tz=UTC)
