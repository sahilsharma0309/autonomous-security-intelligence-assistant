"""Social alias and username footprinting hooks.

Checks whether a username exists on a set of platforms and records the
resulting handles in the graph.

Design notes, because this collector needs more care than the others:

**It ships with no platforms configured.** There is no built-in list of social
networks. The operator registers the platforms to check, explicitly, for the
engagement at hand; with none registered the tool returns an empty result and
says so. Username enumeration across platforms is the part of OSINT most
easily turned against an individual, and a tool that arrives pre-loaded with
thirty sites invites exactly that. Making the target set a deliberate act
keeps the blast radius something the operator chose.

**It is scope-gated on the engagement, not the handle.** A username is not a
hostname, so the dispatcher's target check cannot be applied to it directly.
The ``target`` argument is therefore the authorized engagement domain, and the
handle is footprinted in that context. Enumeration is consequently only
possible inside an engagement whose scope the operator has already declared.

**Existence checks are inference, not observation.** An HTTP 200 on a profile
URL means a page rendered, which is weaker evidence than a DNS answer: many
platforms return 200 for a "user not found" page, and some soft-block
automated requests. Findings are recorded at :attr:`Confidence.MODERATE`
accordingly, and the raw status code is kept for review.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from security_assistant.core.tool import ToolParameter, tool
from security_assistant.core.types import RiskLevel, ToolCategory, ToolContext
from security_assistant.osint.collectors.base import CollectorError, provider_from
from security_assistant.osint.models import (
    Confidence,
    EdgeType,
    Entity,
    EntityType,
    Relationship,
    looks_like_email,
    normalize_domain,
    normalize_social_handle,
)

logger = logging.getLogger(__name__)

_httpx: Any
try:  # pragma: no cover - depends on which extras are installed
    import httpx

    _httpx = httpx
except ImportError:  # pragma: no cover
    _httpx = None

__all__ = [
    "HttpxProfileProbe",
    "PlatformHook",
    "ProbeOutcome",
    "ProfileProbe",
    "UnavailableProfileProbe",
    "default_profile_probe",
    "platforms_from_config",
    "social_footprint",
]

_USERNAME_MAX = 128


@dataclass(frozen=True, slots=True)
class PlatformHook:
    """One platform to check for a username.

    ``url_template`` must contain a single ``{username}`` placeholder::

        PlatformHook(name="examplehub", url_template="https://examplehub.test/u/{username}")
    """

    name: str
    url_template: str
    exists_statuses: tuple[int, ...] = (200,)
    absent_statuses: tuple[int, ...] = (404, 410)
    enabled: bool = True

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("Platform hook name must not be empty")
        if "{username}" not in self.url_template:
            raise ValueError(
                f"Platform {self.name!r} url_template must contain a "
                "'{username}' placeholder"
            )

    def url_for(self, username: str) -> str:
        """Render the profile URL for ``username``."""
        from urllib.parse import quote

        return self.url_template.format(username=quote(username, safe=""))

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> PlatformHook:
        """Build a hook from configuration (e.g. parsed YAML)."""
        name = raw.get("name")
        template = raw.get("url_template") or raw.get("url")
        if not name or not template:
            raise ValueError(
                f"Platform hook requires 'name' and 'url_template': {dict(raw)!r}"
            )
        return cls(
            name=str(name),
            url_template=str(template),
            exists_statuses=tuple(int(s) for s in raw.get("exists_statuses", (200,))),
            absent_statuses=tuple(int(s) for s in raw.get("absent_statuses", (404, 410))),
            enabled=bool(raw.get("enabled", True)),
        )


@dataclass(frozen=True, slots=True)
class ProbeOutcome:
    """The result of checking one profile URL."""

    url: str
    status: int
    error: str | None = None

    @property
    def reachable(self) -> bool:
        return self.error is None


@runtime_checkable
class ProfileProbe(Protocol):
    """Checks whether a profile URL exists."""

    async def probe(self, url: str) -> ProbeOutcome:  # pragma: no cover - protocol
        ...


class HttpxProfileProbe:
    """Profile probe backed by ``httpx``.

    Issues a ``GET`` without following redirects, so a platform that redirects
    unknown users to a sign-up page is not mistaken for a hit.
    """

    __slots__ = ("_timeout", "_user_agent")

    def __init__(self, timeout: float = 10.0, user_agent: str = "") -> None:
        self._timeout = timeout
        self._user_agent = user_agent or "security-assistant-osint/1.0"

    async def probe(self, url: str) -> ProbeOutcome:
        if _httpx is None:  # pragma: no cover - guarded by the default factory
            raise CollectorError("httpx is not installed")
        try:
            async with _httpx.AsyncClient(
                timeout=self._timeout,
                follow_redirects=False,
                headers={"User-Agent": self._user_agent},
            ) as client:
                response = await client.get(url)
                return ProbeOutcome(url=url, status=int(response.status_code))
        except Exception as exc:  # noqa: BLE001 - httpx raises many types
            return ProbeOutcome(url=url, status=0, error=str(exc))


class UnavailableProfileProbe:
    """Placeholder used when no HTTP client is installed."""

    __slots__ = ()

    async def probe(self, url: str) -> ProbeOutcome:
        raise CollectorError(
            "No HTTP client available for profile probing. Install httpx or "
            "inject a 'profile_probe' provider."
        )


def default_profile_probe() -> ProfileProbe:
    """Return the best profile probe available in this environment."""
    if _httpx is not None:  # pragma: no cover - requires the extra
        return HttpxProfileProbe()
    return UnavailableProfileProbe()


def platforms_from_config(raw: Any) -> list[PlatformHook]:
    """Build platform hooks from configuration.

    Accepts already-built :class:`PlatformHook` objects or mappings. Returns an
    empty list for ``None``, which is the default and means "check nothing".
    """
    if raw is None:
        return []
    if isinstance(raw, PlatformHook):
        return [raw]
    if not isinstance(raw, Iterable) or isinstance(raw, (str, bytes, Mapping)):
        raise CollectorError(
            f"social_platforms must be a list of platform hooks, got {type(raw).__name__}"
        )

    hooks: list[PlatformHook] = []
    for item in raw:
        if isinstance(item, PlatformHook):
            hooks.append(item)
        elif isinstance(item, Mapping):
            try:
                hooks.append(PlatformHook.from_mapping(item))
            except ValueError as exc:
                raise CollectorError(str(exc)) from exc
        else:
            raise CollectorError(
                f"Cannot interpret social platform entry: {item!r}"
            )
    return hooks


@dataclass(slots=True)
class HandleFinding:
    """One platform's verdict for a username."""

    platform: str
    username: str
    url: str
    status: int
    exists: bool
    inconclusive: bool = False
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "platform": self.platform,
            "username": self.username,
            "url": self.url,
            "status": self.status,
            "exists": self.exists,
            "inconclusive": self.inconclusive,
            "error": self.error,
        }


@dataclass(slots=True)
class FootprintResult:
    """The full outcome of a footprinting run."""

    username: str
    engagement_target: str
    configured: bool = False
    findings: list[HandleFinding] = field(default_factory=list)
    note: str = ""

    @property
    def found(self) -> list[HandleFinding]:
        return [f for f in self.findings if f.exists]

    def to_dict(self) -> dict[str, Any]:
        return {
            "username": self.username,
            "engagement_target": self.engagement_target,
            "configured": self.configured,
            "platforms_checked": len(self.findings),
            "handles_found": len(self.found),
            "findings": [f.to_dict() for f in self.findings],
            "note": self.note,
        }


def findings_to_graph_elements(
    result: FootprintResult, *, source: str = "osint.social"
) -> tuple[list[Entity], list[Relationship]]:
    """Convert confirmed handles into graph entities and relationships."""
    entities: list[Entity] = []
    relationships: list[Relationship] = []

    try:
        root = Entity.create(
            EntityType.DOMAIN,
            result.engagement_target,
            source=source,
            detail="engagement context",
        )
    except ValueError as exc:  # pragma: no cover - validated upstream
        raise CollectorError(f"Invalid engagement target: {exc}") from exc
    entities.append(root)

    for finding in result.found:
        try:
            handle = Entity.create(
                EntityType.SOCIAL_HANDLE,
                normalize_social_handle(finding.username, finding.platform),
                source=source,
                detail=f"profile found on {finding.platform}",
                attributes={"platform": finding.platform, "url": finding.url},
            )
        except ValueError:
            logger.debug("Skipping unparseable handle %r", finding.username)
            continue
        entities.append(handle)
        relationships.append(
            Relationship.create(
                root,
                handle,
                EdgeType.HAS_HANDLE,
                # A rendered profile page is inference, not observation.
                confidence=Confidence.MODERATE,
                source_tool=source,
                detail=f"profile responded {finding.status} on {finding.platform}",
            )
        )

    return entities, relationships


@tool(
    name="osint.social",
    description=(
        "Check a username against explicitly configured social platforms and "
        "record confirmed handles. No platforms are configured by default."
    ),
    category=ToolCategory.OSINT,
    risk=RiskLevel.ACTIVE,
    parameters=[
        ToolParameter(
            "target",
            str,
            description="Authorized engagement domain this footprinting belongs to",
        ),
        ToolParameter("username", str, description="Username or alias to check"),
        ToolParameter(
            "platforms",
            list,
            required=False,
            description="Platform hooks to check; defaults to the configured set",
        ),
    ],
    timeout_seconds=60.0,
    rate_limit_per_minute=30.0,
    produces=["handles"],
    tags=["osint", "social"],
)
async def social_footprint(
    ctx: ToolContext,
    target: str,
    username: str,
    platforms: Sequence[Any] | None = None,
) -> dict[str, Any]:
    """Footprint ``username`` across the configured platforms."""
    try:
        engagement_target = normalize_domain(target)
    except ValueError as exc:
        raise CollectorError(f"Invalid engagement target {target!r}: {exc}") from exc

    handle = username.strip().lstrip("@")
    if not handle:
        raise CollectorError("Username must not be empty")
    if len(handle) > _USERNAME_MAX:
        raise CollectorError(f"Username exceeds {_USERNAME_MAX} characters")

    hooks = [
        hook
        for hook in platforms_from_config(
            platforms if platforms is not None else ctx.config.get("social_platforms")
        )
        if hook.enabled
    ]

    result = FootprintResult(
        username=handle, engagement_target=engagement_target, configured=bool(hooks)
    )

    if not hooks:
        result.note = (
            "No social platforms configured. Register platform hooks via the "
            "'social_platforms' context key or the tool's 'platforms' argument "
            "to enable footprinting."
        )
        logger.info("osint.social ran with no configured platforms; nothing checked")
        return {**result.to_dict(), "entities": [], "relationships": []}

    probe = provider_from(ctx, "profile_probe", default_profile_probe)

    for hook in hooks:
        url = hook.url_for(handle)
        outcome = await probe.probe(url)

        if not outcome.reachable:
            result.findings.append(
                HandleFinding(
                    platform=hook.name,
                    username=handle,
                    url=url,
                    status=outcome.status,
                    exists=False,
                    inconclusive=True,
                    error=outcome.error,
                )
            )
            continue

        exists = outcome.status in hook.exists_statuses
        absent = outcome.status in hook.absent_statuses
        result.findings.append(
            HandleFinding(
                platform=hook.name,
                username=handle,
                url=url,
                status=outcome.status,
                exists=exists,
                # Anything that is neither an expected hit nor an expected miss
                # (rate limiting, a redirect, a soft block) is reported as
                # inconclusive rather than silently counted as "not found".
                inconclusive=not exists and not absent,
            )
        )

    entities, relationships = findings_to_graph_elements(result)
    return {
        **result.to_dict(),
        "entities": [e.to_dict() for e in entities],
        "relationships": [r.to_dict() for r in relationships],
    }


def handle_looks_like_email(value: str) -> bool:
    """Whether an alias is actually an email address."""
    return looks_like_email(value)
