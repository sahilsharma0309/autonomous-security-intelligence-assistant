"""WHOIS registration collector.

Reads registration metadata for a domain -- registrar, registrant
organization, contact addresses, key dates -- and maps it into the graph.

**Risk classification: PASSIVE.** A WHOIS query goes to the registry or
registrar, never to the target's own infrastructure, so it meets the "never
contacts the target" bar and is available to passive-only engagements.

WHOIS output is notoriously inconsistent between registries: field names vary,
values arrive as scalars or lists, and redacted records return placeholder
strings rather than nothing. :func:`parse_whois_record` normalizes all of that,
including recognizing GDPR redaction so a privacy-protected domain is reported
as redacted rather than as an organization literally named "REDACTED FOR
PRIVACY".
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol, runtime_checkable

from security_assistant.core.tool import ToolParameter, tool
from security_assistant.core.types import RiskLevel, ToolCategory, ToolContext
from security_assistant.osint.collectors.base import (
    CollectorError,
    provider_from,
    run_blocking,
)
from security_assistant.osint.models import (
    Confidence,
    EdgeType,
    Entity,
    EntityType,
    Relationship,
    looks_like_email,
    normalize_domain,
)

logger = logging.getLogger(__name__)

_whois: Any
try:  # pragma: no cover - depends on which extras are installed
    import whois

    _whois = whois
except ImportError:  # pragma: no cover
    _whois = None

__all__ = [
    "PythonWhoisClient",
    "WhoisClient",
    "WhoisRecord",
    "default_whois_client",
    "parse_whois_record",
    "whois_collect",
]

# Registries return these instead of omitting a redacted field. Treating them
# as real values would create nonsense organization nodes that then correlate
# with every other privacy-protected domain in the graph.
_REDACTION_MARKERS = (
    "redacted",
    "privacy",
    "not disclosed",
    "data protected",
    "gdpr masked",
    "statutory masking enabled",
    "withheld for privacy",
    "domains by proxy",
    "whoisguard",
    "private registration",
)

_ORG_FIELDS = ("org", "organization", "registrant_org", "registrant_organization")
_REGISTRAR_FIELDS = ("registrar", "registrar_name")
_EMAIL_FIELDS = ("emails", "email", "registrant_email", "admin_email", "tech_email")
_NAMESERVER_FIELDS = ("name_servers", "nameservers", "nserver")
_CREATED_FIELDS = ("creation_date", "created", "created_date")
_EXPIRY_FIELDS = ("expiration_date", "expires", "registry_expiry_date")
_UPDATED_FIELDS = ("updated_date", "last_updated")


@runtime_checkable
class WhoisClient(Protocol):
    """Fetches a raw WHOIS record for a domain."""

    async def lookup(
        self, domain: str
    ) -> Mapping[str, Any]:  # pragma: no cover - protocol declaration
        ...


class PythonWhoisClient:
    """WHOIS client backed by the ``python-whois`` package."""

    __slots__ = ()

    async def lookup(self, domain: str) -> Mapping[str, Any]:
        if _whois is None:  # pragma: no cover - guarded by the default factory
            raise CollectorError("python-whois is not installed")
        try:
            record = await run_blocking(_whois.whois, domain)
        except Exception as exc:
            raise CollectorError(f"WHOIS lookup for {domain!r} failed: {exc}") from exc

        if record is None:
            return {}
        # python-whois returns a dict-like object.
        return dict(record) if not isinstance(record, dict) else record


class UnavailableWhoisClient:
    """Placeholder used when no WHOIS backend is installed.

    Fails loudly with an actionable message rather than returning an empty
    record, which would look like a domain with no registration data.
    """

    __slots__ = ()

    async def lookup(self, domain: str) -> Mapping[str, Any]:
        raise CollectorError(
            "No WHOIS backend available. Install the OSINT extra "
            "(`poetry install -E osint`) or inject a 'whois_client' provider."
        )


def default_whois_client() -> WhoisClient:
    """Return the best WHOIS client available in this environment."""
    if _whois is not None:  # pragma: no cover - requires the extra
        return PythonWhoisClient()
    return UnavailableWhoisClient()


def _is_redacted(value: str) -> bool:
    """True when a WHOIS value is a privacy placeholder rather than data."""
    lowered = value.casefold()
    return any(marker in lowered for marker in _REDACTION_MARKERS)


def _first_str(raw: Mapping[str, Any], fields: Sequence[str]) -> str | None:
    """First non-empty, non-redacted string across ``fields``.

    WHOIS values arrive as strings or lists of strings depending on registry.
    """
    for name in fields:
        value = raw.get(name)
        if value is None:
            continue
        candidates = value if isinstance(value, (list, tuple, set)) else [value]
        for candidate in candidates:
            text = str(candidate).strip()
            if text and not _is_redacted(text):
                return text
    return None


def _all_strs(raw: Mapping[str, Any], fields: Sequence[str]) -> list[str]:
    """Every distinct non-redacted string across ``fields``."""
    found: list[str] = []
    for name in fields:
        value = raw.get(name)
        if value is None:
            continue
        candidates = value if isinstance(value, (list, tuple, set)) else [value]
        for candidate in candidates:
            text = str(candidate).strip()
            if text and not _is_redacted(text) and text not in found:
                found.append(text)
    return found


def _first_date(raw: Mapping[str, Any], fields: Sequence[str]) -> str | None:
    """First parseable date across ``fields``, as an ISO string."""
    for name in fields:
        value = raw.get(name)
        if value is None:
            continue
        candidates = value if isinstance(value, (list, tuple)) else [value]
        for candidate in candidates:
            if isinstance(candidate, datetime):
                return candidate.isoformat()
            text = str(candidate).strip()
            if not text:
                continue
            try:
                return datetime.fromisoformat(text.replace("Z", "+00:00")).isoformat()
            except ValueError:
                return text
    return None


@dataclass(slots=True)
class WhoisRecord:
    """Normalized WHOIS registration data."""

    domain: str
    registrar: str | None = None
    registrant_org: str | None = None
    emails: list[str] = field(default_factory=list)
    nameservers: list[str] = field(default_factory=list)
    created_at: str | None = None
    expires_at: str | None = None
    updated_at: str | None = None
    redacted: bool = False
    raw_fields: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "registrar": self.registrar,
            "registrant_org": self.registrant_org,
            "emails": list(self.emails),
            "nameservers": list(self.nameservers),
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "updated_at": self.updated_at,
            "redacted": self.redacted,
            "raw_fields": list(self.raw_fields),
        }


def parse_whois_record(domain: str, raw: Mapping[str, Any]) -> WhoisRecord:
    """Normalize a registry's WHOIS payload into a :class:`WhoisRecord`."""
    emails = [e for e in _all_strs(raw, _EMAIL_FIELDS) if looks_like_email(e)]
    nameservers = [ns.rstrip(".").lower() for ns in _all_strs(raw, _NAMESERVER_FIELDS)]

    registrant_org = _first_str(raw, _ORG_FIELDS)
    registrar = _first_str(raw, _REGISTRAR_FIELDS)

    # If org/contact fields exist but every value was a privacy placeholder,
    # the record is redacted rather than empty -- a meaningful distinction.
    had_contact_fields = any(raw.get(name) is not None for name in (*_ORG_FIELDS, *_EMAIL_FIELDS))
    redacted = had_contact_fields and registrant_org is None and not emails

    return WhoisRecord(
        domain=domain,
        registrar=registrar,
        registrant_org=registrant_org,
        emails=emails,
        nameservers=sorted(set(nameservers)),
        created_at=_first_date(raw, _CREATED_FIELDS),
        expires_at=_first_date(raw, _EXPIRY_FIELDS),
        updated_at=_first_date(raw, _UPDATED_FIELDS),
        redacted=redacted,
        raw_fields=sorted(str(k) for k in raw),
    )


def record_to_graph_elements(
    record: WhoisRecord, *, source: str = "osint.whois"
) -> tuple[list[Entity], list[Relationship]]:
    """Convert a WHOIS record into graph entities and relationships."""
    entities: list[Entity] = []
    relationships: list[Relationship] = []

    root = Entity.create(
        EntityType.DOMAIN,
        record.domain,
        source=source,
        detail="whois subject",
        attributes={
            k: v
            for k, v in (
                ("registrar", record.registrar),
                ("created_at", record.created_at),
                ("expires_at", record.expires_at),
                ("whois_redacted", record.redacted or None),
            )
            if v is not None
        },
    )
    entities.append(root)

    def link(target: Entity, edge: EdgeType, confidence: float, detail: str) -> None:
        entities.append(target)
        relationships.append(
            Relationship.create(
                root, target, edge, confidence=confidence, source_tool=source, detail=detail
            )
        )

    if record.registrant_org:
        link(
            Entity.create(
                EntityType.ORGANIZATION,
                record.registrant_org,
                source=source,
                detail="whois registrant",
            ),
            EdgeType.REGISTERED_BY,
            Confidence.OBSERVED,
            "whois registrant organization",
        )

    if record.registrar and record.registrar != record.registrant_org:
        link(
            Entity.create(
                EntityType.ORGANIZATION, record.registrar, source=source, detail="registrar"
            ),
            EdgeType.REGISTERED_BY,
            # The registrar is the seller, not the owner -- a real but much
            # weaker association than the registrant.
            Confidence.WEAK,
            "whois registrar",
        )

    for email in record.emails:
        try:
            link(
                Entity.create(EntityType.EMAIL, email, source=source, detail="whois contact"),
                EdgeType.REGISTRANT_CONTACT,
                Confidence.STRONG,
                "whois contact email",
            )
        except ValueError:
            logger.debug("Skipping unparseable WHOIS email %r", email)

    for nameserver in record.nameservers:
        try:
            link(
                Entity.create(
                    EntityType.DOMAIN, nameserver, source=source, detail="whois nameserver"
                ),
                EdgeType.NAMESERVER_FOR,
                Confidence.OBSERVED,
                "whois nameserver",
            )
        except ValueError:
            logger.debug("Skipping unparseable WHOIS nameserver %r", nameserver)

    return entities, relationships


@tool(
    name="osint.whois",
    description=(
        "Look up WHOIS registration metadata for a domain (registrar, "
        "registrant, contacts, nameservers, key dates)."
    ),
    category=ToolCategory.OSINT,
    risk=RiskLevel.PASSIVE,
    parameters=[ToolParameter("target", str, description="Domain name to look up")],
    timeout_seconds=30.0,
    rate_limit_per_minute=20.0,
    produces=["registration", "contacts"],
    tags=["osint", "whois"],
)
async def whois_collect(ctx: ToolContext, target: str) -> dict[str, Any]:
    """Fetch and normalize WHOIS data for ``target``."""
    try:
        domain = normalize_domain(target)
    except ValueError as exc:
        raise CollectorError(f"Invalid domain {target!r}: {exc}") from exc

    client = provider_from(ctx, "whois_client", default_whois_client)
    raw = await client.lookup(domain)
    record = parse_whois_record(domain, raw)
    entities, relationships = record_to_graph_elements(record)

    return {
        **record.to_dict(),
        "entities": [e.to_dict() for e in entities],
        "relationships": [r.to_dict() for r in relationships],
    }
