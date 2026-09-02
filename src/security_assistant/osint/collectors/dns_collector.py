"""DNS reconnaissance collector.

Resolves A/AAAA/MX/NS/TXT/CNAME records for a domain and turns the answers
into graph entities and relationships.

**Risk classification: ACTIVE.** A recursive lookup can reach the target's own
authoritative nameservers, so this does not meet the ``PASSIVE`` bar of "never
contacts the target". A passive-only engagement will not run it.

Resolution goes through the :class:`DnsResolver` protocol. ``dnspython``
provides full record-type support when the ``osint`` extra is installed; the
stdlib fallback handles A/AAAA via :func:`socket.getaddrinfo` and reports the
remaining types as unsupported rather than silently returning nothing.
"""

from __future__ import annotations

import logging
import re
import socket
from collections.abc import Sequence
from dataclasses import dataclass, field
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

_dns: Any
try:  # pragma: no cover - depends on which extras are installed
    import dns.asyncresolver
    import dns.resolver

    _dns = dns
except ImportError:  # pragma: no cover
    _dns = None

__all__ = [
    "DEFAULT_RECORD_TYPES",
    "DnsResolver",
    "DnspythonResolver",
    "StdlibDnsResolver",
    "default_resolver",
    "dns_collect",
    "records_to_graph_elements",
]

DEFAULT_RECORD_TYPES: tuple[str, ...] = ("A", "AAAA", "MX", "NS", "TXT", "CNAME")

# Matches an address-shaped substring anywhere inside a TXT record value.
_TXT_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
SUPPORTED_RECORD_TYPES = frozenset(
    {"A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR", "SRV", "CAA"}
)


@runtime_checkable
class DnsResolver(Protocol):
    """Resolves one record type for one name."""

    async def resolve(
        self, name: str, record_type: str
    ) -> list[str]:  # pragma: no cover - protocol declaration
        ...


class StdlibDnsResolver:
    """Address-record resolver built on :func:`socket.getaddrinfo`.

    Available everywhere, but the OS resolver interface only exposes address
    lookups -- MX/NS/TXT/CNAME need a real DNS library. Those raise
    :class:`CollectorError` rather than returning an empty list, so a missing
    dependency is never mistaken for a domain having no MX records.
    """

    __slots__ = ()

    async def resolve(self, name: str, record_type: str) -> list[str]:
        record = record_type.upper()
        if record not in {"A", "AAAA"}:
            raise CollectorError(
                f"{record} lookups require dnspython; install the OSINT extra "
                "(`poetry install -E osint`) for full record-type support"
            )

        family = socket.AF_INET if record == "A" else socket.AF_INET6
        try:
            infos = await run_blocking(
                socket.getaddrinfo, name, None, family, socket.SOCK_STREAM
            )
        except socket.gaierror as exc:
            if exc.errno in (socket.EAI_NONAME, socket.EAI_NODATA):
                return []
            raise CollectorError(f"DNS lookup for {name!r} failed: {exc}") from exc

        addresses: list[str] = []
        for info in infos:
            address = str(info[4][0])
            if address not in addresses:
                addresses.append(address)
        return addresses


class DnspythonResolver:
    """Full-featured resolver backed by ``dnspython``."""

    __slots__ = ("_lifetime",)

    def __init__(self, lifetime: float = 5.0) -> None:
        if _dns is None:  # pragma: no cover - guarded by default_resolver
            raise CollectorError("dnspython is not installed")
        self._lifetime = lifetime

    async def resolve(self, name: str, record_type: str) -> list[str]:
        record = record_type.upper()
        try:
            answer = await _dns.asyncresolver.resolve(
                name, record, lifetime=self._lifetime
            )
        except (_dns.resolver.NXDOMAIN, _dns.resolver.NoAnswer):
            # A domain with no records of this type is a fact, not an error.
            return []
        except Exception as exc:
            raise CollectorError(f"DNS {record} lookup for {name!r} failed: {exc}") from exc

        return [rdata.to_text().strip('"') for rdata in answer]


def default_resolver() -> DnsResolver:
    """Return the best resolver available in this environment."""
    if _dns is not None:  # pragma: no cover - requires the extra
        return DnspythonResolver()
    return StdlibDnsResolver()


@dataclass(slots=True)
class DnsRecordSet:
    """Parsed answers for one domain, keyed by record type."""

    domain: str
    records: dict[str, list[str]] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "records": {k: list(v) for k, v in sorted(self.records.items())},
            "errors": dict(sorted(self.errors.items())),
        }


def _split_mx(value: str) -> str:
    """``"10 mail.example.com."`` -> ``"mail.example.com"``."""
    parts = value.split()
    return (parts[-1] if parts else value).rstrip(".")


def records_to_graph_elements(
    record_set: DnsRecordSet, *, source: str = "osint.dns"
) -> tuple[list[Entity], list[Relationship]]:
    """Convert a record set into graph entities and relationships.

    Kept separate from the I/O so the mapping from DNS answers to graph shape
    is testable without a resolver.
    """
    entities: list[Entity] = []
    relationships: list[Relationship] = []

    try:
        root = Entity.create(
            EntityType.DOMAIN, record_set.domain, source=source, detail="query target"
        )
    except ValueError as exc:
        raise CollectorError(f"Invalid domain {record_set.domain!r}: {exc}") from exc
    entities.append(root)

    def link(target: Entity, edge: EdgeType, confidence: float, detail: str) -> None:
        entities.append(target)
        relationships.append(
            Relationship.create(
                root, target, edge, confidence=confidence, source_tool=source, detail=detail
            )
        )

    for record_type, values in record_set.records.items():
        upper = record_type.upper()
        for raw in values:
            value = raw.strip()
            if not value:
                continue
            try:
                if upper in {"A", "AAAA"}:
                    link(
                        Entity.create(
                            EntityType.IP_ADDRESS, value, source=source, detail=f"{upper} record"
                        ),
                        EdgeType.RESOLVES_TO,
                        Confidence.OBSERVED,
                        f"{upper} record",
                    )
                elif upper == "MX":
                    link(
                        Entity.create(
                            EntityType.DOMAIN,
                            _split_mx(value),
                            source=source,
                            detail="MX record",
                        ),
                        EdgeType.MAIL_HANDLED_BY,
                        Confidence.OBSERVED,
                        "MX record",
                    )
                elif upper == "NS":
                    link(
                        Entity.create(
                            EntityType.DOMAIN,
                            value.rstrip("."),
                            source=source,
                            detail="NS record",
                        ),
                        EdgeType.NAMESERVER_FOR,
                        Confidence.OBSERVED,
                        "NS record",
                    )
                elif upper == "CNAME":
                    link(
                        Entity.create(
                            EntityType.DOMAIN,
                            value.rstrip("."),
                            source=source,
                            detail="CNAME record",
                        ),
                        EdgeType.ALIAS_OF,
                        Confidence.OBSERVED,
                        "CNAME record",
                    )
                elif upper == "TXT":
                    # TXT records frequently carry contact addresses (SPF
                    # rua/ruf, DMARC reporting). Those are a weaker signal
                    # than a registrant contact, so they get lower confidence.
                    for token in _emails_in_txt(value):
                        link(
                            Entity.create(
                                EntityType.EMAIL,
                                token,
                                source=source,
                                detail="TXT record",
                            ),
                            EdgeType.REGISTRANT_CONTACT,
                            Confidence.WEAK,
                            "email found in TXT record",
                        )
            except ValueError:
                # A malformed answer is skipped rather than failing the whole
                # collection; the raw value stays in the tool's return payload.
                logger.debug("Skipping unparseable %s record %r", upper, value)

    return entities, relationships


def _emails_in_txt(value: str) -> list[str]:
    """Extract email addresses from a TXT record body.

    TXT records embed addresses inside structured values rather than as bare
    tokens -- ``rua=mailto:dmarc@example.com`` in DMARC, ``spf`` exists=
    macros, and so on -- so this scans for address-shaped substrings instead
    of splitting on whitespace, which would keep the ``rua=mailto:`` prefix as
    part of the local part.
    """
    found: list[str] = []
    for match in _TXT_EMAIL_RE.findall(value):
        candidate = match.strip().rstrip(".")
        if looks_like_email(candidate) and candidate not in found:
            found.append(candidate)
    return found


@tool(
    name="osint.dns",
    description=(
        "Resolve DNS records (A/AAAA/MX/NS/TXT/CNAME) for a domain and map the "
        "answers into OSINT graph entities."
    ),
    category=ToolCategory.RECON,
    risk=RiskLevel.ACTIVE,
    parameters=[
        ToolParameter("target", str, description="Domain name to resolve"),
        ToolParameter(
            "record_types",
            list,
            required=False,
            description="Record types to query; defaults to A/AAAA/MX/NS/TXT/CNAME",
        ),
    ],
    timeout_seconds=30.0,
    rate_limit_per_minute=120.0,
    produces=["hosts", "dns_records"],
    tags=["osint", "dns"],
)
async def dns_collect(
    ctx: ToolContext, target: str, record_types: Sequence[str] | None = None
) -> dict[str, Any]:
    """Resolve ``target`` and return records plus serialized graph elements."""
    try:
        domain = normalize_domain(target)
    except ValueError as exc:
        raise CollectorError(f"Invalid domain {target!r}: {exc}") from exc

    requested = [str(r).upper() for r in (record_types or DEFAULT_RECORD_TYPES)]
    unsupported = sorted(set(requested) - SUPPORTED_RECORD_TYPES)
    if unsupported:
        raise CollectorError(f"Unsupported DNS record type(s): {unsupported}")

    resolver = provider_from(ctx, "dns_resolver", default_resolver)
    record_set = DnsRecordSet(domain=domain)

    for record_type in requested:
        try:
            answers = await resolver.resolve(domain, record_type)
        except CollectorError as exc:
            # One unsupported or failing record type must not lose the others.
            record_set.errors[record_type] = str(exc)
            continue
        if answers:
            record_set.records[record_type] = answers

    if not record_set.records and record_set.errors:
        raise CollectorError(
            f"No DNS records could be collected for {domain!r}: "
            f"{'; '.join(f'{k}: {v}' for k, v in sorted(record_set.errors.items()))}"
        )

    entities, relationships = records_to_graph_elements(record_set)
    return {
        **record_set.to_dict(),
        "entities": [e.to_dict() for e in entities],
        "relationships": [r.to_dict() for r in relationships],
    }
