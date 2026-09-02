"""TLS certificate chain collector.

Retrieves the leaf certificate presented by a host and maps it into the graph:
subject alternative names become domain entities (certificates are one of the
most reliable ways to discover an organization's other hostnames), and the
issuer becomes an organization entity.

**Risk classification: ACTIVE.** This opens a TCP connection and completes a
TLS handshake with the target, so it plainly contacts it.

The default fetcher uses the standard library's :mod:`ssl` module, so unlike
the DNS and WHOIS collectors this one is fully functional with no optional
dependencies at all.

One deliberate choice worth noting: the fetcher verifies certificates by
default but can be asked not to (``verify=False``). Reconnaissance frequently
needs to inspect exactly the certificates that fail validation -- expired,
self-signed, wrong-host -- and refusing to look at them would blind the
collector to the most interesting findings. Validation status is recorded as
data on the entity rather than being enforced.
"""

from __future__ import annotations

import asyncio
import logging
import ssl
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
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
    normalize_domain,
)

logger = logging.getLogger(__name__)

__all__ = [
    "CertificateInfo",
    "StdlibTlsFetcher",
    "TlsCertificateFetcher",
    "certificate_to_graph_elements",
    "default_tls_fetcher",
    "parse_certificate",
    "tls_collect",
]

_CERT_DATE_FORMAT = "%b %d %H:%M:%S %Y %Z"


@runtime_checkable
class TlsCertificateFetcher(Protocol):
    """Retrieves the certificate a host presents."""

    async def fetch(
        self, host: str, port: int, *, verify: bool
    ) -> dict[str, Any]:  # pragma: no cover - protocol declaration
        ...


class StdlibTlsFetcher:
    """Certificate fetcher built on :mod:`ssl` and :mod:`asyncio`."""

    __slots__ = ("_timeout",)

    def __init__(self, timeout: float = 10.0) -> None:
        self._timeout = timeout

    async def fetch(self, host: str, port: int, *, verify: bool) -> dict[str, Any]:
        context = ssl.create_default_context()
        verification_error: str | None = None

        if not verify:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

        try:
            _reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=context, server_hostname=host),
                timeout=self._timeout,
            )
        except ssl.SSLCertVerificationError as exc:
            if verify:
                # Retry unverified so the bad certificate can still be
                # inspected -- an expired or mismatched cert is a finding.
                logger.info(
                    "Certificate verification failed for %s:%d (%s); "
                    "retrying without verification to inspect it",
                    host,
                    port,
                    exc.verify_message or exc,
                )
                result = await self.fetch(host, port, verify=False)
                result["verified"] = False
                result["verification_error"] = str(exc.verify_message or exc)
                return result
            raise CollectorError(f"TLS handshake with {host}:{port} failed: {exc}") from exc
        except TimeoutError as exc:
            raise CollectorError(f"TLS connection to {host}:{port} timed out") from exc
        except (OSError, ssl.SSLError) as exc:
            raise CollectorError(f"TLS connection to {host}:{port} failed: {exc}") from exc

        try:
            ssl_object = writer.get_extra_info("ssl_object")
            if ssl_object is None:  # pragma: no cover - defensive
                raise CollectorError(f"No TLS session established with {host}:{port}")

            certificate: dict[str, Any] = dict(ssl_object.getpeercert() or {})
            certificate["_cipher"] = ssl_object.cipher()
            certificate["_version"] = ssl_object.version()
            certificate["verified"] = verify
            if verification_error:  # pragma: no cover - set on the retry path
                certificate["verification_error"] = verification_error
            return certificate
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, ssl.SSLError):  # pragma: no cover - best effort
                logger.debug("Error closing TLS connection to %s:%d", host, port)


def default_tls_fetcher() -> TlsCertificateFetcher:
    """Return the stdlib certificate fetcher."""
    return StdlibTlsFetcher()


@dataclass(slots=True)
class CertificateInfo:
    """Normalized view of a leaf certificate."""

    host: str
    port: int = 443
    subject_cn: str | None = None
    issuer_cn: str | None = None
    issuer_org: str | None = None
    sans: list[str] = field(default_factory=list)
    not_before: str | None = None
    not_after: str | None = None
    serial_number: str | None = None
    tls_version: str | None = None
    cipher: str | None = None
    verified: bool = True
    verification_error: str | None = None

    @property
    def is_expired(self) -> bool:
        """True when ``not_after`` is in the past."""
        if not self.not_after:
            return False
        try:
            expiry = datetime.fromisoformat(self.not_after)
        except ValueError:  # pragma: no cover - defensive
            return False
        from security_assistant.core.types import utcnow

        now = utcnow()
        if expiry.tzinfo is None:
            now = now.replace(tzinfo=None)
        return expiry < now

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "subject_cn": self.subject_cn,
            "issuer_cn": self.issuer_cn,
            "issuer_org": self.issuer_org,
            "sans": list(self.sans),
            "not_before": self.not_before,
            "not_after": self.not_after,
            "serial_number": self.serial_number,
            "tls_version": self.tls_version,
            "cipher": self.cipher,
            "verified": self.verified,
            "verification_error": self.verification_error,
            "is_expired": self.is_expired,
        }


def _rdn_value(rdns: Any, field_name: str) -> str | None:
    """Pull one field out of :func:`ssl.SSLSocket.getpeercert` RDN tuples.

    The structure is a tuple of tuples of ``(key, value)`` pairs, which is
    awkward enough to be worth isolating.
    """
    if not isinstance(rdns, (list, tuple)):
        return None
    for rdn in rdns:
        if not isinstance(rdn, (list, tuple)):
            continue
        for pair in rdn:
            if isinstance(pair, (list, tuple)) and len(pair) == 2:
                key, value = pair
                if str(key) == field_name and str(value).strip():
                    return str(value).strip()
    return None


def _parse_cert_date(value: Any) -> str | None:
    """Parse OpenSSL's ``'Jun  1 12:00:00 2025 GMT'`` into an ISO string."""
    if not value:
        return None
    text = str(value).strip()
    try:
        return datetime.strptime(text, _CERT_DATE_FORMAT).isoformat()
    except ValueError:
        return text


def parse_certificate(host: str, port: int, raw: dict[str, Any]) -> CertificateInfo:
    """Normalize a raw ``getpeercert()`` mapping."""
    sans: list[str] = []
    for entry_type, entry_value in raw.get("subjectAltName", ()) or ():
        if str(entry_type).lower() == "dns":
            name = str(entry_value).strip().lstrip("*.").rstrip(".").lower()
            if name and name not in sans:
                sans.append(name)

    cipher = raw.get("_cipher")
    cipher_name = cipher[0] if isinstance(cipher, (list, tuple)) and cipher else None

    return CertificateInfo(
        host=host,
        port=port,
        subject_cn=_rdn_value(raw.get("subject"), "commonName"),
        issuer_cn=_rdn_value(raw.get("issuer"), "commonName"),
        issuer_org=_rdn_value(raw.get("issuer"), "organizationName"),
        sans=sans,
        not_before=_parse_cert_date(raw.get("notBefore")),
        not_after=_parse_cert_date(raw.get("notAfter")),
        serial_number=str(raw["serialNumber"]) if raw.get("serialNumber") else None,
        tls_version=str(raw["_version"]) if raw.get("_version") else None,
        cipher=str(cipher_name) if cipher_name else None,
        verified=bool(raw.get("verified", True)),
        verification_error=(
            str(raw["verification_error"]) if raw.get("verification_error") else None
        ),
    )


def certificate_to_graph_elements(
    certificate: CertificateInfo, *, source: str = "osint.tls"
) -> tuple[list[Entity], list[Relationship]]:
    """Convert certificate data into graph entities and relationships."""
    entities: list[Entity] = []
    relationships: list[Relationship] = []

    root = Entity.create(
        EntityType.DOMAIN,
        certificate.host,
        source=source,
        detail="tls subject",
        attributes={
            k: v
            for k, v in (
                ("tls_version", certificate.tls_version),
                ("cipher", certificate.cipher),
                ("cert_not_after", certificate.not_after),
                ("cert_expired", certificate.is_expired or None),
                ("cert_verified", certificate.verified),
                ("cert_verification_error", certificate.verification_error),
            )
            if v is not None
        },
    )
    entities.append(root)

    for san in certificate.sans:
        if san == root.canonical:
            continue
        try:
            covered = Entity.create(
                EntityType.DOMAIN, san, source=source, detail="certificate SAN"
            )
        except ValueError:
            logger.debug("Skipping unparseable SAN %r", san)
            continue
        entities.append(covered)
        relationships.append(
            Relationship.create(
                root,
                covered,
                EdgeType.SECURES,
                # A shared certificate is strong evidence of common control,
                # though shared hosting and CDNs make it short of certain.
                confidence=Confidence.STRONG,
                source_tool=source,
                detail="subject alternative name",
            )
        )

    issuer = certificate.issuer_org or certificate.issuer_cn
    if issuer:
        try:
            issuer_entity = Entity.create(
                EntityType.ORGANIZATION, issuer, source=source, detail="certificate issuer"
            )
        except ValueError:  # pragma: no cover - defensive
            return entities, relationships
        entities.append(issuer_entity)
        relationships.append(
            Relationship.create(
                root,
                issuer_entity,
                EdgeType.ISSUED_BY,
                confidence=Confidence.OBSERVED,
                source_tool=source,
                detail="certificate issuer",
            )
        )

    return entities, relationships


@tool(
    name="osint.tls",
    description=(
        "Retrieve and inspect the TLS certificate a host presents, extracting "
        "subject alternative names and issuer details."
    ),
    category=ToolCategory.RECON,
    risk=RiskLevel.ACTIVE,
    parameters=[
        ToolParameter("target", str, description="Hostname to connect to"),
        ToolParameter(
            "port", int, required=False, default=443, description="TLS port (default 443)"
        ),
        ToolParameter(
            "verify",
            bool,
            required=False,
            default=True,
            description="Verify the chain; invalid certs are still inspected either way",
        ),
    ],
    timeout_seconds=30.0,
    rate_limit_per_minute=60.0,
    produces=["certificates", "sans"],
    tags=["osint", "tls"],
)
async def tls_collect(
    ctx: ToolContext, target: str, port: int = 443, verify: bool = True
) -> dict[str, Any]:
    """Fetch and normalize the certificate presented by ``target``."""
    try:
        host = normalize_domain(target)
    except ValueError as exc:
        raise CollectorError(f"Invalid hostname {target!r}: {exc}") from exc

    if not 1 <= port <= 65535:
        raise CollectorError(f"Port out of range: {port}")

    fetcher = provider_from(ctx, "tls_fetcher", default_tls_fetcher)
    raw = await fetcher.fetch(host, port, verify=verify)
    certificate = parse_certificate(host, port, dict(raw))
    entities, relationships = certificate_to_graph_elements(certificate)

    return {
        **certificate.to_dict(),
        "entities": [e.to_dict() for e in entities],
        "relationships": [r.to_dict() for r in relationships],
    }


def sans_of(certificates: Sequence[CertificateInfo]) -> list[str]:
    """Every distinct SAN across a set of certificates, sorted."""
    found: set[str] = set()
    for certificate in certificates:
        found.update(certificate.sans)
    return sorted(found)
