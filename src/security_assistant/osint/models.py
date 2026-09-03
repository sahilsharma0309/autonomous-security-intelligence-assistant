"""Entity and relationship models for the OSINT graph.

Every observation the collectors make is reduced to two shapes: an
:class:`Entity` (a thing) and a :class:`Relationship` (a directed, typed link
between two things). Both carry provenance and a confidence score, because an
intelligence graph whose edges cannot be traced back to what produced them is
not auditable.

**Canonicalization is the load-bearing idea here.** Two collectors that
independently observe ``Example.COM.`` and ``example.com`` must produce the
same node, or the graph silently fragments into near-duplicates and every
downstream correlation is wrong. So each entity type defines exactly one
canonical form, and :attr:`Entity.key` is derived from it. Deduplication is
then a dictionary lookup rather than a similarity search -- the correlator in
:mod:`security_assistant.osint.correlator` only has to handle the genuinely
ambiguous cases.

The module depends on nothing outside the standard library. ``phonenumbers``
is used for E.164 normalization when installed, with a documented digit-based
fallback otherwise.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

from security_assistant.core.types import utcnow

# phonenumbers gives proper region-aware E.164 parsing; the fallback below is
# deliberately conservative rather than clever when it is absent.
_phonenumbers: Any
try:  # pragma: no cover - depends on which extras are installed
    import phonenumbers

    _phonenumbers = phonenumbers
except ImportError:  # pragma: no cover
    _phonenumbers = None

__all__ = [
    "Confidence",
    "EdgeType",
    "Entity",
    "EntityType",
    "Observation",
    "Relationship",
    "combine_confidence",
    "hash_algorithm",
    "normalize_device",
    "normalize_domain",
    "normalize_email",
    "normalize_file_hash",
    "normalize_host",
    "normalize_organization",
    "normalize_phone",
    "normalize_service",
    "normalize_social_handle",
    "normalize_url",
]

_WHITESPACE_RE = re.compile(r"\s+")

# Ports that are implied by their scheme and so dropped from the canonical
# form -- https://example.com:443/ and https://example.com/ are one URL.
_DEFAULT_PORTS: dict[str, tuple[int, ...]] = {
    "http": (80,),
    "https": (443,),
    "ftp": (21,),
    "ws": (80,),
    "wss": (443,),
}

# Digest length -> algorithm. Length is unambiguous across these three.
_HASH_LENGTHS: dict[int, str] = {32: "md5", 40: "sha1", 64: "sha256"}
_NON_PHONE_RE = re.compile(r"[^0-9+]")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# Legal-form suffixes stripped when comparing organization names. "Acme Inc."
# and "Acme, LLC" are usually the same org for correlation purposes, so the
# match key drops these while `Entity.value` keeps the name as observed.
_ORG_SUFFIXES = frozenset(
    {
        "inc", "incorporated", "llc", "l.l.c", "ltd", "limited", "corp",
        "corporation", "co", "company", "gmbh", "ag", "sa", "sas", "bv", "nv",
        "plc", "pty", "pvt", "oy", "ab", "as", "srl", "spa", "kk", "kg",
    }
)


class EntityType(StrEnum):
    """The kinds of node the graph holds.

    The first six are OSINT entities. ``IOT_DEVICE`` and ``NETWORK_SERVICE``
    are first-class asset nodes so that discovered infrastructure correlates
    with OSINT findings directly -- a camera at ``192.0.2.10`` and a domain
    resolving to that same address meet at the shared ``ip_address`` node
    rather than living in two disconnected inventories.

    ``URL`` and ``FILE_HASH`` extend the same idea to threat intelligence: a
    phishing URL and the domain it abuses meet at the shared ``domain`` node,
    so "is this URL on infrastructure we already know about?" is a graph
    traversal rather than a separate lookup.
    """

    EMAIL = "email"
    PHONE = "phone"
    DOMAIN = "domain"
    IP_ADDRESS = "ip_address"
    SOCIAL_HANDLE = "social_handle"
    ORGANIZATION = "organization"
    IOT_DEVICE = "iot_device"
    NETWORK_SERVICE = "network_service"
    URL = "url"
    FILE_HASH = "file_hash"


class EdgeType(StrEnum):
    """The kinds of directed relationship the graph holds."""

    RESOLVES_TO = "resolves_to"
    """domain -> ip_address (A/AAAA record)."""

    MAIL_HANDLED_BY = "mail_handled_by"
    """domain -> domain (MX record)."""

    NAMESERVER_FOR = "nameserver_for"
    """domain -> domain (NS record)."""

    ALIAS_OF = "alias_of"
    """domain -> domain (CNAME)."""

    SUBDOMAIN_OF = "subdomain_of"
    """domain -> domain (structural containment)."""

    REGISTERED_BY = "registered_by"
    """domain -> organization (WHOIS registrant/registrar)."""

    REGISTRANT_CONTACT = "registrant_contact"
    """domain -> email|phone (WHOIS contact details)."""

    SECURES = "secures"
    """domain -> domain (a certificate's SAN covers this name)."""

    ISSUED_BY = "issued_by"
    """domain -> organization (certificate issuer)."""

    HAS_HANDLE = "has_handle"
    """organization|email -> social_handle."""

    USES_EMAIL = "uses_email"
    """organization -> email."""

    EXPOSES_SERVICE = "exposes_service"
    """iot_device -> network_service (an open, reachable port)."""

    RUNS_ON = "runs_on"
    """iot_device -> ip_address (the address the device answers on)."""

    SERVICE_ON = "service_on"
    """network_service -> ip_address (where the service is reachable)."""

    MANUFACTURED_BY = "manufactured_by"
    """iot_device -> organization (vendor inferred from a banner)."""

    REDIRECTS_TO = "redirects_to"
    """url -> url (one hop of a redirect chain)."""

    SERVED_BY = "served_by"
    """url -> domain|ip_address (the host the URL is fetched from)."""

    CONTACTS = "contacts"
    """url -> domain (a third-party host the page reached during load)."""

    REFERENCES_FILE = "references_file"
    """url -> file_hash (a resource the page served or offered)."""

    SAME_AS = "same_as"
    """Entity resolution: two nodes are believed to be the same real thing."""

    ASSOCIATED_WITH = "associated_with"
    """A weaker, untyped association."""


class Confidence:
    """Named confidence levels.

    These are not an enum because confidence is a continuous score; the
    constants just keep collectors from inventing arbitrary magic numbers.
    A collector reporting a fact it observed directly (a DNS answer) should
    use :attr:`OBSERVED`; one reporting an inference should use less.
    """

    CERTAIN = 1.0
    OBSERVED = 0.95
    """Directly observed from an authoritative response."""

    STRONG = 0.8
    """Strong inference (e.g. a certificate SAN implies control)."""

    MODERATE = 0.6
    LIKELY = 0.5
    WEAK = 0.3
    """A hint worth recording but not acting on alone."""

    @staticmethod
    def clamp(value: float) -> float:
        """Constrain a score to ``[0.0, 1.0]``."""
        return max(0.0, min(1.0, float(value)))


def combine_confidence(scores: Iterable[float]) -> float:
    """Combine independent evidence with a noisy-OR.

    Two sources each 60% sure give ``1 - 0.4*0.4 = 0.84`` -- more than either
    alone, never reaching certainty. This is the right shape for corroborating
    observations: agreement should increase belief, but no finite amount of
    circumstantial evidence should produce 1.0.

    >>> round(combine_confidence([0.6, 0.6]), 4)
    0.84
    >>> combine_confidence([])
    0.0
    """
    complement = 1.0
    seen = False
    for score in scores:
        seen = True
        complement *= 1.0 - Confidence.clamp(score)
    return Confidence.clamp(1.0 - complement) if seen else 0.0


# --------------------------------------------------------------------------- #
# Canonicalization
# --------------------------------------------------------------------------- #
def normalize_domain(value: str) -> str:
    """Canonicalize a domain name.

    Lowercases, strips the root dot and any surrounding whitespace, and
    IDNA-encodes unicode labels so ``BÜCHER.de`` and ``xn--bcher-kva.de``
    collapse to one node.

    >>> normalize_domain("  Example.COM. ")
    'example.com'
    """
    text = value.strip().rstrip(".").lower()
    if not text:
        raise ValueError("Domain must not be empty")
    if text.isascii():
        return text
    try:
        return text.encode("idna").decode("ascii")
    except UnicodeError:
        # Not encodable (e.g. a label over 63 bytes); keep the lowercase form
        # rather than dropping the observation entirely.
        return text


def normalize_email(value: str) -> str:
    """Canonicalize an email address.

    The domain half is case-insensitive per RFC 5321 and is normalized as a
    domain. The local part is *not* lowercased blindly -- it is technically
    case-sensitive -- but in practice every major provider treats it
    case-insensitively, and treating ``A@x.com`` and ``a@x.com`` as separate
    people causes far more harm here than the theoretical inaccuracy.

    >>> normalize_email("Alice+news@Example.COM")
    'alice+news@example.com'
    """
    text = value.strip()
    if "@" not in text:
        raise ValueError(f"Not an email address: {value!r}")
    local, _, domain = text.rpartition("@")
    if not local or not domain:
        raise ValueError(f"Not an email address: {value!r}")
    return f"{local.lower()}@{normalize_domain(domain)}"


def normalize_phone(value: str, region_hint: str | None = None) -> str:
    """Canonicalize a phone number to E.164 where possible.

    Uses ``phonenumbers`` when installed. Without it, the fallback strips
    formatting and keeps a leading ``+``; it does not guess a country code,
    because inventing one produces confident nonsense.

    >>> normalize_phone("+1 (415) 555-0100")
    '+14155550100'
    """
    text = value.strip()
    if not text:
        raise ValueError("Phone number must not be empty")

    if _phonenumbers is not None:  # pragma: no cover - requires the extra
        try:
            parsed = _phonenumbers.parse(text, region_hint)
            if _phonenumbers.is_valid_number(parsed):
                formatted = _phonenumbers.format_number(
                    parsed, _phonenumbers.PhoneNumberFormat.E164
                )
                return str(formatted)
        except Exception:  # noqa: BLE001 - fall through to the stdlib path
            pass

    cleaned = _NON_PHONE_RE.sub("", text)
    if cleaned.startswith("+"):
        cleaned = "+" + cleaned[1:].replace("+", "")
    else:
        cleaned = cleaned.replace("+", "")
    if not cleaned.strip("+"):
        raise ValueError(f"Not a phone number: {value!r}")
    return cleaned


def normalize_social_handle(value: str, platform: str | None = None) -> str:
    """Canonicalize a social handle to ``platform/handle``.

    Accepts ``@alice``, ``alice``, ``twitter/alice`` and profile URLs.

    >>> normalize_social_handle("@Alice", "Twitter")
    'twitter/alice'
    >>> normalize_social_handle("https://github.com/Some-User")
    'github.com/some-user'
    """
    text = value.strip()
    if not text:
        raise ValueError("Social handle must not be empty")

    if "://" in text:
        from urllib.parse import urlsplit

        parsed = urlsplit(text)
        host = (parsed.hostname or "").lower()
        path = parsed.path.strip("/").split("/")[0] if parsed.path else ""
        if host and path:
            return f"{host}/{path.lower()}"
        text = path or host

    if "/" in text:
        left, _, right = text.partition("/")
        return f"{left.strip().lower()}/{right.strip().lstrip('@').lower()}"

    handle = text.lstrip("@").lower()
    if platform:
        return f"{platform.strip().lower()}/{handle}"
    return handle


def normalize_organization(value: str) -> str:
    """Canonicalize an organization name for matching.

    Casefolds, strips accents and punctuation, collapses whitespace, and drops
    trailing legal-form suffixes so ``Acme, Inc.`` and ``ACME LLC`` share a key.
    The original spelling is preserved on :attr:`Entity.value`.

    >>> normalize_organization("Acme, Inc.")
    'acme'
    >>> normalize_organization("ACME  LLC")
    'acme'
    """
    text = value.strip()
    if not text:
        raise ValueError("Organization name must not be empty")

    decomposed = unicodedata.normalize("NFKD", text)
    ascii_text = "".join(c for c in decomposed if not unicodedata.combining(c))
    cleaned = re.sub(r"[^\w\s]", " ", ascii_text, flags=re.UNICODE).casefold()
    tokens = [t for t in _WHITESPACE_RE.split(cleaned) if t]

    while tokens and tokens[-1] in _ORG_SUFFIXES:
        tokens.pop()

    if not tokens:  # The name was nothing but a legal suffix.
        tokens = [t for t in _WHITESPACE_RE.split(cleaned) if t]
    return " ".join(tokens)


def normalize_host(value: str) -> str:
    """Canonicalize something that is either an IP address or a hostname.

    Assets are addressed both ways depending on how they were discovered, so
    device and service identities go through one helper that picks the right
    normalization rather than guessing per call site.

    >>> normalize_host("2001:0db8:0000::0001")
    '2001:db8::1'
    >>> normalize_host("Camera.Example.COM.")
    'camera.example.com'
    """
    text = value.strip().strip("[]")
    if not text:
        raise ValueError("Host must not be empty")
    try:
        return _normalize_ip(text)
    except ValueError:
        return normalize_domain(text)


def normalize_device(value: str) -> str:
    """Canonicalize an IoT device identity.

    A device is identified by the address it answers on, so two collectors
    that find the same camera -- one via Shodan, one via a direct scan --
    produce one node.
    """
    return normalize_host(value)


def normalize_service(value: str) -> str:
    """Canonicalize a network service as ``host:port/protocol``.

    Accepts ``host:port``, ``host:port/proto``, and bracketed IPv6
    (``[2001:db8::1]:554/rtsp``). The protocol defaults to ``tcp`` because a
    bare ``host:port`` overwhelmingly means TCP in this context; recording it
    explicitly keeps UDP services from silently colliding with TCP ones on the
    same port.

    An IPv6 host stays bracketed in the canonical form, so the result parses
    back to itself -- without that, ``2001:db8::1:554/rtsp`` is ambiguous
    about where the address ends and the port begins.

    >>> normalize_service("192.0.2.10:554/RTSP")
    '192.0.2.10:554/rtsp'
    >>> normalize_service("192.0.2.10:80")
    '192.0.2.10:80/tcp'
    >>> normalize_service("[2001:0db8::1]:554/rtsp")
    '[2001:db8::1]:554/rtsp'
    """
    text = value.strip()
    if not text:
        raise ValueError("Service must not be empty")

    protocol = "tcp"
    if "/" in text:
        text, _, raw_protocol = text.rpartition("/")
        protocol = raw_protocol.strip().lower() or "tcp"

    # Bracketed IPv6 keeps its colons out of the host:port split.
    if text.startswith("["):
        end = text.find("]")
        if end == -1:
            raise ValueError(f"Unterminated IPv6 literal in service {value!r}")
        host, remainder = text[1:end], text[end + 1 :]
        port_text = remainder.lstrip(":")
    else:
        host, _, port_text = text.rpartition(":")
        if not host:  # No colon at all.
            raise ValueError(f"Service {value!r} must include a port")

    if not port_text.isdigit():
        raise ValueError(f"Service {value!r} has a non-numeric port {port_text!r}")
    port = int(port_text)
    if not 1 <= port <= 65535:
        raise ValueError(f"Service {value!r} port out of range: {port}")

    normalized_host = normalize_host(host)
    # An IPv6 address must stay bracketed or the canonical form cannot be
    # re-parsed: the colons would be indistinguishable from the port separator.
    if ":" in normalized_host:
        normalized_host = f"[{normalized_host}]"
    return f"{normalized_host}:{port}/{protocol}"


def normalize_url(value: str) -> str:
    """Canonicalize a URL.

    Lowercases the scheme and host, IDNA-encodes the host, drops the default
    port for the scheme, removes a fragment (it never reaches the server), and
    keeps the path, query and credentials as observed.

    Normalization here is security-relevant, not cosmetic: the canonical host
    is what a scope check reads, so a form that quietly disagreed with what
    the fetcher would actually contact would let a URL slip past
    authorization. The host is therefore normalized exactly as
    :func:`normalize_domain` does it, and an unparseable URL is rejected
    rather than passed through.

    >>> normalize_url("HTTP://Example.COM:80/Path?b=1#frag")
    'http://example.com/Path?b=1'
    >>> normalize_url("https://example.com")
    'https://example.com/'
    """
    from urllib.parse import urlsplit, urlunsplit

    text = value.strip()
    if not text:
        raise ValueError("URL must not be empty")

    parts = urlsplit(text)
    scheme = parts.scheme.lower()
    if not scheme:
        raise ValueError(f"URL {value!r} has no scheme")
    if not parts.hostname:
        raise ValueError(f"URL {value!r} has no host")

    try:
        host = normalize_domain(parts.hostname)
    except ValueError:
        host = parts.hostname.lower()
    # An IPv6 literal must stay bracketed to remain re-parseable.
    if ":" in host:
        host = f"[{host}]"

    netloc = host
    if parts.port is not None and parts.port not in _DEFAULT_PORTS.get(scheme, ()):
        netloc = f"{host}:{parts.port}"
    if parts.username:
        credentials = parts.username
        if parts.password:
            credentials = f"{credentials}:{parts.password}"
        netloc = f"{credentials}@{netloc}"

    path = parts.path or "/"
    # The fragment is deliberately dropped: it is never sent to the server, so
    # two URLs differing only by fragment are the same request.
    return urlunsplit((scheme, netloc, path, parts.query, ""))


def normalize_file_hash(value: str) -> str:
    """Canonicalize a file hash to lowercase hex.

    Accepts MD5, SHA-1 and SHA-256. The length identifies the algorithm, so
    the digest alone is a sufficient key; anything else is rejected rather
    than stored as an unusable node.

    >>> normalize_file_hash("  DA39A3EE5E6B4B0D3255BFEF95601890AFD80709 ")
    'da39a3ee5e6b4b0d3255bfef95601890afd80709'
    """
    text = value.strip().lower()
    if not text:
        raise ValueError("File hash must not be empty")
    if len(text) not in _HASH_LENGTHS:
        raise ValueError(
            f"Not an MD5/SHA-1/SHA-256 hash (got {len(text)} chars): {value!r}"
        )
    if any(c not in "0123456789abcdef" for c in text):
        raise ValueError(f"File hash contains non-hex characters: {value!r}")
    return text


def hash_algorithm(digest: str) -> str:
    """Name the algorithm implied by a digest's length."""
    return _HASH_LENGTHS.get(len(digest.strip()), "unknown")


_NORMALIZERS = {
    EntityType.DOMAIN: normalize_domain,
    EntityType.EMAIL: normalize_email,
    EntityType.PHONE: normalize_phone,
    EntityType.ORGANIZATION: normalize_organization,
    EntityType.IOT_DEVICE: normalize_device,
    EntityType.NETWORK_SERVICE: normalize_service,
    EntityType.URL: normalize_url,
    EntityType.FILE_HASH: normalize_file_hash,
}


def _normalize_ip(value: str) -> str:
    """Canonicalize an IP address (compressed form for IPv6)."""
    return str(ipaddress.ip_address(value.strip()))


def canonicalize(entity_type: EntityType, value: str) -> str:
    """Return the canonical form of ``value`` for ``entity_type``."""
    if entity_type is EntityType.IP_ADDRESS:
        return _normalize_ip(value)
    if entity_type is EntityType.SOCIAL_HANDLE:
        return normalize_social_handle(value)
    normalizer = _NORMALIZERS.get(entity_type)
    if normalizer is None:  # pragma: no cover - defensive
        return value.strip().lower()
    return normalizer(value)


# --------------------------------------------------------------------------- #
# Provenance
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class Observation:
    """Where a fact came from.

    Attached to every entity and relationship so a finding can be traced back
    to the tool run that produced it.
    """

    source: str
    """Tool name, e.g. ``osint.dns``."""

    collected_at: datetime = field(default_factory=utcnow)
    detail: str = ""
    run_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "collected_at": self.collected_at.isoformat(),
            "detail": self.detail,
            "run_id": self.run_id,
        }


# --------------------------------------------------------------------------- #
# Graph elements
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class Entity:
    """A node in the OSINT graph.

    ``value`` holds the observed spelling; ``canonical`` holds the normalized
    form; :attr:`key` (``"type:canonical"``) is the graph identity. Construct
    via :meth:`create` so normalization is never skipped.
    """

    type: EntityType
    value: str
    canonical: str
    attributes: dict[str, Any] = field(default_factory=dict)
    confidence: float = Confidence.OBSERVED
    observations: list[Observation] = field(default_factory=list)
    first_seen: datetime = field(default_factory=utcnow)
    last_seen: datetime = field(default_factory=utcnow)

    @classmethod
    def create(
        cls,
        entity_type: EntityType,
        value: str,
        *,
        attributes: Mapping[str, Any] | None = None,
        confidence: float = Confidence.OBSERVED,
        source: str = "",
        detail: str = "",
    ) -> Entity:
        """Build a normalized entity, raising ``ValueError`` on bad input."""
        canonical = canonicalize(entity_type, value)
        observations = [Observation(source=source, detail=detail)] if source else []
        return cls(
            type=entity_type,
            value=value.strip(),
            canonical=canonical,
            attributes=dict(attributes or {}),
            confidence=Confidence.clamp(confidence),
            observations=observations,
        )

    @property
    def key(self) -> str:
        """Stable graph identity: ``"domain:example.com"``."""
        return f"{self.type.value}:{self.canonical}"

    @property
    def sources(self) -> list[str]:
        """Distinct tool names that observed this entity."""
        seen: list[str] = []
        for observation in self.observations:
            if observation.source and observation.source not in seen:
                seen.append(observation.source)
        return seen

    def merge(self, other: Entity) -> Entity:
        """Fold ``other`` into this entity in place and return ``self``.

        Attributes already present are kept -- the first observation of a fact
        wins -- while new attributes, observations and a higher confidence are
        absorbed. Merging entities with different keys is a programming error.
        """
        if other.key != self.key:
            raise ValueError(
                f"Refusing to merge entities with different keys: "
                f"{self.key!r} vs {other.key!r}"
            )

        for name, attr_value in other.attributes.items():
            self.attributes.setdefault(name, attr_value)

        known = {(o.source, o.detail) for o in self.observations}
        for observation in other.observations:
            if (observation.source, observation.detail) not in known:
                self.observations.append(observation)

        self.confidence = combine_confidence([self.confidence, other.confidence])
        self.first_seen = min(self.first_seen, other.first_seen)
        self.last_seen = max(self.last_seen, other.last_seen)
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "type": self.type.value,
            "value": self.value,
            "canonical": self.canonical,
            "attributes": dict(self.attributes),
            "confidence": round(self.confidence, 4),
            "sources": self.sources,
            "observations": [o.to_dict() for o in self.observations],
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
        }

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Entity {self.key} confidence={self.confidence:.2f}>"


@dataclass(slots=True)
class Relationship:
    """A directed, typed edge between two entities."""

    source_key: str
    target_key: str
    type: EdgeType
    confidence: float = Confidence.OBSERVED
    attributes: dict[str, Any] = field(default_factory=dict)
    observations: list[Observation] = field(default_factory=list)
    first_seen: datetime = field(default_factory=utcnow)
    last_seen: datetime = field(default_factory=utcnow)

    @classmethod
    def create(
        cls,
        source: Entity | str,
        target: Entity | str,
        edge_type: EdgeType,
        *,
        confidence: float = Confidence.OBSERVED,
        attributes: Mapping[str, Any] | None = None,
        source_tool: str = "",
        detail: str = "",
    ) -> Relationship:
        """Build a relationship from entities or their keys."""
        source_key = source.key if isinstance(source, Entity) else source
        target_key = target.key if isinstance(target, Entity) else target
        if source_key == target_key:
            raise ValueError(f"Refusing to create a self-loop on {source_key!r}")
        observations = (
            [Observation(source=source_tool, detail=detail)] if source_tool else []
        )
        return cls(
            source_key=source_key,
            target_key=target_key,
            type=edge_type,
            confidence=Confidence.clamp(confidence),
            attributes=dict(attributes or {}),
            observations=observations,
        )

    @property
    def key(self) -> tuple[str, str, str]:
        """Identity of this edge: ``(source, type, target)``."""
        return (self.source_key, self.type.value, self.target_key)

    @property
    def sources(self) -> list[str]:
        seen: list[str] = []
        for observation in self.observations:
            if observation.source and observation.source not in seen:
                seen.append(observation.source)
        return seen

    def merge(self, other: Relationship) -> Relationship:
        """Fold a duplicate edge into this one, corroborating confidence."""
        if other.key != self.key:
            raise ValueError(
                f"Refusing to merge relationships with different keys: "
                f"{self.key!r} vs {other.key!r}"
            )
        for name, attr_value in other.attributes.items():
            self.attributes.setdefault(name, attr_value)

        known = {(o.source, o.detail) for o in self.observations}
        for observation in other.observations:
            if (observation.source, observation.detail) not in known:
                self.observations.append(observation)

        self.confidence = combine_confidence([self.confidence, other.confidence])
        self.first_seen = min(self.first_seen, other.first_seen)
        self.last_seen = max(self.last_seen, other.last_seen)
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source_key,
            "target": self.target_key,
            "type": self.type.value,
            "confidence": round(self.confidence, 4),
            "attributes": dict(self.attributes),
            "sources": self.sources,
            "observations": [o.to_dict() for o in self.observations],
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
        }

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"<Relationship {self.source_key} -{self.type.value}-> "
            f"{self.target_key} confidence={self.confidence:.2f}>"
        )


def looks_like_email(value: str) -> bool:
    """Cheap structural check used by collectors before creating an entity."""
    return bool(_EMAIL_RE.match(value.strip()))
