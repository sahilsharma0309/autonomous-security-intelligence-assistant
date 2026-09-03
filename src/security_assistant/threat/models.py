"""Threat-intelligence models and their projection into the entity graph.

The scanners in this module produce three different shapes of evidence --
heuristic :class:`Finding` objects derived from the URL itself, third-party
:class:`ReputationVerdict` records, and an observed :class:`SandboxReport` --
and :class:`UrlAssessment` is where they are combined into one score.

**Scoring is a saturating combination, not a sum.** Adding weights lets a
handful of cosmetic observations ("the URL is long", "it has many hyphens")
out-vote one decisive one, and it makes the ceiling an artifact of how many
heuristics happen to exist. Instead, findings are grouped by category, the
strongest signal in each category is taken, and categories are combined with
a noisy-OR -- the same rule Module 2 uses for corroborating observations.
Correlated indicators therefore cannot stack: "long URL" and "many
subdomains" are both structural, so together they count once, plus a small
increment for the corroboration.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum, StrEnum
from typing import Any

from security_assistant.core.types import utcnow
from security_assistant.osint.models import (
    Confidence,
    EdgeType,
    Entity,
    EntityType,
    Relationship,
    hash_algorithm,
    normalize_domain,
    normalize_url,
)

__all__ = [
    "Finding",
    "FindingCategory",
    "RedirectHop",
    "ReputationVerdict",
    "RiskBand",
    "SandboxReport",
    "Severity",
    "UrlAssessment",
    "assessment_to_graph_elements",
    "score_findings",
]

#: How much a single finding of each severity contributes, as a probability
#: that the URL is malicious given only that finding.
SEVERITY_WEIGHTS: dict[str, float] = {
    "info": 0.0,
    "low": 0.08,
    "medium": 0.30,
    "high": 0.65,
    "critical": 0.92,
}

#: Extra credit for each corroborating finding beyond the strongest in a
#: category. Deliberately small: two structural oddities are barely more
#: telling than one, because they tend to have the same underlying cause.
CORROBORATION_BONUS = 0.04


class Severity(StrEnum):
    """How much one finding should move the verdict."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def weight(self) -> float:
        return SEVERITY_WEIGHTS[self.value]


class FindingCategory(StrEnum):
    """What kind of evidence a finding is.

    Findings are grouped by this before scoring, so that several indicators
    with a common cause count once rather than compounding.
    """

    STRUCTURE = "structure"
    """The shape of the URL itself: length, depth, embedded credentials."""

    DECEPTION = "deception"
    """The name is trying to look like something else: typosquat, homoglyph."""

    HOSTING = "hosting"
    """Where it lives: IP literal, suspicious TLD, dynamic-DNS provider."""

    CERTIFICATE = "certificate"
    """TLS problems: expired, self-signed, mismatched, brand-new."""

    REPUTATION = "reputation"
    """Third-party intelligence: VirusTotal, URLScan."""

    BEHAVIOR = "behavior"
    """What the page did when loaded: redirects, credential forms."""

    CONTENT = "content"
    """What the page contained: brand assets, obfuscated script."""


class RiskBand(IntEnum):
    """A coarse label for a 0-100 score.

    Bands exist so that a report can say "suspicious" without implying the
    underlying number is more precise than it is.
    """

    BENIGN = 0
    LOW = 20
    SUSPICIOUS = 40
    HIGH = 60
    CRITICAL = 80

    @classmethod
    def for_score(cls, score: float) -> RiskBand:
        band = cls.BENIGN
        for candidate in (cls.LOW, cls.SUSPICIOUS, cls.HIGH, cls.CRITICAL):
            if score >= candidate.value:
                band = candidate
        return band

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.name.lower()


@dataclass(frozen=True, slots=True)
class Finding:
    """One piece of evidence about a URL."""

    code: str
    """Stable identifier, e.g. ``deceptive_homoglyph``."""

    title: str
    severity: Severity
    category: FindingCategory
    detail: str = ""
    source: str = ""

    @property
    def weight(self) -> float:
        return self.severity.weight

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category.value,
            "detail": self.detail,
            "source": self.source,
        }


def score_findings(findings: Iterable[Finding]) -> float:
    """Combine findings into a 0-100 risk score.

    Strongest-per-category, then noisy-OR across categories. See the module
    docstring for why this is not a sum.

    >>> from security_assistant.threat.models import Finding, FindingCategory, Severity
    >>> one = Finding("a", "A", Severity.HIGH, FindingCategory.DECEPTION)
    >>> round(score_findings([one]))
    65
    >>> # A second finding in the same category adds only corroboration.
    >>> two = Finding("b", "B", Severity.LOW, FindingCategory.DECEPTION)
    >>> round(score_findings([one, two]))
    69
    """
    strongest: dict[str, float] = {}
    extras: dict[str, int] = {}

    for finding in findings:
        category = finding.category.value
        weight = finding.weight
        if category not in strongest:
            strongest[category] = weight
            extras[category] = 0
            continue
        if weight > strongest[category]:
            strongest[category] = weight
        # Only findings that carry weight count as corroboration; an INFO
        # note is context, not evidence.
        if weight > 0.0:
            extras[category] += 1

    complement = 1.0
    for category, weight in strongest.items():
        adjusted = weight
        if weight > 0.0:
            adjusted = min(1.0, weight + CORROBORATION_BONUS * extras[category])
        complement *= 1.0 - adjusted

    return round(100.0 * (1.0 - complement), 2)


@dataclass(frozen=True, slots=True)
class ReputationVerdict:
    """A third-party service's opinion about an indicator."""

    source: str
    """``virustotal`` or ``urlscan``."""

    indicator: str
    indicator_type: str
    """``url``, ``domain``, ``ip_address`` or ``file_hash``."""

    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    categories: tuple[str, ...] = ()
    reputation: int | None = None
    as_of: datetime | None = None
    """When the *service* last saw this, which is not when we asked."""

    raw_verdict: str = ""

    @property
    def total_engines(self) -> int:
        return self.malicious + self.suspicious + self.harmless + self.undetected

    @property
    def detection_ratio(self) -> float:
        """Fraction of deciding engines calling this bad.

        Engines that returned nothing are excluded from the denominator: an
        indicator nobody has analysed should not read as "0% malicious".
        """
        deciding = self.malicious + self.suspicious + self.harmless
        if deciding == 0:
            return 0.0
        return (self.malicious + self.suspicious) / deciding

    def to_finding(self) -> Finding | None:
        """Express this verdict as a scoreable finding, if it says anything."""
        if self.malicious == 0 and self.suspicious == 0:
            return None

        if self.malicious >= 5:
            severity = Severity.CRITICAL
        elif self.malicious >= 2:
            severity = Severity.HIGH
        elif self.malicious == 1:
            # A lone detection is very often a false positive.
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW

        return Finding(
            code=f"reputation_{self.source}",
            title=f"{self.source} reports detections",
            severity=severity,
            category=FindingCategory.REPUTATION,
            detail=(
                f"{self.malicious} malicious / {self.suspicious} suspicious "
                f"of {self.total_engines} engines"
                + (f"; categories: {', '.join(self.categories)}" if self.categories else "")
            ),
            source=self.source,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "indicator": self.indicator,
            "indicator_type": self.indicator_type,
            "malicious": self.malicious,
            "suspicious": self.suspicious,
            "harmless": self.harmless,
            "undetected": self.undetected,
            "total_engines": self.total_engines,
            "detection_ratio": round(self.detection_ratio, 4),
            "categories": list(self.categories),
            "reputation": self.reputation,
            "as_of": self.as_of.isoformat() if self.as_of else None,
            "raw_verdict": self.raw_verdict,
        }


@dataclass(frozen=True, slots=True)
class RedirectHop:
    """One step of a redirect chain."""

    url: str
    status: int = 0
    method: str = "GET"

    def to_dict(self) -> dict[str, Any]:
        return {"url": self.url, "status": self.status, "method": self.method}


@dataclass(slots=True)
class SandboxReport:
    """What was observed loading a URL.

    ``engine`` records which inspector produced this -- ``container`` for a
    real headless browser, ``static`` for the dependency-free HTTP fallback.
    The distinction matters when reading the result: the static inspector
    sees redirects and headers but no script-driven behaviour, so an absent
    behavioural finding means "not looked for", not "not present".
    """

    initial_url: str
    final_url: str = ""
    engine: str = "static"
    chain: list[RedirectHop] = field(default_factory=list)
    status: int = 0
    contacted_domains: list[str] = field(default_factory=list)
    resource_hashes: list[str] = field(default_factory=list)
    console_messages: list[str] = field(default_factory=list)
    dom_excerpt: str = ""
    dom_sha256: str = ""
    screenshot_sha256: str = ""
    screenshot_bytes: int = 0
    title: str = ""
    has_password_input: bool = False
    load_ms: int = 0
    errors: list[str] = field(default_factory=list)
    collected_at: datetime = field(default_factory=utcnow)

    @property
    def redirected(self) -> bool:
        return bool(self.final_url) and self.final_url != self.initial_url

    def to_dict(self) -> dict[str, Any]:
        return {
            "initial_url": self.initial_url,
            "final_url": self.final_url,
            "engine": self.engine,
            "status": self.status,
            "redirected": self.redirected,
            "chain": [hop.to_dict() for hop in self.chain],
            "contacted_domains": list(self.contacted_domains),
            "resource_hashes": list(self.resource_hashes),
            "console_messages": list(self.console_messages),
            "dom_excerpt": self.dom_excerpt,
            "dom_sha256": self.dom_sha256,
            "screenshot_sha256": self.screenshot_sha256,
            "screenshot_bytes": self.screenshot_bytes,
            "title": self.title,
            "has_password_input": self.has_password_input,
            "load_ms": self.load_ms,
            "errors": list(self.errors),
            "collected_at": self.collected_at.isoformat(),
        }


@dataclass(slots=True)
class UrlAssessment:
    """Everything known about one URL, and the score that follows from it."""

    url: str
    findings: list[Finding] = field(default_factory=list)
    verdicts: list[ReputationVerdict] = field(default_factory=list)
    sandbox: SandboxReport | None = None
    assessed_at: datetime = field(default_factory=utcnow)

    @property
    def all_findings(self) -> list[Finding]:
        """Heuristic findings plus those implied by reputation verdicts."""
        combined = list(self.findings)
        for verdict in self.verdicts:
            finding = verdict.to_finding()
            if finding is not None:
                combined.append(finding)
        return combined

    @property
    def risk_score(self) -> float:
        return score_findings(self.all_findings)

    @property
    def risk_band(self) -> RiskBand:
        return RiskBand.for_score(self.risk_score)

    def top_findings(self, limit: int = 5) -> list[Finding]:
        return sorted(self.all_findings, key=lambda f: -f.weight)[:limit]

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "risk_score": self.risk_score,
            "risk_band": str(self.risk_band),
            "findings": [f.to_dict() for f in self.all_findings],
            "verdicts": [v.to_dict() for v in self.verdicts],
            "sandbox": self.sandbox.to_dict() if self.sandbox else None,
            "assessed_at": self.assessed_at.isoformat(),
        }


def _host_entity(host: str, source: str, detail: str) -> Entity | None:
    """Build a domain or ip_address entity from a bare host."""
    if not host:
        return None
    try:
        return Entity.create(
            EntityType.IP_ADDRESS, host, source=source, detail=detail
        )
    except ValueError:
        pass
    try:
        return Entity.create(EntityType.DOMAIN, host, source=source, detail=detail)
    except ValueError:
        return None


def _host_of(url: str) -> str:
    from urllib.parse import urlsplit

    try:
        return (urlsplit(url).hostname or "").strip("[]")
    except ValueError:  # pragma: no cover - defensive
        return ""


def assessment_to_graph_elements(
    assessment: UrlAssessment, *, source: str = "threat.url_score"
) -> tuple[list[Entity], list[Relationship]]:
    """Project an assessment into graph entities and relationships.

    The URL becomes a node carrying its score; its host becomes a domain or
    address node, which is the join point with everything OSINT and IoT
    already discovered. Redirect hops, contacted domains and resource hashes
    become their own nodes so that two different phishing URLs sharing a
    redirect target are visibly connected.
    """
    entities: list[Entity] = []
    relationships: list[Relationship] = []

    try:
        root = Entity.create(
            EntityType.URL,
            assessment.url,
            source=source,
            detail="assessed url",
            attributes={
                "risk_score": assessment.risk_score,
                "risk_band": str(assessment.risk_band),
                "finding_codes": [f.code for f in assessment.all_findings],
            },
        )
    except ValueError:
        return [], []
    entities.append(root)

    def link(
        target: Entity | None, edge: EdgeType, confidence: float, detail: str
    ) -> None:
        if target is None or target.key == root.key:
            return
        entities.append(target)
        relationships.append(
            Relationship.create(
                root, target, edge, confidence=confidence, source_tool=source, detail=detail
            )
        )

    link(
        _host_entity(_host_of(assessment.url), source, "url host"),
        EdgeType.SERVED_BY,
        Confidence.OBSERVED,
        "host of the assessed URL",
    )

    sandbox = assessment.sandbox
    if sandbox is not None:
        previous = root
        for hop in sandbox.chain:
            try:
                hop_entity = Entity.create(
                    EntityType.URL,
                    hop.url,
                    source=source,
                    detail=f"redirect hop (status {hop.status})",
                )
            except ValueError:
                continue
            if hop_entity.key == previous.key:
                continue
            entities.append(hop_entity)
            relationships.append(
                Relationship.create(
                    previous,
                    hop_entity,
                    EdgeType.REDIRECTS_TO,
                    confidence=Confidence.OBSERVED,
                    attributes={"status": hop.status},
                    source_tool=source,
                    detail="observed redirect",
                )
            )
            # Each hop's own host is a join point too.
            host = _host_entity(_host_of(hop.url), source, "redirect host")
            if host is not None and host.key != hop_entity.key:
                entities.append(host)
                relationships.append(
                    Relationship.create(
                        hop_entity,
                        host,
                        EdgeType.SERVED_BY,
                        confidence=Confidence.OBSERVED,
                        source_tool=source,
                        detail="host of redirect hop",
                    )
                )
            previous = hop_entity

        for domain in sandbox.contacted_domains:
            try:
                contacted = Entity.create(
                    EntityType.DOMAIN,
                    domain,
                    source=source,
                    detail="contacted during page load",
                )
            except ValueError:
                continue
            link(
                contacted,
                EdgeType.CONTACTS,
                # The page reached it, which is observed; that it matters is
                # not.
                Confidence.OBSERVED,
                "third-party host contacted during load",
            )

        for digest in sandbox.resource_hashes:
            try:
                file_entity = Entity.create(
                    EntityType.FILE_HASH,
                    digest,
                    source=source,
                    detail="resource served by page",
                    attributes={"algorithm": hash_algorithm(digest)},
                )
            except ValueError:
                continue
            link(
                file_entity,
                EdgeType.REFERENCES_FILE,
                Confidence.OBSERVED,
                "resource observed during load",
            )

    return entities, relationships


def verdicts_to_graph_elements(
    verdicts: Sequence[ReputationVerdict], *, source: str = "threat.virustotal"
) -> tuple[list[Entity], list[Relationship]]:
    """Project standalone reputation verdicts onto their indicator nodes.

    Used by the lookup tools, which have a verdict but no full assessment.
    Reputation is recorded as attributes on the indicator rather than as its
    own node -- "VirusTotal said so" is a property of the thing, not a thing.
    """
    entities: list[Entity] = []

    for verdict in verdicts:
        attributes: dict[str, Any] = {
            f"{verdict.source}_malicious": verdict.malicious,
            f"{verdict.source}_suspicious": verdict.suspicious,
            f"{verdict.source}_detection_ratio": round(verdict.detection_ratio, 4),
        }
        if verdict.categories:
            attributes[f"{verdict.source}_categories"] = list(verdict.categories)
        if verdict.as_of is not None:
            attributes[f"{verdict.source}_as_of"] = verdict.as_of.isoformat()

        entity: Entity | None
        try:
            if verdict.indicator_type == "url":
                entity = Entity.create(
                    EntityType.URL,
                    verdict.indicator,
                    source=source,
                    detail=f"{verdict.source} verdict",
                    attributes=attributes,
                )
            elif verdict.indicator_type == "file_hash":
                entity = Entity.create(
                    EntityType.FILE_HASH,
                    verdict.indicator,
                    source=source,
                    detail=f"{verdict.source} verdict",
                    attributes=attributes,
                )
            else:
                entity = _host_entity(
                    verdict.indicator, source, f"{verdict.source} verdict"
                )
                if entity is not None:
                    entity.attributes.update(attributes)
        except ValueError:
            continue
        if entity is not None:
            entities.append(entity)

    return entities, []


def parse_url_or_none(value: str) -> str | None:
    """Canonicalize a URL, returning ``None`` instead of raising."""
    try:
        return normalize_url(value)
    except ValueError:
        return None


def registrable_domain(host: str) -> str:
    """Best-effort registrable domain (``a.b.example.co.uk`` -> ``example.co.uk``).

    Without the public-suffix list this cannot be exact, so it uses a small
    table of common multi-label suffixes and otherwise takes the last two
    labels. It is used for comparison heuristics only -- never for an
    authorization decision, where an approximation would be unsafe.
    """
    try:
        normalized = normalize_domain(host)
    except ValueError:
        return ""
    labels = normalized.split(".")
    if len(labels) <= 2:
        return normalized
    last_two = ".".join(labels[-2:])
    if last_two in _MULTI_LABEL_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last_two


_MULTI_LABEL_SUFFIXES = frozenset(
    {
        "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk",
        "com.au", "net.au", "org.au", "edu.au", "gov.au",
        "co.nz", "net.nz", "org.nz", "co.za", "co.jp", "ne.jp", "or.jp",
        "com.br", "com.cn", "com.mx", "com.tr", "com.tw", "com.sg", "com.hk",
        "co.in", "co.kr", "co.il", "com.ar", "com.co", "com.pe", "com.ua",
    }
)


def hosts_in_assessment(assessment: UrlAssessment) -> list[str]:
    """Every distinct host the assessment touched, in order of first sight."""
    found: list[str] = []

    def add(host: str) -> None:
        if host and host not in found:
            found.append(host)

    add(_host_of(assessment.url))
    if assessment.sandbox is not None:
        for hop in assessment.sandbox.chain:
            add(_host_of(hop.url))
        for domain in assessment.sandbox.contacted_domains:
            add(domain)
    return found


def merge_verdicts(
    verdicts: Iterable[ReputationVerdict],
) -> dict[str, list[ReputationVerdict]]:
    """Group verdicts by indicator for reporting."""
    grouped: dict[str, list[ReputationVerdict]] = {}
    for verdict in verdicts:
        grouped.setdefault(verdict.indicator, []).append(verdict)
    return grouped


def summarize(assessments: Sequence[UrlAssessment]) -> Mapping[str, Any]:
    """Aggregate several assessments for a run-level report."""
    if not assessments:
        return {"count": 0, "max_score": 0.0, "bands": {}}
    bands: dict[str, int] = {}
    for assessment in assessments:
        key = str(assessment.risk_band)
        bands[key] = bands.get(key, 0) + 1
    return {
        "count": len(assessments),
        "max_score": max(a.risk_score for a in assessments),
        "bands": bands,
    }
