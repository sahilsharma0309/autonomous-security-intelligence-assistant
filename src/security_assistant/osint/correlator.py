"""Correlation and entity resolution.

Collectors produce overlapping, partly-contradictory observations. This module
turns that pile into a coherent graph by doing two distinct jobs that are
easy to conflate:

**Entity resolution** decides when two *nodes* are the same real-world thing.
Exact canonical matches are already handled at insertion time by
:meth:`EntityGraph.add_entity`, so what is left here is the genuinely
ambiguous cases: organizations whose names differ cosmetically, domains that
differ only by a ``www.`` prefix, handles that restate an email local part.
Each candidate pair gets a score and a human-readable rationale, and only pairs
above a threshold are merged.

**Link inference** decides when two nodes are *related* without being the same,
adding edges the collectors could not see individually -- shared infrastructure
implying common ownership, subdomain containment, an email domain matching a
known domain.

Both are deliberately conservative. A false merge is far more damaging than a
missed one: it silently fuses two organizations' infrastructure into one
picture, and every conclusion drawn afterwards is wrong in a way that is very
hard to notice. So every rule states its evidence, scores are combined with a
noisy-OR rather than summed, and the default threshold is high.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Any

from security_assistant.osint.graph import EntityGraph
from security_assistant.osint.models import (
    Confidence,
    EdgeType,
    Entity,
    EntityType,
    Relationship,
    combine_confidence,
)

logger = logging.getLogger(__name__)

__all__ = [
    "CorrelationReport",
    "Correlator",
    "CorrelatorConfig",
    "MatchEvidence",
    "MergeCandidate",
    "string_similarity",
]

# Free/disposable providers: a shared email domain here says nothing about
# shared ownership, so the correlator must not treat it as evidence.
PUBLIC_EMAIL_DOMAINS = frozenset(
    {
        "gmail.com", "googlemail.com", "yahoo.com", "hotmail.com", "outlook.com",
        "live.com", "aol.com", "icloud.com", "me.com", "proton.me",
        "protonmail.com", "gmx.com", "mail.com", "yandex.ru", "zoho.com",
        "tutanota.com", "fastmail.com", "hushmail.com", "pm.me",
    }
)

#: Confidence that ``www.X`` and ``X`` are one identity. Deliberately above the
#: default merge threshold: the convention is near-universal, and the merge
#: preserves the alias spelling, so the operation is recoverable.
WWW_ALIAS_CONFIDENCE = 0.9

# Certificate issuers and large hosts legitimately appear across unrelated
# targets; shared infrastructure with them implies nothing about ownership.
GENERIC_ORG_TOKENS = frozenset(
    {
        "let s encrypt", "lets encrypt", "digicert", "sectigo", "comodo",
        "godaddy", "cloudflare", "amazon", "google trust services", "globalsign",
        "identrust", "entrust", "verisign", "namecheap", "tucows", "markmonitor",
    }
)


def string_similarity(left: str, right: str) -> float:
    """Ratio in ``[0, 1]`` of how similar two strings are.

    Uses :class:`difflib.SequenceMatcher`, which is in the standard library and
    good enough for the short names involved here. Empty inputs score 0.

    >>> string_similarity("acme corp", "acme corporation") > 0.7
    True
    >>> string_similarity("acme", "zenith")
    0.0
    """
    if not left or not right:
        return 0.0
    if left == right:
        return 1.0
    ratio = SequenceMatcher(None, left, right).ratio()
    # SequenceMatcher gives short unrelated strings a misleading floor; treat
    # weak similarity as no evidence at all.
    return ratio if ratio >= 0.5 else 0.0


@dataclass(frozen=True, slots=True)
class MatchEvidence:
    """One reason to believe two entities are the same."""

    rule: str
    score: float
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {"rule": self.rule, "score": round(self.score, 4), "detail": self.detail}


@dataclass(slots=True)
class MergeCandidate:
    """A proposed entity resolution between two nodes."""

    primary_key: str
    duplicate_key: str
    evidence: list[MatchEvidence] = field(default_factory=list)

    @property
    def score(self) -> float:
        """Combined confidence across all evidence (noisy-OR)."""
        return combine_confidence(e.score for e in self.evidence)

    @property
    def rationale(self) -> str:
        return "; ".join(f"{e.rule}: {e.detail}" for e in self.evidence)

    def to_dict(self) -> dict[str, Any]:
        return {
            "primary": self.primary_key,
            "duplicate": self.duplicate_key,
            "score": round(self.score, 4),
            "evidence": [e.to_dict() for e in self.evidence],
            "rationale": self.rationale,
        }


@dataclass(slots=True)
class CorrelationReport:
    """What a correlation pass did."""

    merged: list[MergeCandidate] = field(default_factory=list)
    proposed: list[MergeCandidate] = field(default_factory=list)
    """Candidates that scored above the review floor but below the merge
    threshold -- surfaced for an analyst rather than applied."""

    inferred: list[Relationship] = field(default_factory=list)
    entities_before: int = 0
    entities_after: int = 0

    @property
    def entities_removed(self) -> int:
        return max(0, self.entities_before - self.entities_after)

    def to_dict(self) -> dict[str, Any]:
        return {
            "entities_before": self.entities_before,
            "entities_after": self.entities_after,
            "entities_removed": self.entities_removed,
            "merged": [c.to_dict() for c in self.merged],
            "proposed_for_review": [c.to_dict() for c in self.proposed],
            "inferred_relationships": [r.to_dict() for r in self.inferred],
        }

    def summary(self) -> str:
        return (
            f"merged {len(self.merged)} duplicate(s), "
            f"proposed {len(self.proposed)} for review, "
            f"inferred {len(self.inferred)} relationship(s); "
            f"{self.entities_before} -> {self.entities_after} entities"
        )


@dataclass(slots=True)
class CorrelatorConfig:
    """Thresholds governing how aggressive correlation is."""

    merge_threshold: float = 0.85
    """Score at or above which a merge is applied automatically."""

    review_threshold: float = 0.6
    """Score at or above which a candidate is surfaced for human review."""

    organization_similarity: float = 0.88
    """Name similarity required to consider two orgs the same."""

    infer_shared_infrastructure: bool = True
    infer_subdomains: bool = True
    infer_email_domains: bool = True
    max_shared_ip_fanout: int = 8
    """Above this many domains on one IP, treat it as shared hosting and stop
    inferring common ownership from it."""

    def __post_init__(self) -> None:
        if not 0.0 < self.merge_threshold <= 1.0:
            raise ValueError("merge_threshold must be in (0, 1]")
        if not 0.0 <= self.review_threshold <= self.merge_threshold:
            raise ValueError("review_threshold must be in [0, merge_threshold]")
        if self.max_shared_ip_fanout < 1:
            raise ValueError("max_shared_ip_fanout must be >= 1")


class Correlator:
    """Resolves duplicate entities and infers missing relationships.

    >>> correlator = Correlator()
    >>> report = correlator.correlate(graph)          # doctest: +SKIP
    >>> print(report.summary())                       # doctest: +SKIP
    """

    def __init__(self, config: CorrelatorConfig | None = None) -> None:
        self._config = config or CorrelatorConfig()

    @property
    def config(self) -> CorrelatorConfig:
        return self._config

    # -- public API -------------------------------------------------------- #
    def correlate(self, graph: EntityGraph, *, apply: bool = True) -> CorrelationReport:
        """Run entity resolution and link inference over ``graph``.

        With ``apply=False`` nothing is mutated and the report describes what
        *would* happen -- useful for reviewing a correlation pass before
        committing to it.
        """
        report = CorrelationReport(entities_before=len(graph))

        candidates = self.find_duplicates(graph)
        for candidate in candidates:
            if candidate.score >= self._config.merge_threshold:
                report.merged.append(candidate)
                if apply:
                    self._apply_merge(graph, candidate)
            elif candidate.score >= self._config.review_threshold:
                report.proposed.append(candidate)

        inferred = self.infer_relationships(graph)
        report.inferred = inferred
        if apply:
            for relationship in inferred:
                try:
                    graph.add_relationship(relationship)
                except KeyError:  # pragma: no cover - endpoint merged away
                    logger.debug("Skipping inferred edge with missing endpoint")

        report.entities_after = len(graph)
        logger.info("Correlation complete: %s", report.summary())
        return report

    def find_duplicates(self, graph: EntityGraph) -> list[MergeCandidate]:
        """Find candidate entity resolutions, highest-scoring first.

        Only compares entities of the same type, and only within the types
        where cosmetic variation is actually expected. Comparison is quadratic
        within a type, which is fine for engagement-sized graphs.
        """
        candidates: list[MergeCandidate] = []
        candidates.extend(self._organization_duplicates(graph))
        candidates.extend(self._domain_duplicates(graph))
        candidates.extend(self._handle_email_matches(graph))
        candidates.sort(key=lambda c: (-c.score, c.primary_key, c.duplicate_key))
        return candidates

    def infer_relationships(self, graph: EntityGraph) -> list[Relationship]:
        """Infer relationships the individual collectors could not see."""
        inferred: list[Relationship] = []
        if self._config.infer_subdomains:
            inferred.extend(self._infer_subdomains(graph))
        if self._config.infer_shared_infrastructure:
            inferred.extend(self._infer_shared_infrastructure(graph))
        if self._config.infer_email_domains:
            inferred.extend(self._infer_email_domains(graph))

        # Never propose an edge the graph already has.
        existing = {r.key for r in graph.relationships}
        deduped: list[Relationship] = []
        seen: set[tuple[str, str, str]] = set()
        for relationship in inferred:
            if relationship.key in existing or relationship.key in seen:
                continue
            seen.add(relationship.key)
            deduped.append(relationship)
        return deduped

    def score_pair(self, left: Entity, right: Entity) -> MergeCandidate | None:
        """Score one specific pair, or return ``None`` if they are unrelated."""
        if left.type is not right.type or left.key == right.key:
            return None
        if left.type is EntityType.ORGANIZATION:
            return self._score_organizations(left, right)
        if left.type is EntityType.DOMAIN:
            return self._score_domains(left, right)
        return None

    # -- entity resolution rules ------------------------------------------ #
    def _organization_duplicates(self, graph: EntityGraph) -> list[MergeCandidate]:
        organizations = graph.by_type(EntityType.ORGANIZATION)
        found: list[MergeCandidate] = []
        for index, left in enumerate(organizations):
            for right in organizations[index + 1 :]:
                candidate = self._score_organizations(left, right)
                if candidate is not None:
                    found.append(candidate)
        return found

    def _score_organizations(self, left: Entity, right: Entity) -> MergeCandidate | None:
        # Certificate issuers and registrars appear across unrelated targets;
        # merging them together would fuse everything they touch.
        if self._is_generic_org(left) or self._is_generic_org(right):
            return None

        similarity = string_similarity(left.canonical, right.canonical)
        if similarity < self._config.organization_similarity:
            return None

        primary, duplicate = self._order(left, right)
        evidence = [
            MatchEvidence(
                rule="organization_name_similarity",
                score=similarity,
                detail=(
                    f"{primary.canonical!r} ~ {duplicate.canonical!r} "
                    f"(similarity {similarity:.2f})"
                ),
            )
        ]
        if left.canonical == right.canonical:
            evidence.append(
                MatchEvidence(
                    rule="canonical_name_equal",
                    score=Confidence.STRONG,
                    detail=f"identical normalized name {left.canonical!r}",
                )
            )
        return MergeCandidate(primary.key, duplicate.key, evidence)

    def _domain_duplicates(self, graph: EntityGraph) -> list[MergeCandidate]:
        domains = graph.by_type(EntityType.DOMAIN)
        by_canonical = {d.canonical: d for d in domains}
        found: list[MergeCandidate] = []

        for domain in domains:
            if not domain.canonical.startswith("www."):
                continue
            bare = domain.canonical[4:]
            counterpart = by_canonical.get(bare)
            if counterpart is None:
                continue

            # The bare domain is the canonical identity; www is the alias, and
            # the merge keeps its spelling in `attributes["aliases"]`, so no
            # observation is lost.
            evidence = [
                MatchEvidence(
                    rule="www_prefix",
                    score=WWW_ALIAS_CONFIDENCE,
                    detail=f"{domain.canonical!r} is the www alias of {bare!r}",
                )
            ]

            # ...unless they demonstrably resolve to different infrastructure,
            # in which case they are two distinct hosts that happen to share a
            # name, and merging them would fuse unrelated systems.
            alias_addresses = self._resolved_addresses(graph, domain.key)
            apex_addresses = self._resolved_addresses(graph, counterpart.key)
            if alias_addresses and apex_addresses and not (alias_addresses & apex_addresses):
                evidence = [
                    MatchEvidence(
                        rule="www_prefix_conflicting_resolution",
                        score=self._config.review_threshold,
                        detail=(
                            f"{domain.canonical!r} and {bare!r} resolve to disjoint "
                            f"addresses ({sorted(alias_addresses)} vs "
                            f"{sorted(apex_addresses)}); flagged for review "
                            "rather than merged"
                        ),
                    )
                ]

            found.append(
                MergeCandidate(
                    primary_key=counterpart.key,
                    duplicate_key=domain.key,
                    evidence=evidence,
                )
            )
        return found

    @staticmethod
    def _resolved_addresses(graph: EntityGraph, key: str) -> set[str]:
        """Addresses a domain is known to resolve to."""
        return {
            edge.target_key
            for edge in graph.out_edges(key)
            if edge.type is EdgeType.RESOLVES_TO
        }

    def _score_domains(self, left: Entity, right: Entity) -> MergeCandidate | None:
        """Score two domains as the same host (currently the www case).

        This is the graph-free pairwise form used by :meth:`score_pair`; the
        conflicting-resolution check in :meth:`_domain_duplicates` needs edges
        and so cannot apply here.
        """
        for a, b in ((left, right), (right, left)):
            if a.canonical == f"www.{b.canonical}":
                return MergeCandidate(
                    primary_key=b.key,
                    duplicate_key=a.key,
                    evidence=[
                        MatchEvidence(
                            rule="www_prefix",
                            score=WWW_ALIAS_CONFIDENCE,
                            detail=f"{a.canonical!r} is the www alias of {b.canonical!r}",
                        )
                    ],
                )
        return None

    def _handle_email_matches(self, graph: EntityGraph) -> list[MergeCandidate]:
        """Link social handles to emails sharing a local part.

        This does *not* merge -- an email and a handle are different entity
        types and different things. It is recorded as inference elsewhere; here
        it only contributes when the handle is literally an email address.
        """
        found: list[MergeCandidate] = []
        handles = graph.by_type(EntityType.SOCIAL_HANDLE)
        emails = {e.canonical for e in graph.by_type(EntityType.EMAIL)}

        for handle in handles:
            _, _, bare = handle.canonical.rpartition("/")
            if bare in emails:
                found.append(
                    MergeCandidate(
                        primary_key=f"{EntityType.EMAIL.value}:{bare}",
                        duplicate_key=handle.key,
                        evidence=[
                            MatchEvidence(
                                rule="handle_is_email",
                                score=Confidence.MODERATE,
                                detail=f"handle {handle.canonical!r} is the email {bare!r}",
                            )
                        ],
                    )
                )
        return found

    @staticmethod
    def _is_generic_org(entity: Entity) -> bool:
        canonical = entity.canonical
        return any(token in canonical for token in GENERIC_ORG_TOKENS)

    @staticmethod
    def _order(left: Entity, right: Entity) -> tuple[Entity, Entity]:
        """Pick which entity survives a merge.

        The better-corroborated node wins; ties break on the key so the result
        is deterministic across runs.
        """
        left_rank = (len(left.sources), left.confidence, right.key)
        right_rank = (len(right.sources), right.confidence, left.key)
        return (left, right) if left_rank >= right_rank else (right, left)

    def _apply_merge(self, graph: EntityGraph, candidate: MergeCandidate) -> None:
        try:
            graph.merge_entities(candidate.primary_key, candidate.duplicate_key)
        except (KeyError, ValueError) as exc:
            # An earlier merge in the same pass may already have consumed one
            # side; that is expected, not an error.
            logger.debug(
                "Skipping merge %s <- %s: %s",
                candidate.primary_key,
                candidate.duplicate_key,
                exc,
            )

    # -- link inference rules ---------------------------------------------- #
    def _infer_subdomains(self, graph: EntityGraph) -> list[Relationship]:
        """Add ``SUBDOMAIN_OF`` edges from structural containment."""
        domains = graph.by_type(EntityType.DOMAIN)
        by_canonical = {d.canonical: d for d in domains}
        inferred: list[Relationship] = []

        for domain in domains:
            labels = domain.canonical.split(".")
            # Walk up the parents, stopping before the public-suffix-ish tail.
            for index in range(1, len(labels) - 1):
                parent_name = ".".join(labels[index:])
                parent = by_canonical.get(parent_name)
                if parent is None or parent.key == domain.key:
                    continue
                inferred.append(
                    Relationship.create(
                        domain,
                        parent,
                        EdgeType.SUBDOMAIN_OF,
                        confidence=Confidence.CERTAIN,
                        source_tool="osint.correlator",
                        detail="structural subdomain containment",
                    )
                )
                break
        return inferred

    def _infer_shared_infrastructure(self, graph: EntityGraph) -> list[Relationship]:
        """Associate domains that resolve to the same address.

        Skipped for addresses with high fan-out: on shared hosting or a CDN,
        co-residency says nothing about common ownership.
        """
        inferred: list[Relationship] = []

        for address in graph.by_type(EntityType.IP_ADDRESS):
            resolvers = [
                edge.source_key
                for edge in graph.in_edges(address.key)
                if edge.type is EdgeType.RESOLVES_TO
            ]
            if not 2 <= len(resolvers) <= self._config.max_shared_ip_fanout:
                continue

            for index, left_key in enumerate(sorted(resolvers)):
                for right_key in sorted(resolvers)[index + 1 :]:
                    left = graph.get(left_key)
                    right = graph.get(right_key)
                    if left is None or right is None:
                        continue
                    inferred.append(
                        Relationship.create(
                            left,
                            right,
                            EdgeType.ASSOCIATED_WITH,
                            # Co-residency is a hint, not proof of ownership.
                            confidence=Confidence.WEAK,
                            attributes={"via": address.canonical},
                            source_tool="osint.correlator",
                            detail=f"both resolve to {address.canonical}",
                        )
                    )
        return inferred

    def _infer_email_domains(self, graph: EntityGraph) -> list[Relationship]:
        """Link an email to the domain entity of its own domain part."""
        domains = {d.canonical: d for d in graph.by_type(EntityType.DOMAIN)}
        inferred: list[Relationship] = []

        for email in graph.by_type(EntityType.EMAIL):
            _, _, domain_part = email.canonical.rpartition("@")
            if domain_part in PUBLIC_EMAIL_DOMAINS:
                continue
            domain = domains.get(domain_part)
            if domain is None:
                continue
            inferred.append(
                Relationship.create(
                    domain,
                    email,
                    EdgeType.USES_EMAIL,
                    confidence=Confidence.STRONG,
                    source_tool="osint.correlator",
                    detail=f"email domain matches {domain_part}",
                )
            )
        return inferred

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"<Correlator merge_threshold={self._config.merge_threshold} "
            f"review_threshold={self._config.review_threshold}>"
        )


def build_graph_from_payloads(
    payloads: Iterable[Sequence[dict[str, Any]] | dict[str, Any]],
    *,
    name: str = "osint",
) -> EntityGraph:
    """Assemble a graph from collector tool return values.

    Each collector returns ``{"entities": [...], "relationships": [...]}``;
    this folds any number of those into one graph. Relationships whose
    endpoints are missing are skipped rather than raising, because collectors
    run independently and one may legitimately fail.
    """
    from security_assistant.osint.graph import (
        _entity_from_dict,
        _relationship_from_dict,
    )

    graph = EntityGraph(name=name)
    pending: list[dict[str, Any]] = []

    for payload in payloads:
        if not isinstance(payload, dict):
            continue
        for raw in payload.get("entities", []) or []:
            try:
                graph.add_entity(_entity_from_dict(raw))
            except (KeyError, ValueError) as exc:
                logger.debug("Skipping malformed entity payload: %s", exc)
        pending.extend(payload.get("relationships", []) or [])

    for raw in pending:
        try:
            graph.add_relationship(_relationship_from_dict(raw))
        except (KeyError, ValueError) as exc:
            logger.debug("Skipping relationship with missing endpoint: %s", exc)

    return graph
