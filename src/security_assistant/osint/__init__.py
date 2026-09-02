"""OSINT & Entity Graph module.

Collects open-source intelligence about an authorized target and assembles it
into a Maltego-style link graph: typed entities (domains, IPs, emails, phone
numbers, social handles, organizations) joined by typed, confidence-weighted
relationships, every one traceable back to the tool that observed it.

Typical wiring::

    from security_assistant.core import Agent, AuthorizationScope, RiskLevel, ToolRegistry
    from security_assistant.osint import ALL_COLLECTORS, Correlator, build_graph_from_payloads

    registry = ToolRegistry()
    registry.register_all(ALL_COLLECTORS)

    scope = AuthorizationScope(
        allow=["example.com"], max_risk=RiskLevel.ACTIVE,
        authorization_reference="ENG-2024-114",
    )
    result = await Agent(registry, scope).run("Map surface", target="example.com")

    graph = build_graph_from_payloads(result.values_by_tool().values())
    report = Correlator().correlate(graph)
    print(graph.to_json())

The collectors are scope-gated by the core dispatcher, so nothing here
contacts a target the engagement has not authorized.
"""

from __future__ import annotations

from security_assistant.osint.collectors import (
    ALL_COLLECTORS,
    CollectorError,
    PlatformHook,
    dns_collect,
    social_footprint,
    tls_collect,
    whois_collect,
)
from security_assistant.osint.correlator import (
    CorrelationReport,
    Correlator,
    CorrelatorConfig,
    MatchEvidence,
    MergeCandidate,
    build_graph_from_payloads,
    string_similarity,
)
from security_assistant.osint.graph import (
    EntityGraph,
    GraphStats,
    NetworkXNotInstalledError,
)
from security_assistant.osint.models import (
    Confidence,
    EdgeType,
    Entity,
    EntityType,
    Observation,
    Relationship,
    combine_confidence,
    normalize_domain,
    normalize_email,
    normalize_organization,
    normalize_phone,
    normalize_social_handle,
)

__all__ = [
    # Collectors
    "ALL_COLLECTORS",
    "CollectorError",
    "PlatformHook",
    "dns_collect",
    "social_footprint",
    "tls_collect",
    "whois_collect",
    # Graph
    "EntityGraph",
    "GraphStats",
    "NetworkXNotInstalledError",
    # Models
    "Confidence",
    "EdgeType",
    "Entity",
    "EntityType",
    "Observation",
    "Relationship",
    "combine_confidence",
    "normalize_domain",
    "normalize_email",
    "normalize_organization",
    "normalize_phone",
    "normalize_social_handle",
    # Correlation
    "CorrelationReport",
    "Correlator",
    "CorrelatorConfig",
    "MatchEvidence",
    "MergeCandidate",
    "build_graph_from_payloads",
    "string_similarity",
]
