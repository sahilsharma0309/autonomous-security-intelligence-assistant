"""Threat Intelligence & URL Deep Scanner.

Assesses a URL from three independent directions and combines them into one
0-100 score:

* **Heuristics** (:mod:`~security_assistant.threat.analyzer`) -- typosquatting,
  homoglyphs, deceptive structure, suspicious hosting, TLS problems. Contacts
  nothing.
* **Reputation** (:mod:`~security_assistant.threat.virustotal`,
  :mod:`~security_assistant.threat.urlscan`) -- what third-party services
  already know.
* **Observation** (:mod:`~security_assistant.threat.sandbox`) -- what actually
  happens when the page is loaded, behind a container boundary.

Findings, URLs, hosts and file hashes are projected into the Module 2 entity
graph, so a phishing URL and infrastructure discovered by OSINT or IoT recon
meet at the shared domain and address nodes.

Typical wiring::

    from security_assistant.core import Agent, AuthorizationScope, RiskLevel, ToolRegistry
    from security_assistant.threat import ALL_THREAT_TOOLS

    registry = ToolRegistry()
    registry.register_all(ALL_THREAT_TOOLS)

    scope = AuthorizationScope(
        allow=["suspicious.example"], max_risk=RiskLevel.ACTIVE,
        authorization_reference="IR-2024-88",
    )
    result = await Agent(registry, scope).run(
        "Assess this link", target="https://suspicious.example/login"
    )

Safety notes worth reading before use:

* :mod:`~security_assistant.threat.safety` refuses to fetch loopback, private
  and link-local addresses. This scanner takes URLs chosen by an adversary,
  so without that check it is an SSRF gadget aimed at its own host.
* The sandbox executes attacker-controlled JavaScript. It does so in a
  throwaway, non-root, capability-dropped, read-only container on an
  egress-controlled network, and degrades to script-free HTTP inspection when
  no container runtime exists -- marking the report ``engine="static"`` so the
  reduced coverage is visible.
"""

from __future__ import annotations

from security_assistant.threat.analyzer import (
    AnalyzerConfig,
    UrlAnalyzer,
    confusable_skeleton,
    edit_distance,
    looks_like_homoglyph,
)
from security_assistant.threat.models import (
    Finding,
    FindingCategory,
    RedirectHop,
    ReputationVerdict,
    RiskBand,
    SandboxReport,
    Severity,
    UrlAssessment,
    assessment_to_graph_elements,
    registrable_domain,
    score_findings,
)
from security_assistant.threat.safety import (
    UnsafeUrlError,
    assert_fetchable,
    is_blocked_address,
    is_fetchable,
)
from security_assistant.threat.sandbox import (
    ContainerSandbox,
    SandboxConfig,
    SandboxError,
    SandboxInspector,
    SandboxUnavailableError,
    StaticInspector,
    default_inspector,
)
from security_assistant.threat.tools import (
    ALL_THREAT_TOOLS,
    ThreatToolError,
    domain_reputation,
    url_analyze,
    url_inspect,
    url_score,
    urlscan_search,
    urlscan_submit,
)
from security_assistant.threat.urlscan import (
    SubmitOptions,
    UrlscanClient,
    UrlscanError,
    default_urlscan_client,
)
from security_assistant.threat.virustotal import (
    TokenBucket,
    VirusTotalClient,
    VirusTotalError,
    default_virustotal_client,
)

__all__ = [
    # Tools
    "ALL_THREAT_TOOLS",
    "ThreatToolError",
    "domain_reputation",
    "url_analyze",
    "url_inspect",
    "url_score",
    "urlscan_search",
    "urlscan_submit",
    # Models
    "Finding",
    "FindingCategory",
    "RedirectHop",
    "ReputationVerdict",
    "RiskBand",
    "SandboxReport",
    "Severity",
    "UrlAssessment",
    "assessment_to_graph_elements",
    "registrable_domain",
    "score_findings",
    # Analysis
    "AnalyzerConfig",
    "UrlAnalyzer",
    "confusable_skeleton",
    "edit_distance",
    "looks_like_homoglyph",
    # Sandbox
    "ContainerSandbox",
    "SandboxConfig",
    "SandboxError",
    "SandboxInspector",
    "SandboxUnavailableError",
    "StaticInspector",
    "default_inspector",
    # Safety
    "UnsafeUrlError",
    "assert_fetchable",
    "is_blocked_address",
    "is_fetchable",
    # Clients
    "SubmitOptions",
    "TokenBucket",
    "UrlscanClient",
    "UrlscanError",
    "VirusTotalClient",
    "VirusTotalError",
    "default_urlscan_client",
    "default_virustotal_client",
]
