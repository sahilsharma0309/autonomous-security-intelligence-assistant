"""Threat-scanner tool registrations.

Six tools, split so that each one's ``risk`` is honest about what it does:

======================  =========  ==========================================
Tool                    Risk       What it touches
======================  =========  ==========================================
``threat.url_analyze``  PASSIVE    Nothing -- string heuristics only
``threat.virustotal``   PASSIVE    VirusTotal's index
``threat.urlscan``      PASSIVE    URLScan's existing scans
``threat.urlscan_submit`` ACTIVE   Asks urlscan.io to fetch the target
``threat.url_inspect``  ACTIVE     Loads the page in a sandboxed browser
``threat.url_score``    PASSIVE    Nothing -- aggregates prior evidence
======================  =========  ==========================================

``threat.urlscan_submit`` being ACTIVE is the one worth explaining: the
request reaches the target from urlscan.io's infrastructure rather than
ours, which changes whose address appears in the target's logs but not
whether the target was contacted. Treating it as passive would let a
passive-only engagement cause a visit, which is exactly the thing that
classification exists to prevent.

All I/O is injectable through ``ToolContext.config``:

===================  ====================================
Context key          Provider protocol
===================  ====================================
``virustotal_client``  ``VirusTotalClient``
``urlscan_client``     ``UrlscanClient``
``sandbox_inspector``  ``SandboxInspector``
``analyzer_config``    ``AnalyzerConfig``
===================  ====================================
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from typing import Any

from security_assistant.core.tool import ToolParameter, tool
from security_assistant.core.types import RiskLevel, ToolCategory, ToolContext
from security_assistant.osint.collectors.base import provider_from
from security_assistant.osint.models import (
    normalize_domain,
    normalize_file_hash,
    normalize_url,
)
from security_assistant.threat import urlscan as urlscan_module
from security_assistant.threat import virustotal as vt_module
from security_assistant.threat.analyzer import AnalyzerConfig, UrlAnalyzer
from security_assistant.threat.models import (
    Finding,
    FindingCategory,
    ReputationVerdict,
    SandboxReport,
    Severity,
    UrlAssessment,
    assessment_to_graph_elements,
    verdicts_to_graph_elements,
)
from security_assistant.threat.safety import UnsafeUrlError, assert_fetchable
from security_assistant.threat.sandbox import (
    SandboxError,
    default_inspector,
)

logger = logging.getLogger(__name__)

__all__ = [
    "ALL_THREAT_TOOLS",
    "ThreatToolError",
    "domain_reputation",
    "url_analyze",
    "url_inspect",
    "url_score",
    "urlscan_search",
    "urlscan_submit",
]


class ThreatToolError(RuntimeError):
    """A threat tool could not complete."""


def _analyzer(ctx: ToolContext) -> UrlAnalyzer:
    config = ctx.config.get("analyzer_config")
    if isinstance(config, AnalyzerConfig):
        return UrlAnalyzer(config)
    brands = ctx.config.get("protected_brands")
    if isinstance(brands, (list, tuple)) and brands:
        return UrlAnalyzer(AnalyzerConfig().with_brands(brands))
    return UrlAnalyzer()


def _normalized_url(target: str) -> str:
    try:
        return normalize_url(target)
    except ValueError as exc:
        raise ThreatToolError(f"Invalid URL {target!r}: {exc}") from exc


def _graph_payload(
    entities: Sequence[Any], relationships: Sequence[Any]
) -> dict[str, Any]:
    return {
        "entities": [e.to_dict() for e in entities],
        "relationships": [r.to_dict() for r in relationships],
    }


# --------------------------------------------------------------------------- #
@tool(
    name="threat.url_analyze",
    description=(
        "Analyze a URL for phishing indicators, typosquatting, homoglyphs and "
        "suspicious hosting without contacting it."
    ),
    category=ToolCategory.ANALYSIS,
    risk=RiskLevel.PASSIVE,
    parameters=[
        ToolParameter("target", str, description="URL to analyze"),
        ToolParameter(
            "brands",
            list,
            required=False,
            description="Additional brand domains to check for imitation",
        ),
    ],
    timeout_seconds=15.0,
    rate_limit_per_minute=600.0,
    produces=["url_findings"],
    tags=["threat", "phishing"],
)
async def url_analyze(
    ctx: ToolContext, target: str, brands: Sequence[str] | None = None
) -> dict[str, Any]:
    """Heuristic analysis of a URL string. Contacts nothing."""
    url = _normalized_url(target)
    analyzer = _analyzer(ctx)
    if brands:
        analyzer = UrlAnalyzer(analyzer.config.with_brands(brands))

    findings = analyzer.analyze_url(url)
    certificate = ctx.config.get("certificate")
    if isinstance(certificate, Mapping):
        findings.extend(analyzer.analyze_certificate(url, certificate))

    assessment = UrlAssessment(url=url, findings=findings)
    entities, relationships = assessment_to_graph_elements(
        assessment, source="threat.url_analyze"
    )
    return {**assessment.to_dict(), **_graph_payload(entities, relationships)}


@tool(
    name="threat.virustotal",
    description=(
        "Look up an indicator (URL, domain, IP or file hash) in VirusTotal's "
        "existing index."
    ),
    category=ToolCategory.ANALYSIS,
    risk=RiskLevel.PASSIVE,
    parameters=[
        ToolParameter("target", str, description="Indicator to look up"),
        ToolParameter(
            "indicator_type",
            str,
            required=False,
            description="url, domain, ip_address or file_hash; inferred when omitted",
        ),
    ],
    timeout_seconds=60.0,
    rate_limit_per_minute=4.0,
    produces=["reputation"],
    tags=["threat", "reputation"],
)
async def domain_reputation(
    ctx: ToolContext, target: str, indicator_type: str | None = None
) -> dict[str, Any]:
    """Fetch and normalize a VirusTotal report."""
    kind = (indicator_type or _infer_indicator_type(target)).strip().lower()
    indicator = _canonical_indicator(kind, target)

    client = provider_from(
        ctx, "virustotal_client", vt_module.default_virustotal_client
    )
    payload = await client.report(kind, indicator)

    parser = {
        "url": vt_module.parse_url_report,
        "domain": vt_module.parse_domain_report,
        "ip_address": vt_module.parse_ip_report,
        "file_hash": vt_module.parse_file_report,
    }.get(kind)
    if parser is None:
        raise ThreatToolError(f"Unsupported indicator type: {kind!r}")

    verdict = parser(payload, indicator)
    entities, relationships = verdicts_to_graph_elements(
        [verdict], source="threat.virustotal"
    )
    return {
        **verdict.to_dict(),
        "found": bool(payload),
        "passive_dns": vt_module.passive_dns(payload) if kind == "domain" else [],
        **_graph_payload(entities, relationships),
    }


@tool(
    name="threat.urlscan",
    description="Search URLScan.io for existing scans of a URL or domain.",
    category=ToolCategory.ANALYSIS,
    risk=RiskLevel.PASSIVE,
    parameters=[
        ToolParameter("target", str, description="URL or domain to search for"),
        ToolParameter(
            "size", int, required=False, default=20, description="Maximum results"
        ),
    ],
    timeout_seconds=45.0,
    rate_limit_per_minute=30.0,
    produces=["reputation"],
    tags=["threat", "reputation"],
)
async def urlscan_search(
    ctx: ToolContext, target: str, size: int = 20
) -> dict[str, Any]:
    """Query existing URLScan results. The target is never contacted."""
    client = provider_from(ctx, "urlscan_client", urlscan_module.default_urlscan_client)
    query = f'page.domain:"{_query_domain(target)}"'
    payload = await client.search(query, size=size)

    verdict = urlscan_module.parse_search(payload, target)
    entities, relationships = verdicts_to_graph_elements(
        [verdict], source="threat.urlscan"
    )
    return {
        **verdict.to_dict(),
        "query": query,
        "result_count": len(payload.get("results", []) or []),
        **_graph_payload(entities, relationships),
    }


@tool(
    name="threat.urlscan_submit",
    description=(
        "Submit a URL to URLScan.io for scanning. This causes urlscan.io to "
        "fetch the target, so the target's logs record a visit."
    ),
    category=ToolCategory.SCANNING,
    risk=RiskLevel.ACTIVE,
    parameters=[
        ToolParameter("target", str, description="URL to submit"),
        ToolParameter(
            "visibility",
            str,
            required=False,
            default="unlisted",
            description="unlisted (default), private, or public",
        ),
    ],
    timeout_seconds=90.0,
    rate_limit_per_minute=10.0,
    produces=["reputation", "sandbox_report"],
    tags=["threat", "reputation"],
)
async def urlscan_submit(
    ctx: ToolContext, target: str, visibility: str = "unlisted"
) -> dict[str, Any]:
    """Submit a URL for scanning by urlscan.io.

    Defaults to ``unlisted``: a public scan is published where anyone can
    read it, which would disclose what an engagement is looking at.
    """
    url = _normalized_url(target)
    try:
        assert_fetchable(url)
    except UnsafeUrlError as exc:
        raise ThreatToolError(str(exc)) from exc

    try:
        options = urlscan_module.SubmitOptions(visibility=visibility)
    except ValueError as exc:
        raise ThreatToolError(str(exc)) from exc

    client = provider_from(ctx, "urlscan_client", urlscan_module.default_urlscan_client)
    submission = await client.submit(url, options)
    scan_id = str(submission.get("uuid", "") or "")

    return {
        "url": url,
        "scan_id": scan_id,
        "visibility": options.visibility,
        "result_url": str(submission.get("result", "") or ""),
        "submitted": bool(scan_id),
        "entities": [],
        "relationships": [],
    }


@tool(
    name="threat.url_inspect",
    description=(
        "Load a URL in a sandboxed headless browser and report the redirect "
        "chain, final URL, DOM excerpt, console output and contacted hosts."
    ),
    category=ToolCategory.SCANNING,
    risk=RiskLevel.ACTIVE,
    parameters=[
        ToolParameter("target", str, description="URL to load"),
    ],
    timeout_seconds=120.0,
    rate_limit_per_minute=20.0,
    produces=["sandbox_report", "url_findings"],
    tags=["threat", "sandbox"],
)
async def url_inspect(ctx: ToolContext, target: str) -> dict[str, Any]:
    """Inspect a URL by loading it behind the sandbox boundary."""
    url = _normalized_url(target)
    try:
        assert_fetchable(url)
    except UnsafeUrlError as exc:
        # Refusing here is the point: this is the tool that would otherwise
        # fetch an internal address on an attacker's behalf.
        raise ThreatToolError(str(exc)) from exc

    inspector = provider_from(ctx, "sandbox_inspector", default_inspector)
    try:
        report = await inspector.inspect(url)
    except SandboxError as exc:
        raise ThreatToolError(f"Sandbox inspection failed: {exc}") from exc

    analyzer = _analyzer(ctx)
    findings = analyzer.analyze_sandbox(report)
    assessment = UrlAssessment(url=url, findings=findings, sandbox=report)
    entities, relationships = assessment_to_graph_elements(
        assessment, source="threat.url_inspect"
    )
    return {**assessment.to_dict(), **_graph_payload(entities, relationships)}


@tool(
    name="threat.url_score",
    description=(
        "Combine heuristic findings, reputation verdicts and sandbox evidence "
        "into a single 0-100 risk score."
    ),
    category=ToolCategory.ANALYSIS,
    risk=RiskLevel.PASSIVE,
    parameters=[
        ToolParameter("target", str, description="URL being scored"),
        ToolParameter(
            "evidence",
            list,
            required=False,
            description="Prior tool payloads to aggregate",
        ),
    ],
    timeout_seconds=30.0,
    rate_limit_per_minute=600.0,
    consumes=["url_findings", "reputation", "sandbox_report"],
    produces=["risk_score"],
    tags=["threat", "scoring"],
)
async def url_score(
    ctx: ToolContext, target: str, evidence: Sequence[Any] | None = None
) -> dict[str, Any]:
    """Aggregate prior evidence for ``target`` into one score.

    Evidence comes from the payloads of the other threat tools. Anything not
    recognized is ignored rather than guessed at.
    """
    url = _normalized_url(target)

    if evidence is not None:
        candidates: list[Mapping[str, Any]] = [
            item for item in evidence if isinstance(item, Mapping)
        ]
    else:
        # No explicit evidence: pick up what earlier steps in this run
        # produced. The dispatcher publishes each successful tool's payload
        # into ctx.state, which is how a consuming tool reaches its
        # producers' output without the planner having to guess argument
        # names.
        candidates = [v for v in ctx.state.values() if isinstance(v, Mapping)]

    # Only aggregate evidence that is actually about this URL. A run may
    # assess several URLs, and silently folding one URL's detections into
    # another's score would be worse than having no score at all.
    payloads = [item for item in candidates if _concerns(item, url)]

    findings: list[Finding] = []
    verdicts: list[ReputationVerdict] = []
    sandbox: SandboxReport | None = None

    for payload in payloads:
        findings.extend(_findings_from(payload))
        verdict = _verdict_from(payload)
        if verdict is not None:
            verdicts.append(verdict)
        if sandbox is None:
            sandbox = _sandbox_from(payload)

    # Deduplicate findings by code: two tools reporting the same structural
    # observation is one piece of evidence, not two.
    unique: dict[str, Finding] = {}
    for finding in findings:
        unique.setdefault(finding.code, finding)

    assessment = UrlAssessment(
        url=url, findings=list(unique.values()), verdicts=verdicts, sandbox=sandbox
    )
    entities, relationships = assessment_to_graph_elements(
        assessment, source="threat.url_score"
    )
    return {
        **assessment.to_dict(),
        "evidence_count": len(payloads),
        "top_findings": [f.to_dict() for f in assessment.top_findings()],
        **_graph_payload(entities, relationships),
    }


# --------------------------------------------------------------------------- #
# Evidence decoding
# --------------------------------------------------------------------------- #
def _concerns(payload: Mapping[str, Any], url: str) -> bool:
    """Whether a payload is evidence about ``url``.

    Matches the URL exactly, or an indicator naming the URL's own host --
    a VirusTotal domain report for ``phish.example`` is evidence about
    ``https://phish.example/login``. A payload that names neither is treated
    as unrelated rather than assumed relevant.
    """
    from urllib.parse import urlsplit

    host = (urlsplit(url).hostname or "").lower()

    for field in ("url", "initial_url", "indicator"):
        value = payload.get(field)
        if not isinstance(value, str) or not value:
            continue
        if value == url:
            return True
        if host and value.lower() == host:
            return True
        if "://" in value:
            try:
                if (urlsplit(value).hostname or "").lower() == host:
                    return True
            except ValueError:  # pragma: no cover - defensive
                continue

    sandbox = payload.get("sandbox")
    if isinstance(sandbox, Mapping):
        return _concerns(sandbox, url)

    return False


def _findings_from(payload: Mapping[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for raw in payload.get("findings", []) or []:
        if not isinstance(raw, Mapping):
            continue
        try:
            findings.append(
                Finding(
                    code=str(raw["code"]),
                    title=str(raw.get("title", "")),
                    severity=Severity(str(raw.get("severity", "low"))),
                    category=FindingCategory(str(raw.get("category", "structure"))),
                    detail=str(raw.get("detail", "")),
                    source=str(raw.get("source", "")),
                )
            )
        except (KeyError, ValueError):
            logger.debug("Skipping unparseable finding payload")
    return findings


def _verdict_from(payload: Mapping[str, Any]) -> ReputationVerdict | None:
    source = str(payload.get("source", ""))
    if source not in {"virustotal", "urlscan"}:
        return None
    try:
        return ReputationVerdict(
            source=source,
            indicator=str(payload.get("indicator", "")),
            indicator_type=str(payload.get("indicator_type", "url")),
            malicious=int(payload.get("malicious", 0) or 0),
            suspicious=int(payload.get("suspicious", 0) or 0),
            harmless=int(payload.get("harmless", 0) or 0),
            undetected=int(payload.get("undetected", 0) or 0),
            categories=tuple(str(c) for c in (payload.get("categories") or [])),
        )
    except (TypeError, ValueError):
        return None


def _sandbox_from(payload: Mapping[str, Any]) -> SandboxReport | None:
    raw = payload.get("sandbox")
    if not isinstance(raw, Mapping):
        return None
    from security_assistant.threat.models import RedirectHop

    chain = [
        RedirectHop(
            url=str(hop.get("url", "")),
            status=int(hop.get("status", 0) or 0),
            method=str(hop.get("method", "GET")),
        )
        for hop in (raw.get("chain") or [])
        if isinstance(hop, Mapping) and hop.get("url")
    ]
    return SandboxReport(
        initial_url=str(raw.get("initial_url", "")),
        final_url=str(raw.get("final_url", "")),
        engine=str(raw.get("engine", "static")),
        chain=chain,
        status=int(raw.get("status", 0) or 0),
        contacted_domains=[str(d) for d in (raw.get("contacted_domains") or [])],
        resource_hashes=[str(h) for h in (raw.get("resource_hashes") or [])],
        console_messages=[str(m) for m in (raw.get("console_messages") or [])],
        dom_excerpt=str(raw.get("dom_excerpt", "")),
        dom_sha256=str(raw.get("dom_sha256", "")),
        screenshot_sha256=str(raw.get("screenshot_sha256", "")),
        screenshot_bytes=int(raw.get("screenshot_bytes", 0) or 0),
        title=str(raw.get("title", "")),
        has_password_input=bool(raw.get("has_password_input", False)),
        load_ms=int(raw.get("load_ms", 0) or 0),
        errors=[str(e) for e in (raw.get("errors") or [])],
    )


def _infer_indicator_type(value: str) -> str:
    text = value.strip()
    if "://" in text:
        return "url"
    try:
        normalize_file_hash(text)
    except ValueError:
        pass
    else:
        return "file_hash"
    import ipaddress

    try:
        ipaddress.ip_address(text.strip("[]"))
    except ValueError:
        return "domain"
    return "ip_address"


def _canonical_indicator(kind: str, value: str) -> str:
    try:
        if kind == "url":
            return normalize_url(value)
        if kind == "file_hash":
            return normalize_file_hash(value)
        if kind == "domain":
            return normalize_domain(value)
    except ValueError as exc:
        raise ThreatToolError(f"Invalid {kind} {value!r}: {exc}") from exc
    return value.strip().strip("[]")


def _query_domain(target: str) -> str:
    """The domain a URLScan search should be scoped to."""
    if "://" in target:
        from urllib.parse import urlsplit

        host = (urlsplit(target).hostname or "").strip()
        if host:
            return host.lower()
    try:
        return normalize_domain(target)
    except ValueError as exc:
        raise ThreatToolError(f"Invalid search target {target!r}: {exc}") from exc


#: Every threat tool, ready for ``ToolRegistry.register_all``.
ALL_THREAT_TOOLS = (
    url_analyze,
    domain_reputation,
    urlscan_search,
    urlscan_submit,
    url_inspect,
    url_score,
)
