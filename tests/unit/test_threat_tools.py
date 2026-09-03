"""Tests for threat tool registration and dispatch.

The risk classifications are the safety contract, so they are asserted
explicitly rather than assumed from the decorator.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest

from security_assistant.core import (
    AuthorizationScope,
    DispatcherConfig,
    InvocationStatus,
    RiskLevel,
    ToolContext,
    ToolDispatcher,
    ToolRegistry,
)
from security_assistant.threat.models import SandboxReport
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
from security_assistant.threat.urlscan import SubmitOptions
from tests.unit.conftest import run


class FakeVirusTotal:
    def __init__(self, payload: Mapping[str, Any] | None = None) -> None:
        self.payload = payload or {}
        self.calls: list[tuple[str, str]] = []

    async def report(self, indicator_type: str, indicator: str) -> Mapping[str, Any]:
        self.calls.append((indicator_type, indicator))
        return self.payload


class FakeUrlscan:
    def __init__(self, search_payload: Mapping[str, Any] | None = None) -> None:
        self.search_payload = search_payload or {}
        self.searches: list[str] = []
        self.submissions: list[tuple[str, SubmitOptions]] = []

    async def search(self, query: str, *, size: int = 20) -> Mapping[str, Any]:
        self.searches.append(query)
        return self.search_payload

    async def submit(self, url: str, options: SubmitOptions) -> Mapping[str, Any]:
        self.submissions.append((url, options))
        return {"uuid": "scan-1", "result": "https://urlscan.io/result/scan-1/"}

    async def result(self, scan_id: str) -> Mapping[str, Any]:
        return {}


class FakeInspector:
    def __init__(self, report: SandboxReport | None = None) -> None:
        self.report = report
        self.inspected: list[str] = []

    async def inspect(self, url: str) -> SandboxReport:
        self.inspected.append(url)
        return self.report or SandboxReport(
            initial_url=url, final_url=url, engine="container", status=200
        )


def ctx(**config: Any) -> ToolContext:
    return ToolContext(scope=None, config=config)


class TestToolSpecContract:
    def test_risk_classifications(self) -> None:
        risks = {t.spec.name: t.spec.risk for t in ALL_THREAT_TOOLS}
        # These contact nothing.
        assert risks["threat.url_analyze"] is RiskLevel.PASSIVE
        assert risks["threat.url_score"] is RiskLevel.PASSIVE
        assert risks["threat.virustotal"] is RiskLevel.PASSIVE
        assert risks["threat.urlscan"] is RiskLevel.PASSIVE
        # These cause the target to be contacted.
        assert risks["threat.url_inspect"] is RiskLevel.ACTIVE
        assert risks["threat.urlscan_submit"] is RiskLevel.ACTIVE

    def test_submitting_to_a_third_party_is_not_passive(self) -> None:
        """urlscan.io fetching the target on our behalf still contacts it."""
        assert urlscan_submit.spec.risk is RiskLevel.ACTIVE

    def test_all_scope_gated_on_target(self) -> None:
        assert all(t.spec.requires_scope for t in ALL_THREAT_TOOLS)
        assert all(t.spec.target_argument == "target" for t in ALL_THREAT_TOOLS)

    def test_rate_limits_and_timeouts_declared(self) -> None:
        for spec in (t.spec for t in ALL_THREAT_TOOLS):
            assert spec.rate_limit_per_minute, spec.name
            assert spec.timeout_seconds, spec.name

    def test_virustotal_rate_limit_matches_the_public_tier(self) -> None:
        assert domain_reputation.spec.rate_limit_per_minute == 4.0

    def test_artifact_wiring(self) -> None:
        assert url_analyze.spec.produces == frozenset({"url_findings"})
        assert url_score.spec.consumes == frozenset(
            {"url_findings", "reputation", "sandbox_report"}
        )
        assert url_score.spec.produces == frozenset({"risk_score"})

    def test_all_register_cleanly(self) -> None:
        registry = ToolRegistry("threat")
        registry.register_all(ALL_THREAT_TOOLS)
        assert len(registry) == 6


class TestUrlAnalyze:
    def test_reports_findings_and_graph_elements(self) -> None:
        result = run(url_analyze.invoke(ctx(), {"target": "https://paypa1.com/login"}))
        assert result["risk_score"] > 50
        assert any(f["code"] == "typosquat" for f in result["findings"])
        assert "url:https://paypa1.com/login" in {e["key"] for e in result["entities"]}

    def test_benign_url_scores_zero(self) -> None:
        result = run(url_analyze.invoke(ctx(), {"target": "https://example.com/"}))
        assert result["risk_score"] == 0.0
        assert result["risk_band"] == "benign"

    def test_extra_brands_are_honoured(self) -> None:
        result = run(
            url_analyze.invoke(
                ctx(), {"target": "https://acmebnk.com/", "brands": ["acmebank.com"]}
            )
        )
        assert any(f["code"] == "typosquat" for f in result["findings"])

    def test_certificate_from_context_is_folded_in(self) -> None:
        result = run(
            url_analyze.invoke(
                ctx(certificate={"is_expired": True}), {"target": "https://example.com/"}
            )
        )
        assert any(f["code"] == "cert_expired" for f in result["findings"])

    def test_invalid_url_is_rejected(self) -> None:
        with pytest.raises(ThreatToolError, match="Invalid URL"):
            run(url_analyze.invoke(ctx(), {"target": "not-a-url"}))

    def test_contacts_nothing(self) -> None:
        # No provider is configured; if it tried to fetch, it would fail.
        assert run(url_analyze.invoke(ctx(), {"target": "https://example.com/"}))


class TestVirusTotalTool:
    def test_looks_up_and_normalizes(self) -> None:
        client = FakeVirusTotal(
            {"data": {"attributes": {"last_analysis_stats": {"malicious": 5}}}}
        )
        result = run(
            domain_reputation.invoke(
                ctx(virustotal_client=client), {"target": "phish.example"}
            )
        )
        assert result["malicious"] == 5
        assert result["found"] is True
        assert client.calls == [("domain", "phish.example")]

    @pytest.mark.parametrize(
        ("target", "expected"),
        [
            ("https://x.test/a", "url"),
            ("example.com", "domain"),
            ("93.184.216.34", "ip_address"),
            ("da39a3ee5e6b4b0d3255bfef95601890afd80709", "file_hash"),
        ],
    )
    def test_infers_indicator_type(self, target: str, expected: str) -> None:
        client = FakeVirusTotal()
        run(domain_reputation.invoke(ctx(virustotal_client=client), {"target": target}))
        assert client.calls[0][0] == expected

    def test_explicit_type_overrides_inference(self) -> None:
        client = FakeVirusTotal()
        run(
            domain_reputation.invoke(
                ctx(virustotal_client=client),
                {"target": "example.com", "indicator_type": "domain"},
            )
        )
        assert client.calls[0][0] == "domain"

    def test_unknown_indicator_returns_a_clean_verdict(self) -> None:
        result = run(
            domain_reputation.invoke(
                ctx(virustotal_client=FakeVirusTotal({})), {"target": "example.com"}
            )
        )
        assert result["found"] is False
        assert result["malicious"] == 0

    def test_passive_dns_surfaced_for_domains(self) -> None:
        client = FakeVirusTotal(
            {
                "data": {
                    "attributes": {
                        "last_dns_records": [{"type": "A", "value": "93.184.216.34"}]
                    }
                }
            }
        )
        result = run(
            domain_reputation.invoke(
                ctx(virustotal_client=client), {"target": "example.com"}
            )
        )
        assert result["passive_dns"] == ["93.184.216.34"]


class TestUrlscanTools:
    def test_search_scopes_the_query_to_the_domain(self) -> None:
        client = FakeUrlscan()
        run(
            urlscan_search.invoke(
                ctx(urlscan_client=client), {"target": "https://phish.example/login"}
            )
        )
        assert client.searches == ['page.domain:"phish.example"']

    def test_search_never_submits(self) -> None:
        client = FakeUrlscan()
        run(urlscan_search.invoke(ctx(urlscan_client=client), {"target": "phish.example"}))
        assert client.submissions == []

    def test_submit_defaults_to_unlisted(self) -> None:
        client = FakeUrlscan()
        result = run(
            urlscan_submit.invoke(
                ctx(urlscan_client=client), {"target": "https://phish.example/"}
            )
        )
        assert result["scan_id"] == "scan-1"
        assert client.submissions[0][1].visibility == "unlisted"

    def test_submit_honours_explicit_visibility(self) -> None:
        client = FakeUrlscan()
        run(
            urlscan_submit.invoke(
                ctx(urlscan_client=client),
                {"target": "https://phish.example/", "visibility": "public"},
            )
        )
        assert client.submissions[0][1].visibility == "public"

    def test_submit_rejects_unknown_visibility(self) -> None:
        with pytest.raises(ThreatToolError, match="visibility"):
            run(
                urlscan_submit.invoke(
                    ctx(urlscan_client=FakeUrlscan()),
                    {"target": "https://x.test/", "visibility": "everyone"},
                )
            )

    def test_submit_refuses_an_internal_url(self) -> None:
        client = FakeUrlscan()
        with pytest.raises(ThreatToolError):
            run(
                urlscan_submit.invoke(
                    ctx(urlscan_client=client), {"target": "http://127.0.0.1/"}
                )
            )
        assert client.submissions == []


class TestUrlInspect:
    def test_inspects_and_projects(self) -> None:
        inspector = FakeInspector(
            SandboxReport(
                initial_url="https://a.example/",
                final_url="https://b.example/",
                engine="container",
                contacted_domains=["tracker.example"],
            )
        )
        result = run(
            url_inspect.invoke(
                ctx(sandbox_inspector=inspector), {"target": "https://a.example/"}
            )
        )
        assert inspector.inspected == ["https://a.example/"]
        assert result["sandbox"]["engine"] == "container"
        assert any(f["code"] == "cross_domain_redirect" for f in result["findings"])
        assert "domain:tracker.example" in {e["key"] for e in result["entities"]}

    def test_refuses_internal_targets_before_the_inspector_runs(self) -> None:
        inspector = FakeInspector()
        with pytest.raises(ThreatToolError):
            run(
                url_inspect.invoke(
                    ctx(sandbox_inspector=inspector),
                    {"target": "http://169.254.169.254/latest/meta-data/"},
                )
            )
        assert inspector.inspected == []

    def test_static_engine_is_flagged_in_the_findings(self) -> None:
        inspector = FakeInspector(
            SandboxReport(
                initial_url="https://a.example/",
                final_url="https://a.example/",
                engine="static",
            )
        )
        result = run(
            url_inspect.invoke(
                ctx(sandbox_inspector=inspector), {"target": "https://a.example/"}
            )
        )
        assert any(f["code"] == "static_inspection_only" for f in result["findings"])

    def test_sandbox_failure_becomes_a_tool_error(self) -> None:
        class Broken:
            async def inspect(self, url: str) -> SandboxReport:
                from security_assistant.threat.sandbox import SandboxError

                raise SandboxError("container died")

        with pytest.raises(ThreatToolError, match="Sandbox inspection failed"):
            run(
                url_inspect.invoke(
                    ctx(sandbox_inspector=Broken()), {"target": "https://a.example/"}
                )
            )


class TestUrlScore:
    def test_aggregates_evidence_from_other_tools(self) -> None:
        heuristics = run(url_analyze.invoke(ctx(), {"target": "https://paypa1.com/login"}))
        reputation = run(
            domain_reputation.invoke(
                ctx(
                    virustotal_client=FakeVirusTotal(
                        {"data": {"attributes": {"last_analysis_stats": {"malicious": 8}}}}
                    )
                ),
                {"target": "paypa1.com"},
            )
        )
        result = run(
            url_score.invoke(
                ctx(),
                {
                    "target": "https://paypa1.com/login",
                    "evidence": [heuristics, reputation],
                },
            )
        )
        assert result["evidence_count"] == 2
        assert result["risk_score"] > heuristics["risk_score"]
        assert result["risk_band"] in {"high", "critical"}

    def test_no_evidence_scores_zero(self) -> None:
        result = run(url_score.invoke(ctx(), {"target": "https://example.com/"}))
        assert result["risk_score"] == 0.0
        assert result["evidence_count"] == 0

    def test_duplicate_findings_count_once(self) -> None:
        heuristics = run(url_analyze.invoke(ctx(), {"target": "https://paypa1.com/login"}))
        once = run(
            url_score.invoke(
                ctx(), {"target": "https://paypa1.com/login", "evidence": [heuristics]}
            )
        )
        twice = run(
            url_score.invoke(
                ctx(),
                {
                    "target": "https://paypa1.com/login",
                    "evidence": [heuristics, dict(heuristics)],
                },
            )
        )
        assert once["risk_score"] == twice["risk_score"]

    def test_unrecognized_evidence_is_ignored(self) -> None:
        result = run(
            url_score.invoke(
                ctx(),
                {"target": "https://example.com/", "evidence": ["nonsense", 42, {}]},
            )
        )
        assert result["risk_score"] == 0.0

    def test_picks_up_evidence_from_run_state_when_none_is_passed(self) -> None:
        """The dispatcher publishes each tool's payload into ctx.state; a
        consuming tool reads its producers from there rather than relying on
        the planner to guess an argument name."""
        heuristics = run(url_analyze.invoke(ctx(), {"target": "https://paypa1.com/login"}))
        context = ctx()
        context.state["threat.url_analyze"] = heuristics

        result = run(url_score.invoke(context, {"target": "https://paypa1.com/login"}))

        assert result["evidence_count"] == 1
        assert result["risk_score"] > 0

    def test_evidence_about_a_different_url_is_not_folded_in(self) -> None:
        """A run may assess several URLs; borrowing one URL's detections for
        another would be worse than having no score."""
        other = run(url_analyze.invoke(ctx(), {"target": "https://paypa1.com/login"}))
        context = ctx()
        context.state["threat.url_analyze"] = other

        result = run(url_score.invoke(context, {"target": "https://example.com/"}))

        assert result["evidence_count"] == 0
        assert result["risk_score"] == 0.0

    def test_domain_reputation_counts_for_a_url_on_that_domain(self) -> None:
        reputation = run(
            domain_reputation.invoke(
                ctx(
                    virustotal_client=FakeVirusTotal(
                        {"data": {"attributes": {"last_analysis_stats": {"malicious": 9}}}}
                    )
                ),
                {"target": "phish.example"},
            )
        )
        context = ctx()
        context.state["threat.virustotal"] = reputation

        result = run(url_score.invoke(context, {"target": "https://phish.example/login"}))

        assert result["evidence_count"] == 1
        assert result["risk_score"] > 80

    def test_explicit_evidence_overrides_run_state(self) -> None:
        heuristics = run(url_analyze.invoke(ctx(), {"target": "https://paypa1.com/login"}))
        context = ctx()
        context.state["threat.url_analyze"] = heuristics

        result = run(
            url_score.invoke(
                context, {"target": "https://paypa1.com/login", "evidence": []}
            )
        )
        assert result["evidence_count"] == 0

    def test_sandbox_evidence_is_decoded(self) -> None:
        inspector = FakeInspector(
            SandboxReport(
                initial_url="https://a.example/",
                final_url="https://b.example/",
                engine="container",
            )
        )
        inspected = run(
            url_inspect.invoke(
                ctx(sandbox_inspector=inspector), {"target": "https://a.example/"}
            )
        )
        result = run(
            url_score.invoke(
                ctx(), {"target": "https://a.example/", "evidence": [inspected]}
            )
        )
        assert result["sandbox"] is not None
        assert result["sandbox"]["final_url"] == "https://b.example/"


class TestAuthorizationBoundary:
    @staticmethod
    def _dispatcher(max_risk: RiskLevel) -> ToolDispatcher:
        registry = ToolRegistry("threat")
        registry.register_all(ALL_THREAT_TOOLS)
        scope = AuthorizationScope(
            allow=["phish.example"],
            max_risk=max_risk,
            authorization_reference="IR-TEST",
        )
        return ToolDispatcher(registry, scope, DispatcherConfig())

    def test_passive_scope_blocks_the_sandbox(self) -> None:
        dispatcher = self._dispatcher(RiskLevel.PASSIVE)
        inspector = FakeInspector()
        context = ToolContext(scope=dispatcher.scope, config={"sandbox_inspector": inspector})
        result = run(
            dispatcher.call(
                "threat.url_inspect", context, target="https://phish.example/"
            )
        )
        assert result.status is InvocationStatus.DENIED
        assert inspector.inspected == []

    def test_passive_scope_blocks_urlscan_submission(self) -> None:
        dispatcher = self._dispatcher(RiskLevel.PASSIVE)
        client = FakeUrlscan()
        context = ToolContext(scope=dispatcher.scope, config={"urlscan_client": client})
        result = run(
            dispatcher.call(
                "threat.urlscan_submit", context, target="https://phish.example/"
            )
        )
        assert result.status is InvocationStatus.DENIED
        assert client.submissions == []

    def test_passive_scope_still_allows_analysis_and_lookups(self) -> None:
        dispatcher = self._dispatcher(RiskLevel.PASSIVE)
        context = ToolContext(
            scope=dispatcher.scope, config={"virustotal_client": FakeVirusTotal()}
        )
        for name in ("threat.url_analyze", "threat.virustotal"):
            result = run(dispatcher.call(name, context, target="https://phish.example/"))
            assert result.status is InvocationStatus.SUCCESS, name

    def test_out_of_scope_target_is_denied(self) -> None:
        dispatcher = self._dispatcher(RiskLevel.ACTIVE)
        inspector = FakeInspector()
        context = ToolContext(scope=dispatcher.scope, config={"sandbox_inspector": inspector})
        result = run(
            dispatcher.call(
                "threat.url_inspect", context, target="https://not-authorized.test/"
            )
        )
        assert result.status is InvocationStatus.DENIED
        assert inspector.inspected == []

    def test_in_scope_active_target_runs(self) -> None:
        dispatcher = self._dispatcher(RiskLevel.ACTIVE)
        context = ToolContext(
            scope=dispatcher.scope, config={"sandbox_inspector": FakeInspector()}
        )
        result = run(
            dispatcher.call(
                "threat.url_inspect", context, target="https://phish.example/login"
            )
        )
        assert result.status is InvocationStatus.SUCCESS
