"""Tests for threat models, scoring, and graph projection.

The scoring rule is the part most worth pinning: it decides what an operator
sees, and a rule that lets cosmetic findings out-vote decisive ones is how a
scanner ends up ignored.
"""

from __future__ import annotations

import pytest

from security_assistant.osint.graph import EntityGraph
from security_assistant.osint.models import EdgeType, EntityType
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
    summarize,
    verdicts_to_graph_elements,
)


def finding(
    code: str,
    severity: Severity = Severity.MEDIUM,
    category: FindingCategory = FindingCategory.STRUCTURE,
) -> Finding:
    return Finding(code=code, title=code, severity=severity, category=category)


class TestScoring:
    def test_no_findings_is_zero(self) -> None:
        assert score_findings([]) == 0.0

    def test_single_finding_matches_its_severity_weight(self) -> None:
        assert score_findings([finding("a", Severity.HIGH)]) == pytest.approx(65.0)

    def test_severity_ordering_is_monotonic(self) -> None:
        scores = [
            score_findings([finding("x", s)])
            for s in (Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)
        ]
        assert scores == sorted(scores)

    def test_info_findings_do_not_move_the_score(self) -> None:
        assert score_findings([finding("note", Severity.INFO)]) == 0.0

    def test_correlated_findings_do_not_stack(self) -> None:
        """Two structural oddities share a cause, so they count roughly once."""
        one = score_findings([finding("a", Severity.MEDIUM, FindingCategory.STRUCTURE)])
        two = score_findings(
            [
                finding("a", Severity.MEDIUM, FindingCategory.STRUCTURE),
                finding("b", Severity.MEDIUM, FindingCategory.STRUCTURE),
            ]
        )
        assert two > one
        # ...but nowhere near double.
        assert two < one * 1.25

    def test_independent_categories_do_compound(self) -> None:
        same = score_findings(
            [
                finding("a", Severity.MEDIUM, FindingCategory.STRUCTURE),
                finding("b", Severity.MEDIUM, FindingCategory.STRUCTURE),
            ]
        )
        different = score_findings(
            [
                finding("a", Severity.MEDIUM, FindingCategory.STRUCTURE),
                finding("b", Severity.MEDIUM, FindingCategory.DECEPTION),
            ]
        )
        assert different > same

    def test_many_weak_findings_cannot_outrank_one_critical(self) -> None:
        weak = [
            finding(f"w{i}", Severity.LOW, FindingCategory.STRUCTURE) for i in range(10)
        ]
        assert score_findings(weak) < score_findings([finding("c", Severity.CRITICAL)])

    def test_score_is_bounded(self) -> None:
        everything = [
            finding(f"c{i}", Severity.CRITICAL, category)
            for i, category in enumerate(FindingCategory)
        ]
        assert 0.0 <= score_findings(everything) <= 100.0


class TestRiskBand:
    @pytest.mark.parametrize(
        ("score", "expected"),
        [
            (0.0, RiskBand.BENIGN),
            (19.9, RiskBand.BENIGN),
            (20.0, RiskBand.LOW),
            (45.0, RiskBand.SUSPICIOUS),
            (65.0, RiskBand.HIGH),
            (95.0, RiskBand.CRITICAL),
        ],
    )
    def test_bands(self, score: float, expected: RiskBand) -> None:
        assert RiskBand.for_score(score) is expected

    def test_str_is_lowercase_name(self) -> None:
        assert str(RiskBand.SUSPICIOUS) == "suspicious"


class TestReputationVerdict:
    def test_detection_ratio_excludes_silent_engines(self) -> None:
        # 60 engines that returned nothing must not read as "0% malicious".
        verdict = ReputationVerdict(
            source="virustotal",
            indicator="https://x.test/",
            indicator_type="url",
            malicious=2,
            harmless=2,
            undetected=60,
        )
        assert verdict.detection_ratio == pytest.approx(0.5)
        assert verdict.total_engines == 64

    def test_clean_verdict_produces_no_finding(self) -> None:
        clean = ReputationVerdict(
            source="virustotal", indicator="x", indicator_type="url", harmless=70
        )
        assert clean.to_finding() is None

    def test_lone_detection_is_softened(self) -> None:
        """One engine out of seventy is usually a false positive."""
        lone = ReputationVerdict(
            source="virustotal",
            indicator="x",
            indicator_type="url",
            malicious=1,
            harmless=69,
        )
        found = lone.to_finding()
        assert found is not None
        assert found.severity is Severity.MEDIUM

    def test_many_detections_are_critical(self) -> None:
        many = ReputationVerdict(
            source="virustotal", indicator="x", indicator_type="url", malicious=12
        )
        found = many.to_finding()
        assert found is not None
        assert found.severity is Severity.CRITICAL

    def test_zero_engines_does_not_divide_by_zero(self) -> None:
        empty = ReputationVerdict(source="urlscan", indicator="x", indicator_type="url")
        assert empty.detection_ratio == 0.0


class TestUrlAssessment:
    def test_verdicts_contribute_to_the_score(self) -> None:
        bare = UrlAssessment(url="https://x.test/")
        assert bare.risk_score == 0.0

        with_verdict = UrlAssessment(
            url="https://x.test/",
            verdicts=[
                ReputationVerdict(
                    source="virustotal",
                    indicator="https://x.test/",
                    indicator_type="url",
                    malicious=9,
                )
            ],
        )
        assert with_verdict.risk_score > 80.0

    def test_top_findings_are_ordered_by_weight(self) -> None:
        assessment = UrlAssessment(
            url="https://x.test/",
            findings=[
                finding("low", Severity.LOW),
                finding("crit", Severity.CRITICAL),
                finding("med", Severity.MEDIUM),
            ],
        )
        assert [f.code for f in assessment.top_findings(2)] == ["crit", "med"]

    def test_serializes(self) -> None:
        payload = UrlAssessment(
            url="https://x.test/", findings=[finding("a")]
        ).to_dict()
        assert payload["url"] == "https://x.test/"
        assert payload["risk_band"] in {"benign", "low", "suspicious", "high", "critical"}
        assert payload["findings"][0]["code"] == "a"


class TestRegistrableDomain:
    @pytest.mark.parametrize(
        ("host", "expected"),
        [
            ("example.com", "example.com"),
            ("a.b.example.com", "example.com"),
            ("example.co.uk", "example.co.uk"),
            ("a.b.example.co.uk", "example.co.uk"),
            ("localhost", "localhost"),
        ],
    )
    def test_extracts_registrable(self, host: str, expected: str) -> None:
        assert registrable_domain(host) == expected

    def test_invalid_returns_empty(self) -> None:
        assert registrable_domain("") == ""


class TestGraphProjection:
    def test_url_and_host_become_linked_nodes(self) -> None:
        assessment = UrlAssessment(url="https://phish.example/login")
        entities, relationships = assessment_to_graph_elements(assessment)

        keys = {e.key for e in entities}
        assert "url:https://phish.example/login" in keys
        assert "domain:phish.example" in keys
        assert any(r.type is EdgeType.SERVED_BY for r in relationships)

    def test_score_travels_onto_the_node(self) -> None:
        assessment = UrlAssessment(
            url="https://phish.example/", findings=[finding("x", Severity.HIGH)]
        )
        entities, _ = assessment_to_graph_elements(assessment)
        root = next(e for e in entities if e.type is EntityType.URL)
        assert root.attributes["risk_score"] == pytest.approx(65.0)
        assert root.attributes["risk_band"] == "high"

    def test_redirect_chain_becomes_a_path(self) -> None:
        report = SandboxReport(
            initial_url="https://a.example/",
            final_url="https://c.example/",
            chain=[
                RedirectHop("https://b.example/", 302),
                RedirectHop("https://c.example/", 200),
            ],
        )
        assessment = UrlAssessment(url="https://a.example/", sandbox=report)
        entities, relationships = assessment_to_graph_elements(assessment)

        graph = EntityGraph()
        graph.add_entities(entities)
        for relationship in relationships:
            graph.add_relationship(relationship)

        path = graph.shortest_path("url:https://a.example/", "url:https://c.example/")
        assert [e.key for e in path] == [
            "url:https://a.example/",
            "url:https://b.example/",
            "url:https://c.example/",
        ]

    def test_contacted_domains_and_hashes_are_linked(self) -> None:
        report = SandboxReport(
            initial_url="https://a.example/",
            final_url="https://a.example/",
            contacted_domains=["tracker.example"],
            resource_hashes=["da39a3ee5e6b4b0d3255bfef95601890afd80709"],
        )
        assessment = UrlAssessment(url="https://a.example/", sandbox=report)
        _, relationships = assessment_to_graph_elements(assessment)
        kinds = {r.type for r in relationships}
        assert EdgeType.CONTACTS in kinds
        assert EdgeType.REFERENCES_FILE in kinds

    def test_ip_hosted_url_links_to_an_address_node(self) -> None:
        assessment = UrlAssessment(url="http://93.184.216.34/x")
        entities, _ = assessment_to_graph_elements(assessment)
        assert "ip_address:93.184.216.34" in {e.key for e in entities}

    def test_malformed_url_projects_nothing(self) -> None:
        entities, relationships = assessment_to_graph_elements(
            UrlAssessment(url="not a url")
        )
        assert entities == []
        assert relationships == []

    def test_bad_hop_urls_are_skipped_not_fatal(self) -> None:
        report = SandboxReport(
            initial_url="https://a.example/",
            chain=[RedirectHop("::::not a url", 302), RedirectHop("https://b.example/", 200)],
        )
        entities, _ = assessment_to_graph_elements(
            UrlAssessment(url="https://a.example/", sandbox=report)
        )
        assert "url:https://b.example/" in {e.key for e in entities}


class TestVerdictProjection:
    def test_reputation_lands_as_attributes_on_the_indicator(self) -> None:
        verdict = ReputationVerdict(
            source="virustotal",
            indicator="phish.example",
            indicator_type="domain",
            malicious=4,
            harmless=60,
        )
        entities, _ = verdicts_to_graph_elements([verdict])
        assert len(entities) == 1
        assert entities[0].key == "domain:phish.example"
        assert entities[0].attributes["virustotal_malicious"] == 4

    def test_file_hash_verdicts_project(self) -> None:
        verdict = ReputationVerdict(
            source="virustotal",
            indicator="da39a3ee5e6b4b0d3255bfef95601890afd80709",
            indicator_type="file_hash",
            malicious=30,
        )
        entities, _ = verdicts_to_graph_elements([verdict])
        assert entities[0].type is EntityType.FILE_HASH

    def test_unparseable_indicator_is_skipped(self) -> None:
        verdict = ReputationVerdict(
            source="virustotal", indicator="", indicator_type="domain"
        )
        entities, _ = verdicts_to_graph_elements([verdict])
        assert entities == []


class TestSummarize:
    def test_empty(self) -> None:
        assert summarize([])["count"] == 0

    def test_counts_bands(self) -> None:
        result = summarize(
            [
                UrlAssessment(url="https://a.test/"),
                UrlAssessment(
                    url="https://b.test/", findings=[finding("x", Severity.CRITICAL)]
                ),
            ]
        )
        assert result["count"] == 2
        assert result["max_score"] > 90
        assert result["bands"]["benign"] == 1
