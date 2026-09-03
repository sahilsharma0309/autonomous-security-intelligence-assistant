"""Tests for the URL heuristics.

Two things matter equally here: catching real deception, and *not* flagging
ordinary sites. A scanner that scores half the internet as suspicious is one
that gets turned off, so the false-positive tests are as load-bearing as the
detection ones.
"""

from __future__ import annotations

import pytest

from security_assistant.threat.analyzer import (
    AnalyzerConfig,
    UrlAnalyzer,
    confusable_skeleton,
    edit_distance,
    looks_like_homoglyph,
)
from security_assistant.threat.models import (
    FindingCategory,
    RedirectHop,
    SandboxReport,
    Severity,
)


@pytest.fixture
def analyzer() -> UrlAnalyzer:
    return UrlAnalyzer()


def codes(analyzer: UrlAnalyzer, url: str) -> set[str]:
    return {f.code for f in analyzer.analyze_url(url)}


class TestEditDistance:
    @pytest.mark.parametrize(
        ("left", "right", "expected"),
        [("paypal", "paypal", 0), ("paypal", "paypa1", 1), ("paypal", "paypall", 1)],
    )
    def test_distances(self, left: str, right: str, expected: int) -> None:
        assert edit_distance(left, right) == expected

    def test_caps_for_distant_strings(self) -> None:
        assert edit_distance("a", "zzzzzzzzzzzz", cap=3) == 3

    def test_cap_is_never_exceeded(self) -> None:
        assert edit_distance("abcdefgh", "zyxwvuts", cap=2) == 2


class TestConfusables:
    def test_cyrillic_folds_to_latin(self) -> None:
        assert confusable_skeleton("pаypal") == "paypal"

    def test_multi_character_substitutions(self) -> None:
        assert confusable_skeleton("rnicrosoft") == "microsoft"
        assert confusable_skeleton("vvhatsapp") == "whatsapp"

    def test_digit_substitutions(self) -> None:
        assert confusable_skeleton("g00gle") == "google"

    def test_ascii_is_unchanged_apart_from_case(self) -> None:
        assert confusable_skeleton("Example") == "example"

    def test_homoglyph_detection(self) -> None:
        assert looks_like_homoglyph("pаypal.com") is True
        assert looks_like_homoglyph("paypal.com") is False


class TestDeception:
    def test_detects_typosquat(self, analyzer: UrlAnalyzer) -> None:
        assert "typosquat" in codes(analyzer, "https://paypa1.com/login")

    def test_detects_homoglyph_host(self, analyzer: UrlAnalyzer) -> None:
        found = codes(analyzer, "https://pаypal.com/")
        assert "homoglyph_host" in found

    def test_detects_punycode(self, analyzer: UrlAnalyzer) -> None:
        assert "punycode_host" in codes(analyzer, "https://xn--pypal-4ve.com/")

    def test_detects_brand_in_subdomain(self, analyzer: UrlAnalyzer) -> None:
        found = codes(analyzer, "https://paypal.com.evil.example/signin")
        assert "brand_in_subdomain" in found

    def test_detects_phishing_keywords_in_host(self, analyzer: UrlAnalyzer) -> None:
        assert "phishing_keyword_host" in codes(
            analyzer, "https://secure.verify.example.com/"
        )

    def test_the_real_brand_is_not_flagged(self, analyzer: UrlAnalyzer) -> None:
        """paypal.com must never be reported as imitating paypal.com."""
        found = codes(analyzer, "https://paypal.com/signin")
        assert "typosquat" not in found
        assert "lookalike_domain" not in found
        assert "brand_in_subdomain" not in found

    def test_brand_subdomain_of_the_brand_itself_is_fine(
        self, analyzer: UrlAnalyzer
    ) -> None:
        found = codes(analyzer, "https://login.paypal.com/")
        assert "brand_in_subdomain" not in found

    def test_unrelated_domains_are_not_typosquats(self, analyzer: UrlAnalyzer) -> None:
        assert codes(analyzer, "https://kubernetes.io/docs/") == set()

    def test_custom_brands_are_honoured(self) -> None:
        analyzer = UrlAnalyzer(AnalyzerConfig().with_brands(["acmebank.com"]))
        assert "typosquat" in codes(analyzer, "https://acmebnk.com/")


class TestStructure:
    def test_embedded_credentials(self, analyzer: UrlAnalyzer) -> None:
        found = analyzer.analyze_url("https://paypal.com@evil.example/")
        by_code = {f.code: f for f in found}
        assert "embedded_credentials" in by_code
        assert by_code["embedded_credentials"].severity is Severity.HIGH

    def test_embedded_url_parameter(self, analyzer: UrlAnalyzer) -> None:
        assert "embedded_url_parameter" in codes(
            analyzer, "https://example.com/r?next=https://evil.example/"
        )

    def test_plaintext_scheme(self, analyzer: UrlAnalyzer) -> None:
        assert "plaintext_scheme" in codes(analyzer, "http://example.com/")
        assert "plaintext_scheme" not in codes(analyzer, "https://example.com/")

    def test_excessive_length(self, analyzer: UrlAnalyzer) -> None:
        assert "excessive_length" in codes(
            analyzer, "https://example.com/" + "a" * 200
        )

    def test_deep_subdomains(self, analyzer: UrlAnalyzer) -> None:
        assert "deep_subdomain" in codes(analyzer, "https://a.b.c.d.e.example.com/")

    def test_malformed_url_is_reported_not_raised(self, analyzer: UrlAnalyzer) -> None:
        found = analyzer.analyze_url("http://")
        assert [f.code for f in found] == ["malformed_url"]


class TestHosting:
    def test_ip_literal(self, analyzer: UrlAnalyzer) -> None:
        assert "ip_literal_host" in codes(analyzer, "http://93.184.216.34/login")

    def test_suspicious_tld(self, analyzer: UrlAnalyzer) -> None:
        assert "suspicious_tld" in codes(analyzer, "https://example.tk/")

    def test_dynamic_dns(self, analyzer: UrlAnalyzer) -> None:
        assert "dynamic_dns_host" in codes(analyzer, "https://abc.duckdns.org/")

    def test_uncommon_port(self, analyzer: UrlAnalyzer) -> None:
        assert "uncommon_port" in codes(analyzer, "https://example.com:8443/")

    def test_random_looking_subdomain(self, analyzer: UrlAnalyzer) -> None:
        assert "random_subdomain" in codes(
            analyzer, "https://a3f9c2e1b7d40582.example.com/"
        )

    def test_ordinary_site_is_clean(self, analyzer: UrlAnalyzer) -> None:
        assert codes(analyzer, "https://www.example.com/about") == set()


class TestCertificate:
    def test_expired(self, analyzer: UrlAnalyzer) -> None:
        found = analyzer.analyze_certificate(
            "https://example.com/", {"is_expired": True, "not_after": "2020-01-01"}
        )
        assert [f.code for f in found] == ["cert_expired"]

    def test_untrusted(self, analyzer: UrlAnalyzer) -> None:
        found = analyzer.analyze_certificate(
            "https://example.com/",
            {"verified": False, "verification_error": "self signed certificate"},
        )
        assert [f.code for f in found] == ["cert_untrusted"]

    def test_host_mismatch(self, analyzer: UrlAnalyzer) -> None:
        found = analyzer.analyze_certificate(
            "https://evil.example/", {"sans": ["example.com", "www.example.com"]}
        )
        assert [f.code for f in found] == ["cert_host_mismatch"]

    def test_matching_certificate_is_clean(self, analyzer: UrlAnalyzer) -> None:
        found = analyzer.analyze_certificate(
            "https://www.example.com/",
            {"sans": ["*.example.com", "example.com"], "verified": True},
        )
        assert found == []

    def test_accepts_the_osint_tls_payload_shape(self, analyzer: UrlAnalyzer) -> None:
        # Exactly what osint.tls returns, so Module 2 feeds this directly.
        payload = {
            "host": "example.com",
            "sans": ["example.com"],
            "is_expired": False,
            "verified": True,
            "verification_error": None,
        }
        assert analyzer.analyze_certificate("https://example.com/", payload) == []


class TestSandboxFindings:
    def test_cross_domain_redirect(self, analyzer: UrlAnalyzer) -> None:
        report = SandboxReport(
            initial_url="https://a.example/", final_url="https://b.example/"
        )
        assert "cross_domain_redirect" in {
            f.code for f in analyzer.analyze_sandbox(report)
        }

    def test_same_domain_redirect_is_not_flagged(self, analyzer: UrlAnalyzer) -> None:
        report = SandboxReport(
            initial_url="https://www.example.com/", final_url="https://example.com/home"
        )
        assert "cross_domain_redirect" not in {
            f.code for f in analyzer.analyze_sandbox(report)
        }

    def test_long_chain(self, analyzer: UrlAnalyzer) -> None:
        report = SandboxReport(
            initial_url="https://a.example/",
            final_url="https://a.example/",
            chain=[RedirectHop(f"https://a.example/{i}", 302) for i in range(5)],
        )
        assert "long_redirect_chain" in {f.code for f in analyzer.analyze_sandbox(report)}

    def test_credential_form(self, analyzer: UrlAnalyzer) -> None:
        report = SandboxReport(
            initial_url="https://a.example/",
            final_url="https://a.example/",
            has_password_input=True,
        )
        assert "credential_form" in {f.code for f in analyzer.analyze_sandbox(report)}

    def test_static_engine_is_declared_as_reduced_coverage(
        self, analyzer: UrlAnalyzer
    ) -> None:
        """An absent behavioural finding must not read as a clean result."""
        report = SandboxReport(
            initial_url="https://a.example/", final_url="https://a.example/", engine="static"
        )
        found = {f.code: f for f in analyzer.analyze_sandbox(report)}
        assert "static_inspection_only" in found
        note = found["static_inspection_only"]
        assert note.severity is Severity.INFO
        assert note.category is FindingCategory.BEHAVIOR
        # INFO carries no weight, so it cannot inflate the score.
        assert note.weight == 0.0

    def test_container_engine_adds_no_such_note(self, analyzer: UrlAnalyzer) -> None:
        report = SandboxReport(
            initial_url="https://a.example/",
            final_url="https://a.example/",
            engine="container",
        )
        assert "static_inspection_only" not in {
            f.code for f in analyzer.analyze_sandbox(report)
        }


class TestFullAnalysis:
    def test_combines_all_evidence(self, analyzer: UrlAnalyzer) -> None:
        report = SandboxReport(
            initial_url="https://paypa1.com/login",
            final_url="https://collector.example/",
            has_password_input=True,
            engine="container",
        )
        assessment = analyzer.analyze(
            "https://paypa1.com/login",
            certificate={"is_expired": True},
            sandbox=report,
        )
        found = {f.code for f in assessment.all_findings}
        assert {"typosquat", "cert_expired", "cross_domain_redirect"} <= found
        assert assessment.risk_score > 70

    def test_benign_url_scores_zero(self, analyzer: UrlAnalyzer) -> None:
        assert analyzer.analyze("https://www.example.com/about").risk_score == 0.0
