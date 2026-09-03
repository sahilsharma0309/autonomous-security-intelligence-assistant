"""Tests for the VirusTotal and URLScan clients and their parsers.

No network: parsing is tested against recorded response shapes, and the
credential/rate-limit behaviour is tested directly.
"""

from __future__ import annotations

from typing import Any, ClassVar

import pytest

from security_assistant.threat import urlscan as urlscan_module
from security_assistant.threat import virustotal as vt
from security_assistant.threat.models import Severity
from tests.unit.conftest import run


class TestApiKeyHandling:
    def test_virustotal_key_read_from_env(self) -> None:
        assert vt.api_key_from_env({"VIRUSTOTAL_API_KEY": " abc123 "}) == "abc123"

    def test_virustotal_missing_key_is_actionable(self) -> None:
        with pytest.raises(vt.VirusTotalCredentialsError, match="VIRUSTOTAL_API_KEY"):
            vt.api_key_from_env({})

    def test_urlscan_key_read_from_env(self) -> None:
        assert urlscan_module.api_key_from_env({"URLSCAN_API_KEY": "xyz"}) == "xyz"

    def test_urlscan_missing_key_is_actionable(self) -> None:
        with pytest.raises(urlscan_module.UrlscanCredentialsError, match="URLSCAN_API_KEY"):
            urlscan_module.api_key_from_env({})

    def test_key_never_appears_in_client_repr(self) -> None:
        client = vt.VirusTotalHttpClient("super-secret-key")
        assert "super-secret-key" not in repr(client)
        assert "redacted" in repr(client)

    def test_urlscan_key_never_appears_in_repr(self) -> None:
        client = urlscan_module.UrlscanHttpClient("super-secret-key")
        assert "super-secret-key" not in repr(client)

    def test_unavailable_client_fails_loudly(self) -> None:
        """Returning an empty report would read as 'nothing known', which is
        a dangerously reassuring answer when nobody actually asked."""
        client = vt.UnavailableVirusTotalClient("no key")
        with pytest.raises(vt.VirusTotalCredentialsError):
            run(client.report("url", "https://x.test/"))

    def test_default_client_without_credentials_is_the_unavailable_one(self) -> None:
        client = vt.default_virustotal_client({})
        assert isinstance(client, vt.UnavailableVirusTotalClient)


class TestTokenBucket:
    def test_allows_a_burst_up_to_capacity(self) -> None:
        bucket = vt.TokenBucket(rate_per_minute=60.0, capacity=3.0)

        async def scenario() -> float:
            total = 0.0
            for _ in range(3):
                total += await bucket.acquire()
            return total

        # Three tokens are already in the bucket, so none of them waits.
        assert run(scenario()) == 0.0

    def test_throttles_beyond_capacity(self) -> None:
        bucket = vt.TokenBucket(rate_per_minute=6000.0, capacity=1.0)

        async def scenario() -> float:
            await bucket.acquire()
            return await bucket.acquire()

        # The second acquire must wait for a refill (10ms at this rate).
        assert run(scenario()) > 0.0

    def test_rejects_impossible_request(self) -> None:
        bucket = vt.TokenBucket(rate_per_minute=4.0, capacity=2.0)
        with pytest.raises(ValueError, match="capacity"):
            run(bucket.acquire(5.0))

    def test_rejects_invalid_rate(self) -> None:
        with pytest.raises(ValueError, match="positive"):
            vt.TokenBucket(rate_per_minute=0.0)

    def test_public_tier_default(self) -> None:
        assert vt.PUBLIC_TIER_PER_MINUTE == 4.0


class TestVirusTotalParsing:
    URL_REPORT: ClassVar[dict[str, Any]] = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 7,
                    "suspicious": 2,
                    "harmless": 50,
                    "undetected": 12,
                },
                "categories": {"Sophos": "phishing", "Forcepoint": "Phishing"},
                "reputation": -42,
                "last_analysis_date": 1735689600,
            }
        }
    }

    def test_parses_counts(self) -> None:
        verdict = vt.parse_url_report(self.URL_REPORT, "https://phish.test/")
        assert verdict.malicious == 7
        assert verdict.suspicious == 2
        assert verdict.total_engines == 71
        assert verdict.source == "virustotal"
        assert verdict.indicator_type == "url"

    def test_deduplicates_categories(self) -> None:
        verdict = vt.parse_url_report(self.URL_REPORT, "https://phish.test/")
        assert verdict.categories == ("phishing",)

    def test_carries_the_index_timestamp(self) -> None:
        # It reports what VirusTotal last saw, not what is true now.
        verdict = vt.parse_url_report(self.URL_REPORT, "https://phish.test/")
        assert verdict.as_of is not None
        assert verdict.as_of.year == 2025

    def test_produces_a_high_severity_finding(self) -> None:
        found = vt.parse_url_report(self.URL_REPORT, "https://phish.test/").to_finding()
        assert found is not None
        assert found.severity is Severity.CRITICAL

    def test_empty_payload_is_a_clean_verdict_not_a_crash(self) -> None:
        verdict = vt.parse_domain_report({}, "example.com")
        assert verdict.malicious == 0
        assert verdict.to_finding() is None

    def test_missing_stats_are_zeroed(self) -> None:
        verdict = vt.parse_ip_report({"data": {"attributes": {}}}, "1.2.3.4")
        assert verdict.total_engines == 0

    def test_url_identifier_is_unpadded_base64(self) -> None:
        identifier = vt.url_identifier("https://example.com/")
        assert "=" not in identifier

    def test_passive_dns_from_dns_records(self) -> None:
        payload = {
            "data": {
                "attributes": {
                    "last_dns_records": [
                        {"type": "A", "value": "93.184.216.34"},
                        {"type": "MX", "value": "mail.example.com"},
                    ]
                }
            }
        }
        assert vt.passive_dns(payload) == ["93.184.216.34"]

    def test_passive_dns_absent_is_empty(self) -> None:
        assert vt.passive_dns({}) == []


class TestUrlscanParsing:
    SEARCH: ClassVar[dict[str, Any]] = {
        "results": [
            {
                "verdicts": {"overall": {"malicious": True, "categories": ["phishing"]}},
                "task": {"time": "2025-06-01T12:00:00.000Z"},
            },
            {
                "verdicts": {"overall": {"malicious": False}},
                "task": {"time": "2025-05-01T00:00:00Z"},
            },
        ]
    }

    def test_counts_flagged_scans(self) -> None:
        verdict = urlscan_module.parse_search(self.SEARCH, "https://phish.test/")
        assert verdict.malicious == 1
        assert verdict.harmless == 1
        assert verdict.categories == ("phishing",)

    def test_uses_the_latest_scan_time(self) -> None:
        verdict = urlscan_module.parse_search(self.SEARCH, "https://phish.test/")
        assert verdict.as_of is not None
        assert verdict.as_of.month == 6

    def test_empty_search(self) -> None:
        verdict = urlscan_module.parse_search({}, "https://x.test/")
        assert verdict.malicious == 0
        assert verdict.to_finding() is None

    def test_parses_a_result_document(self) -> None:
        payload = {
            "task": {
                "uuid": "abc-123",
                "url": "https://phish.test/login",
                "time": "2025-06-01T12:00:00Z",
                "screenshotURL": "https://urlscan.io/screenshots/abc-123.png",
            },
            "page": {"url": "https://collector.test/final"},
            "verdicts": {"overall": {"malicious": True, "score": 80, "categories": ["phishing"]}},
            "lists": {"domains": ["cdn.test", "collector.test"], "ips": ["203.0.113.9"]},
            "data": {
                "requests": [
                    {"response": {"remoteIPAddress": "203.0.113.5"}},
                ]
            },
        }
        result = urlscan_module.parse_result(payload)
        assert result.scan_id == "abc-123"
        assert result.final_url == "https://collector.test/final"
        assert result.malicious is True
        assert result.score == 80
        assert "collector.test" in result.contacted_domains
        assert "203.0.113.5" in result.ip_addresses
        assert "203.0.113.9" in result.ip_addresses

    def test_result_to_verdict(self) -> None:
        result = urlscan_module.ScanResult(
            url="https://phish.test/", malicious=True, score=90
        )
        verdict = urlscan_module.result_to_verdict(result)
        assert verdict.malicious == 1
        assert verdict.reputation == 90

    def test_empty_result_document(self) -> None:
        result = urlscan_module.parse_result({})
        assert result.scan_id == ""
        assert result.chain == []
        assert result.contacted_domains == []


class TestSubmitOptions:
    def test_defaults_to_unlisted(self) -> None:
        """A public scan is published where anyone can read it, so defaulting
        to public would leak what an engagement is looking at."""
        assert urlscan_module.SubmitOptions().visibility == "unlisted"

    def test_rejects_unknown_visibility(self) -> None:
        with pytest.raises(ValueError, match="visibility"):
            urlscan_module.SubmitOptions(visibility="everyone")

    def test_payload_includes_url_and_visibility(self) -> None:
        payload = urlscan_module.SubmitOptions(
            visibility="private", tags=("ir",)
        ).to_payload("https://x.test/")
        assert payload == {
            "url": "https://x.test/",
            "visibility": "private",
            "tags": ["ir"],
        }

    def test_unavailable_client_refuses_all_operations(self) -> None:
        client = urlscan_module.UnavailableUrlscanClient("no key")
        for coro in (
            client.search("q"),
            client.submit("https://x.test/", urlscan_module.SubmitOptions()),
            client.result("id"),
        ):
            with pytest.raises(urlscan_module.UrlscanCredentialsError):
                run(coro)
