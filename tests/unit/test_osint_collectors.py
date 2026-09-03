"""Tests for the OSINT collectors.

Every collector's I/O is injected, so these run with no network access and no
optional dependencies installed. The dispatch tests additionally prove the
collectors stay subject to the core's authorization gate.
"""

from __future__ import annotations

from typing import Any, ClassVar

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
from security_assistant.osint.collectors import (
    ALL_COLLECTORS,
    CollectorError,
    DnsRecordSet,
    PlatformHook,
    ProbeOutcome,
    StdlibDnsResolver,
    dns_collect,
    parse_certificate,
    parse_whois_record,
    records_to_graph_elements,
    social_footprint,
    tls_collect,
    whois_collect,
)
from security_assistant.osint.collectors.tls_collector import (
    certificate_to_graph_elements,
)
from security_assistant.osint.collectors.whois_collector import record_to_graph_elements
from tests.unit.conftest import run


# --------------------------------------------------------------------------- #
# Fakes
# --------------------------------------------------------------------------- #
class FakeDnsResolver:
    """Serves canned answers; records what was asked.

    ``fail_types`` makes specific record types raise, which models a resolver
    that can answer some types but not others (exactly what the stdlib
    fallback does for MX/NS).
    """

    def __init__(
        self,
        answers: dict[str, list[str]] | None = None,
        fail_types: set[str] | None = None,
    ) -> None:
        self.answers = answers or {}
        self.fail_types = fail_types or set()
        self.calls: list[tuple[str, str]] = []

    async def resolve(self, name: str, record_type: str) -> list[str]:
        self.calls.append((name, record_type))
        if record_type in self.fail_types:
            raise CollectorError(f"{record_type} lookup unavailable")
        return list(self.answers.get(record_type, []))


class FakeWhoisClient:
    def __init__(self, record: dict[str, Any]) -> None:
        self.record = record

    async def lookup(self, domain: str) -> dict[str, Any]:
        return self.record


class FakeTlsFetcher:
    def __init__(self, certificate: dict[str, Any]) -> None:
        self.certificate = certificate
        self.calls: list[tuple[str, int, bool]] = []

    async def fetch(self, host: str, port: int, *, verify: bool) -> dict[str, Any]:
        self.calls.append((host, port, verify))
        return self.certificate


class FakeProbe:
    def __init__(self, statuses: dict[str, int]) -> None:
        self.statuses = statuses
        self.urls: list[str] = []

    async def probe(self, url: str) -> ProbeOutcome:
        self.urls.append(url)
        if url in self.statuses:
            return ProbeOutcome(url=url, status=self.statuses[url])
        return ProbeOutcome(url=url, status=0, error="unreachable")


def ctx(**config: Any) -> ToolContext:
    return ToolContext(scope=None, config=config)


# --------------------------------------------------------------------------- #
class TestDnsCollector:
    def test_collects_and_maps_records(self) -> None:
        resolver = FakeDnsResolver(
            {
                "A": ["93.184.216.34"],
                "MX": ["10 mail.example.com."],
                "NS": ["ns1.example.com."],
            }
        )
        result = run(
            dns_collect.invoke(
                ctx(dns_resolver=resolver),
                {"target": "Example.COM.", "record_types": ["A", "MX", "NS"]},
            )
        )

        assert result["domain"] == "example.com"
        assert result["records"]["A"] == ["93.184.216.34"]

        keys = {e["key"] for e in result["entities"]}
        assert "domain:example.com" in keys
        assert "ip_address:93.184.216.34" in keys
        assert "domain:mail.example.com" in keys

        edges = {(r["type"], r["target"]) for r in result["relationships"]}
        assert ("resolves_to", "ip_address:93.184.216.34") in edges
        assert ("mail_handled_by", "domain:mail.example.com") in edges
        assert ("nameserver_for", "domain:ns1.example.com") in edges

    def test_mx_priority_is_stripped(self) -> None:
        resolver = FakeDnsResolver({"MX": ["10 mail.example.com."]})
        result = run(
            dns_collect.invoke(
                ctx(dns_resolver=resolver), {"target": "example.com", "record_types": ["MX"]}
            )
        )
        assert "domain:mail.example.com" in {e["key"] for e in result["entities"]}

    def test_extracts_emails_from_txt_records(self) -> None:
        resolver = FakeDnsResolver({"TXT": ["v=DMARC1; rua=mailto:dmarc@example.com; p=none"]})
        result = run(
            dns_collect.invoke(
                ctx(dns_resolver=resolver), {"target": "example.com", "record_types": ["TXT"]}
            )
        )
        assert "email:dmarc@example.com" in {e["key"] for e in result["entities"]}

    def test_one_failing_record_type_does_not_lose_the_others(self) -> None:
        resolver = FakeDnsResolver({"A": ["93.184.216.34"]}, fail_types={"MX"})
        result = run(
            dns_collect.invoke(
                ctx(dns_resolver=resolver),
                {"target": "example.com", "record_types": ["A", "MX"]},
            )
        )
        assert result["records"]["A"] == ["93.184.216.34"]
        assert "MX" in result["errors"]

    def test_total_failure_raises(self) -> None:
        resolver = FakeDnsResolver({}, fail_types={"A", "MX"})
        with pytest.raises(CollectorError, match="No DNS records"):
            run(
                dns_collect.invoke(
                    ctx(dns_resolver=resolver),
                    {"target": "example.com", "record_types": ["A", "MX"]},
                )
            )

    def test_no_records_and_no_errors_is_not_a_failure(self) -> None:
        # A domain that genuinely has no records of the requested types is a
        # valid finding, not an error.
        result = run(
            dns_collect.invoke(
                ctx(dns_resolver=FakeDnsResolver({})),
                {"target": "example.com", "record_types": ["A"]},
            )
        )
        assert result["records"] == {}
        assert result["errors"] == {}

    def test_rejects_unsupported_record_type(self) -> None:
        with pytest.raises(CollectorError, match="Unsupported DNS record type"):
            run(
                dns_collect.invoke(
                    ctx(dns_resolver=FakeDnsResolver()),
                    {"target": "example.com", "record_types": ["NOPE"]},
                )
            )

    def test_rejects_invalid_domain(self) -> None:
        with pytest.raises(CollectorError, match="Invalid domain"):
            run(dns_collect.invoke(ctx(dns_resolver=FakeDnsResolver()), {"target": "  "}))

    def test_defaults_to_the_standard_record_set(self) -> None:
        resolver = FakeDnsResolver({"A": ["1.2.3.4"]})
        run(dns_collect.invoke(ctx(dns_resolver=resolver), {"target": "example.com"}))
        assert {rt for _, rt in resolver.calls} == {"A", "AAAA", "MX", "NS", "TXT", "CNAME"}

    def test_malformed_answers_are_skipped_not_fatal(self) -> None:
        record_set = DnsRecordSet(domain="example.com", records={"A": ["not-an-ip"]})
        entities, relationships = records_to_graph_elements(record_set)
        assert [e.key for e in entities] == ["domain:example.com"]
        assert relationships == []

    def test_stdlib_resolver_refuses_unsupported_types_loudly(self) -> None:
        # Returning [] would look like "no MX records" rather than "can't ask".
        with pytest.raises(CollectorError, match="require dnspython"):
            run(StdlibDnsResolver().resolve("example.com", "MX"))


class TestWhoisCollector:
    def test_parses_and_maps_a_record(self) -> None:
        client = FakeWhoisClient(
            {
                "registrar": "Example Registrar LLC",
                "org": "Acme Inc.",
                "emails": ["admin@example.com"],
                "name_servers": ["NS1.EXAMPLE.COM.", "ns2.example.com"],
                "creation_date": "2001-01-01T00:00:00",
            }
        )
        result = run(whois_collect.invoke(ctx(whois_client=client), {"target": "example.com"}))

        assert result["registrant_org"] == "Acme Inc."
        assert result["emails"] == ["admin@example.com"]
        assert result["nameservers"] == ["ns1.example.com", "ns2.example.com"]
        assert result["redacted"] is False

        keys = {e["key"] for e in result["entities"]}
        assert "organization:acme" in keys
        assert "email:admin@example.com" in keys

    def test_detects_gdpr_redaction(self) -> None:
        record = parse_whois_record(
            "example.com",
            {"org": "REDACTED FOR PRIVACY", "emails": ["Please query the RDDS service"]},
        )
        assert record.redacted is True
        assert record.registrant_org is None
        # A privacy placeholder must not become an organization entity.
        assert record.emails == []

    def test_privacy_placeholders_do_not_become_entities(self) -> None:
        record = parse_whois_record("example.com", {"org": "Domains By Proxy, LLC"})
        entities, _ = record_to_graph_elements(record)
        assert [e.key for e in entities] == ["domain:example.com"]

    def test_handles_scalar_and_list_fields(self) -> None:
        scalar = parse_whois_record("a.com", {"emails": "one@a.com"})
        listed = parse_whois_record("b.com", {"emails": ["one@b.com", "two@b.com"]})
        assert scalar.emails == ["one@a.com"]
        assert listed.emails == ["one@b.com", "two@b.com"]

    def test_registrar_is_weaker_evidence_than_registrant(self) -> None:
        record = parse_whois_record(
            "example.com", {"org": "Acme Inc.", "registrar": "Big Registrar"}
        )
        _, relationships = record_to_graph_elements(record)
        by_target = {r.target_key: r.confidence for r in relationships}
        assert by_target["organization:acme"] > by_target["organization:big registrar"]

    def test_empty_record_is_not_an_error(self) -> None:
        result = run(
            whois_collect.invoke(ctx(whois_client=FakeWhoisClient({})), {"target": "example.com"})
        )
        assert result["registrant_org"] is None
        assert result["redacted"] is False

    def test_missing_backend_fails_actionably(self) -> None:
        from security_assistant.osint.collectors import UnavailableWhoisClient

        with pytest.raises(CollectorError, match="No WHOIS backend available"):
            run(UnavailableWhoisClient().lookup("example.com"))

    def test_non_email_contact_values_are_filtered(self) -> None:
        record = parse_whois_record("example.com", {"emails": ["not an email", "ok@example.com"]})
        assert record.emails == ["ok@example.com"]


class TestTlsCollector:
    CERT: ClassVar[dict[str, Any]] = {
        "subject": ((("commonName", "example.com"),),),
        "issuer": (
            (("commonName", "R3"),),
            (("organizationName", "Let's Encrypt"),),
        ),
        "subjectAltName": (
            ("DNS", "example.com"),
            ("DNS", "*.example.com"),
            ("DNS", "cdn.example.net"),
        ),
        "notBefore": "Jun  1 12:00:00 2025 GMT",
        "notAfter": "Sep  1 12:00:00 2035 GMT",
        "serialNumber": "ABCD1234",
        "_version": "TLSv1.3",
        "_cipher": ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
    }

    def test_collects_and_maps_a_certificate(self) -> None:
        fetcher = FakeTlsFetcher(self.CERT)
        result = run(tls_collect.invoke(ctx(tls_fetcher=fetcher), {"target": "example.com"}))

        assert result["subject_cn"] == "example.com"
        assert result["issuer_org"] == "Let's Encrypt"
        assert result["tls_version"] == "TLSv1.3"
        assert result["is_expired"] is False
        assert fetcher.calls == [("example.com", 443, True)]

        keys = {e["key"] for e in result["entities"]}
        assert "domain:cdn.example.net" in keys
        assert "organization:let s encrypt" in keys

    def test_wildcard_sans_are_normalized(self) -> None:
        certificate = parse_certificate("example.com", 443, dict(self.CERT))
        assert "example.com" in certificate.sans
        assert not any(s.startswith("*") for s in certificate.sans)

    def test_san_matching_the_host_is_not_self_linked(self) -> None:
        certificate = parse_certificate("example.com", 443, dict(self.CERT))
        _, relationships = certificate_to_graph_elements(certificate)
        secures = [r for r in relationships if r.type.value == "secures"]
        assert all(r.target_key != "domain:example.com" for r in secures)

    def test_detects_expiry(self) -> None:
        expired = dict(self.CERT, notAfter="Jun  1 12:00:00 2020 GMT")
        certificate = parse_certificate("example.com", 443, expired)
        assert certificate.is_expired is True

    def test_records_verification_failure_as_data(self) -> None:
        raw = dict(self.CERT, verified=False, verification_error="self signed certificate")
        certificate = parse_certificate("example.com", 443, raw)
        entities, _ = certificate_to_graph_elements(certificate)
        root = entities[0]
        assert root.attributes["cert_verified"] is False
        assert root.attributes["cert_verification_error"] == "self signed certificate"

    def test_rejects_out_of_range_port(self) -> None:
        with pytest.raises(CollectorError, match="Port out of range"):
            run(
                tls_collect.invoke(
                    ctx(tls_fetcher=FakeTlsFetcher(self.CERT)),
                    {"target": "example.com", "port": 70000},
                )
            )

    def test_honours_verify_flag(self) -> None:
        fetcher = FakeTlsFetcher(self.CERT)
        run(
            tls_collect.invoke(ctx(tls_fetcher=fetcher), {"target": "example.com", "verify": False})
        )
        assert fetcher.calls == [("example.com", 443, False)]

    def test_empty_certificate_yields_only_the_host(self) -> None:
        certificate = parse_certificate("example.com", 443, {})
        entities, relationships = certificate_to_graph_elements(certificate)
        assert [e.key for e in entities] == ["domain:example.com"]
        assert relationships == []


class TestSocialCollector:
    HOOK = PlatformHook(name="examplehub", url_template="https://examplehub.test/u/{username}")

    def test_no_platforms_configured_returns_empty_and_says_so(self) -> None:
        result = run(social_footprint.invoke(ctx(), {"target": "example.com", "username": "alice"}))
        assert result["configured"] is False
        assert result["platforms_checked"] == 0
        assert result["entities"] == []
        assert "No social platforms configured" in result["note"]

    def test_finds_a_handle_when_the_platform_confirms(self) -> None:
        # The probe sees the username as supplied; the resulting graph key is
        # canonicalized to lowercase.
        probe = FakeProbe({"https://examplehub.test/u/Alice": 200})
        result = run(
            social_footprint.invoke(
                ctx(profile_probe=probe, social_platforms=[self.HOOK]),
                {"target": "example.com", "username": "@Alice"},
            )
        )
        assert result["handles_found"] == 1
        assert probe.urls == ["https://examplehub.test/u/Alice"]
        assert "social_handle:examplehub/alice" in {e["key"] for e in result["entities"]}

    def test_absent_status_is_a_clean_miss(self) -> None:
        probe = FakeProbe({"https://examplehub.test/u/alice": 404})
        result = run(
            social_footprint.invoke(
                ctx(profile_probe=probe, social_platforms=[self.HOOK]),
                {"target": "example.com", "username": "alice"},
            )
        )
        assert result["handles_found"] == 0
        assert result["findings"][0]["inconclusive"] is False

    def test_unexpected_status_is_inconclusive_not_a_miss(self) -> None:
        # A 429 means "we don't know", and must not be reported as "no account".
        probe = FakeProbe({"https://examplehub.test/u/alice": 429})
        result = run(
            social_footprint.invoke(
                ctx(profile_probe=probe, social_platforms=[self.HOOK]),
                {"target": "example.com", "username": "alice"},
            )
        )
        assert result["findings"][0]["inconclusive"] is True
        assert result["findings"][0]["exists"] is False

    def test_probe_error_is_inconclusive(self) -> None:
        probe = FakeProbe({})
        result = run(
            social_footprint.invoke(
                ctx(profile_probe=probe, social_platforms=[self.HOOK]),
                {"target": "example.com", "username": "alice"},
            )
        )
        assert result["findings"][0]["inconclusive"] is True
        assert result["findings"][0]["error"] == "unreachable"

    def test_username_is_url_encoded(self) -> None:
        probe = FakeProbe({})
        run(
            social_footprint.invoke(
                ctx(profile_probe=probe, social_platforms=[self.HOOK]),
                {"target": "example.com", "username": "a/../b"},
            )
        )
        assert probe.urls == ["https://examplehub.test/u/a%2F..%2Fb"]

    def test_disabled_platforms_are_skipped(self) -> None:
        disabled = PlatformHook(
            name="off", url_template="https://off.test/{username}", enabled=False
        )
        result = run(
            social_footprint.invoke(
                ctx(profile_probe=FakeProbe({}), social_platforms=[disabled]),
                {"target": "example.com", "username": "alice"},
            )
        )
        assert result["configured"] is False

    def test_platform_hooks_from_mappings(self) -> None:
        probe = FakeProbe({"https://m.test/alice": 200})
        result = run(
            social_footprint.invoke(
                ctx(profile_probe=probe),
                {
                    "target": "example.com",
                    "username": "alice",
                    "platforms": [{"name": "m", "url_template": "https://m.test/{username}"}],
                },
            )
        )
        assert result["handles_found"] == 1

    def test_hook_requires_username_placeholder(self) -> None:
        with pytest.raises(ValueError, match=r"username.*placeholder"):
            PlatformHook(name="bad", url_template="https://bad.test/profile")

    def test_rejects_empty_username(self) -> None:
        with pytest.raises(CollectorError, match="must not be empty"):
            run(social_footprint.invoke(ctx(), {"target": "example.com", "username": " @ "}))

    def test_rejects_overlong_username(self) -> None:
        with pytest.raises(CollectorError, match="exceeds"):
            run(social_footprint.invoke(ctx(), {"target": "example.com", "username": "a" * 200}))

    def test_rejects_malformed_platform_config(self) -> None:
        with pytest.raises(CollectorError):
            run(
                social_footprint.invoke(
                    ctx(social_platforms="not-a-list"),
                    {"target": "example.com", "username": "alice"},
                )
            )


class TestToolSpecContract:
    """The declared metadata is what the planner and safety gate rely on."""

    def test_risk_levels_match_what_each_tool_actually_does(self) -> None:
        risks = {t.spec.name: t.spec.risk for t in ALL_COLLECTORS}
        # WHOIS queries a registry, never the target.
        assert risks["osint.whois"] is RiskLevel.PASSIVE
        # These three can reach the target's own infrastructure.
        assert risks["osint.dns"] is RiskLevel.ACTIVE
        assert risks["osint.tls"] is RiskLevel.ACTIVE
        assert risks["osint.social"] is RiskLevel.ACTIVE

    def test_all_collectors_are_scope_gated(self) -> None:
        assert all(t.spec.requires_scope for t in ALL_COLLECTORS)
        assert all(t.spec.target_argument == "target" for t in ALL_COLLECTORS)

    def test_all_declare_rate_limits_and_timeouts(self) -> None:
        for collector in ALL_COLLECTORS:
            assert collector.spec.rate_limit_per_minute, collector.spec.name
            assert collector.spec.timeout_seconds, collector.spec.name

    def test_produced_artifacts(self) -> None:
        produces = {t.spec.name: t.spec.produces for t in ALL_COLLECTORS}
        assert produces["osint.dns"] == frozenset({"hosts", "dns_records"})
        assert produces["osint.whois"] == frozenset({"registration", "contacts"})
        assert produces["osint.tls"] == frozenset({"certificates", "sans"})
        assert produces["osint.social"] == frozenset({"handles"})

    def test_all_register_cleanly(self) -> None:
        registry = ToolRegistry("osint")
        registry.register_all(ALL_COLLECTORS)
        assert len(registry) == 4


class TestDispatchIntegration:
    """The collectors must remain subject to the core's authorization gate."""

    @staticmethod
    def _dispatcher(max_risk: RiskLevel = RiskLevel.ACTIVE) -> ToolDispatcher:
        registry = ToolRegistry("osint")
        registry.register_all(ALL_COLLECTORS)
        scope = AuthorizationScope(
            allow=["example.com"], max_risk=max_risk, authorization_reference="ENG-T"
        )
        return ToolDispatcher(registry, scope, DispatcherConfig())

    def test_in_scope_target_runs(self) -> None:
        dispatcher = self._dispatcher()
        context = ToolContext(
            scope=dispatcher.scope, config={"dns_resolver": FakeDnsResolver({"A": ["1.2.3.4"]})}
        )
        result = run(
            dispatcher.dispatch(
                __import__(
                    "security_assistant.core.types", fromlist=["ToolInvocation"]
                ).ToolInvocation("osint.dns", {"target": "example.com"}),
                context,
            )
        )
        assert result.status is InvocationStatus.SUCCESS

    def test_out_of_scope_target_is_denied_before_any_lookup(self) -> None:
        dispatcher = self._dispatcher()
        resolver = FakeDnsResolver({"A": ["1.2.3.4"]})
        context = ToolContext(scope=dispatcher.scope, config={"dns_resolver": resolver})
        result = run(dispatcher.call("osint.dns", context, target="not-authorized.net"))

        assert result.status is InvocationStatus.DENIED
        # The gate must fire before the collector touches anything.
        assert resolver.calls == []

    def test_passive_scope_blocks_active_collectors(self) -> None:
        dispatcher = self._dispatcher(max_risk=RiskLevel.PASSIVE)
        context = ToolContext(
            scope=dispatcher.scope, config={"dns_resolver": FakeDnsResolver({"A": ["1.2.3.4"]})}
        )
        denied = run(dispatcher.call("osint.dns", context, target="example.com"))
        assert denied.status is InvocationStatus.DENIED

    def test_passive_scope_still_allows_whois(self) -> None:
        dispatcher = self._dispatcher(max_risk=RiskLevel.PASSIVE)
        context = ToolContext(
            scope=dispatcher.scope, config={"whois_client": FakeWhoisClient({"org": "Acme"})}
        )
        allowed = run(dispatcher.call("osint.whois", context, target="example.com"))
        assert allowed.status is InvocationStatus.SUCCESS

    def test_collector_failure_becomes_a_failed_result_not_an_exception(self) -> None:
        dispatcher = self._dispatcher()
        context = ToolContext(scope=dispatcher.scope, config={"dns_resolver": FakeDnsResolver({})})
        result = run(
            dispatcher.call("osint.dns", context, target="example.com", record_types=["BOOM"])
        )
        assert result.status is InvocationStatus.ERROR
        assert result.error_type == "CollectorError"
