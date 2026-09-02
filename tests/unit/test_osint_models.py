"""Tests for OSINT entity models and canonicalization.

Canonicalization is the load-bearing behaviour here: if two spellings of the
same thing produce different keys, the graph fragments and every downstream
correlation is wrong. These tests pin that down.
"""

from __future__ import annotations

import pytest

from security_assistant.osint.models import (
    Confidence,
    EdgeType,
    Entity,
    EntityType,
    Observation,
    Relationship,
    combine_confidence,
    looks_like_email,
    normalize_domain,
    normalize_email,
    normalize_organization,
    normalize_phone,
    normalize_social_handle,
)


class TestNormalizeDomain:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("example.com", "example.com"),
            ("  Example.COM  ", "example.com"),
            ("example.com.", "example.com"),
            ("API.Example.COM.", "api.example.com"),
        ],
    )
    def test_normalizes(self, raw: str, expected: str) -> None:
        assert normalize_domain(raw) == expected

    def test_idna_encodes_unicode(self) -> None:
        assert normalize_domain("bücher.de") == "xn--bcher-kva.de"

    def test_rejects_empty(self) -> None:
        with pytest.raises(ValueError, match="must not be empty"):
            normalize_domain("   ")


class TestNormalizeEmail:
    def test_lowercases_both_halves(self) -> None:
        assert normalize_email("Alice+News@Example.COM") == "alice+news@example.com"

    def test_normalizes_domain_half(self) -> None:
        assert normalize_email("a@Example.COM.") == "a@example.com"

    def test_handles_plus_in_local_part(self) -> None:
        assert normalize_email("a+b@x.com") == "a+b@x.com"

    @pytest.mark.parametrize("bad", ["not-an-email", "@example.com", "a@", ""])
    def test_rejects_malformed(self, bad: str) -> None:
        with pytest.raises(ValueError):
            normalize_email(bad)


class TestNormalizePhone:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("+1 (415) 555-0100", "+14155550100"),
            ("+44 20 7946 0958", "+442079460958"),
            ("415-555-0100", "4155550100"),
        ],
    )
    def test_strips_formatting(self, raw: str, expected: str) -> None:
        assert normalize_phone(raw) == expected

    def test_does_not_invent_a_country_code(self) -> None:
        # Guessing a region would produce confident nonsense.
        assert not normalize_phone("555-0100").startswith("+")

    @pytest.mark.parametrize("bad", ["", "   ", "abc", "+"])
    def test_rejects_non_numbers(self, bad: str) -> None:
        with pytest.raises(ValueError):
            normalize_phone(bad)


class TestNormalizeSocialHandle:
    @pytest.mark.parametrize(
        ("raw", "platform", "expected"),
        [
            ("@Alice", "Twitter", "twitter/alice"),
            ("alice", "GitHub", "github/alice"),
            ("twitter/Alice", None, "twitter/alice"),
            ("@bob", None, "bob"),
        ],
    )
    def test_normalizes(self, raw: str, platform: str | None, expected: str) -> None:
        assert normalize_social_handle(raw, platform) == expected

    def test_parses_profile_urls(self) -> None:
        assert normalize_social_handle("https://github.com/Some-User") == "github.com/some-user"

    def test_rejects_empty(self) -> None:
        with pytest.raises(ValueError):
            normalize_social_handle("  ")


class TestNormalizeOrganization:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("Acme, Inc.", "acme"),
            ("ACME  LLC", "acme"),
            ("Acme Corporation", "acme"),
            ("Acme GmbH", "acme"),
            ("Acme Widgets Ltd", "acme widgets"),
        ],
    )
    def test_strips_legal_suffixes(self, raw: str, expected: str) -> None:
        assert normalize_organization(raw) == expected

    def test_strips_accents(self) -> None:
        assert normalize_organization("Café Corp") == "cafe"

    def test_keeps_name_that_is_only_a_suffix(self) -> None:
        # Stripping everything would produce an empty key that collides with
        # every other all-suffix name.
        assert normalize_organization("Inc") == "inc"

    def test_rejects_empty(self) -> None:
        with pytest.raises(ValueError):
            normalize_organization("  ")


class TestCombineConfidence:
    def test_noisy_or_of_two_sources(self) -> None:
        assert combine_confidence([0.6, 0.6]) == pytest.approx(0.84)

    def test_corroboration_increases_belief(self) -> None:
        assert combine_confidence([0.5, 0.5]) > 0.5

    def test_never_reaches_certainty_from_partial_evidence(self) -> None:
        assert combine_confidence([0.9] * 5) < 1.0

    def test_empty_is_zero(self) -> None:
        assert combine_confidence([]) == 0.0

    def test_certainty_is_absorbing(self) -> None:
        assert combine_confidence([1.0, 0.1]) == pytest.approx(1.0)

    def test_clamps_out_of_range_input(self) -> None:
        assert 0.0 <= combine_confidence([5.0, -3.0]) <= 1.0


class TestEntity:
    def test_key_is_type_plus_canonical(self) -> None:
        entity = Entity.create(EntityType.DOMAIN, "Example.COM.")
        assert entity.key == "domain:example.com"
        assert entity.value == "Example.COM."

    def test_equivalent_spellings_share_a_key(self) -> None:
        left = Entity.create(EntityType.DOMAIN, "EXAMPLE.com")
        right = Entity.create(EntityType.DOMAIN, "example.com.")
        assert left.key == right.key

    def test_ipv6_is_compressed(self) -> None:
        entity = Entity.create(EntityType.IP_ADDRESS, "2001:0db8:0000::0001")
        assert entity.key == "ip_address:2001:db8::1"

    def test_invalid_value_rejected(self) -> None:
        with pytest.raises(ValueError):
            Entity.create(EntityType.IP_ADDRESS, "not-an-ip")

    def test_sources_are_distinct_and_ordered(self) -> None:
        entity = Entity.create(EntityType.DOMAIN, "example.com", source="osint.dns")
        entity.observations.append(Observation(source="osint.dns", detail="again"))
        entity.observations.append(Observation(source="osint.tls"))
        assert entity.sources == ["osint.dns", "osint.tls"]

    def test_merge_combines_confidence_and_attributes(self) -> None:
        left = Entity.create(
            EntityType.DOMAIN, "example.com", confidence=0.6, attributes={"a": 1}
        )
        right = Entity.create(
            EntityType.DOMAIN, "example.com", confidence=0.6, attributes={"b": 2}
        )
        merged = left.merge(right)
        assert merged.confidence == pytest.approx(0.84)
        assert merged.attributes == {"a": 1, "b": 2}

    def test_merge_keeps_first_observation_of_a_fact(self) -> None:
        left = Entity.create(EntityType.DOMAIN, "example.com", attributes={"a": 1})
        right = Entity.create(EntityType.DOMAIN, "example.com", attributes={"a": 99})
        assert left.merge(right).attributes["a"] == 1

    def test_merge_rejects_different_keys(self) -> None:
        left = Entity.create(EntityType.DOMAIN, "a.com")
        right = Entity.create(EntityType.DOMAIN, "b.com")
        with pytest.raises(ValueError, match="different keys"):
            left.merge(right)

    def test_merge_deduplicates_observations(self) -> None:
        left = Entity.create(EntityType.DOMAIN, "example.com", source="osint.dns", detail="A")
        right = Entity.create(EntityType.DOMAIN, "example.com", source="osint.dns", detail="A")
        assert len(left.merge(right).observations) == 1

    def test_serializes(self) -> None:
        payload = Entity.create(EntityType.DOMAIN, "example.com", source="osint.dns").to_dict()
        assert payload["key"] == "domain:example.com"
        assert payload["sources"] == ["osint.dns"]


class TestRelationship:
    def test_key_is_source_type_target(self) -> None:
        left = Entity.create(EntityType.DOMAIN, "example.com")
        right = Entity.create(EntityType.IP_ADDRESS, "93.184.216.34")
        rel = Relationship.create(left, right, EdgeType.RESOLVES_TO)
        assert rel.key == ("domain:example.com", "resolves_to", "ip_address:93.184.216.34")

    def test_accepts_keys_as_well_as_entities(self) -> None:
        rel = Relationship.create("domain:a.com", "domain:b.com", EdgeType.ALIAS_OF)
        assert rel.source_key == "domain:a.com"

    def test_rejects_self_loops(self) -> None:
        with pytest.raises(ValueError, match="self-loop"):
            Relationship.create("domain:a.com", "domain:a.com", EdgeType.ALIAS_OF)

    def test_merge_corroborates_confidence(self) -> None:
        left = Relationship.create("a", "b", EdgeType.RESOLVES_TO, confidence=0.6)
        right = Relationship.create("a", "b", EdgeType.RESOLVES_TO, confidence=0.6)
        assert left.merge(right).confidence == pytest.approx(0.84)

    def test_merge_rejects_different_keys(self) -> None:
        left = Relationship.create("a", "b", EdgeType.RESOLVES_TO)
        right = Relationship.create("a", "c", EdgeType.RESOLVES_TO)
        with pytest.raises(ValueError, match="different keys"):
            left.merge(right)


class TestHelpers:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [("a@b.com", True), ("not-email", False), ("a@b", False), ("", False)],
    )
    def test_looks_like_email(self, value: str, expected: bool) -> None:
        assert looks_like_email(value) is expected

    def test_confidence_clamp(self) -> None:
        assert Confidence.clamp(2.0) == 1.0
        assert Confidence.clamp(-1.0) == 0.0
