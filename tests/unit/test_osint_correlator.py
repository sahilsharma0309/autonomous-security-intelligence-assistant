"""Tests for correlation and entity resolution.

The bias under test throughout is conservatism: a false merge silently fuses
two organizations into one picture and corrupts every later conclusion, so
these tests care as much about what the correlator *refuses* to do as what it
does.
"""

from __future__ import annotations

import pytest

from security_assistant.osint.correlator import (
    Correlator,
    CorrelatorConfig,
    build_graph_from_payloads,
    string_similarity,
)
from security_assistant.osint.graph import EntityGraph
from security_assistant.osint.models import (
    EdgeType,
    Entity,
    EntityType,
    Relationship,
)


def org(name: str, **kwargs: object) -> Entity:
    return Entity.create(EntityType.ORGANIZATION, name, **kwargs)  # type: ignore[arg-type]


def domain(name: str) -> Entity:
    return Entity.create(EntityType.DOMAIN, name)


def ip(address: str) -> Entity:
    return Entity.create(EntityType.IP_ADDRESS, address)


def email(address: str) -> Entity:
    return Entity.create(EntityType.EMAIL, address)


class TestStringSimilarity:
    def test_identical_is_one(self) -> None:
        assert string_similarity("acme", "acme") == 1.0

    def test_close_names_score_high(self) -> None:
        assert string_similarity("acme corp", "acme corporation") > 0.7

    def test_unrelated_names_score_zero(self) -> None:
        assert string_similarity("acme", "zenith") == 0.0

    def test_empty_is_zero(self) -> None:
        assert string_similarity("", "acme") == 0.0


class TestOrganizationResolution:
    def test_identical_normalized_names_merge_at_insertion(self) -> None:
        # "Acme Inc." and "ACME, LLC" both normalize to "acme", so they share a
        # key and collapse before the correlator is ever involved. This is the
        # canonicalization doing the easy half of deduplication.
        graph = EntityGraph()
        graph.add_entity(org("Acme Inc."))
        graph.add_entity(org("ACME, LLC"))
        assert len(graph) == 1

        report = Correlator().correlate(graph)
        assert report.merged == []

    def test_merges_names_that_differ_beyond_normalization(self) -> None:
        # Singular/plural survives normalization, so resolving these is the
        # correlator's job.
        graph = EntityGraph()
        graph.add_entity(org("Acme Widgets"))
        graph.add_entity(org("Acme Widget"))
        assert len(graph) == 2

        report = Correlator().correlate(graph)
        assert len(report.merged) == 1
        assert len(graph) == 1

    def test_refuses_to_merge_unrelated_organizations(self) -> None:
        graph = EntityGraph()
        graph.add_entity(org("Acme Widgets"))
        graph.add_entity(org("Zenith Industries"))

        report = Correlator().correlate(graph)
        assert report.merged == []
        assert len(graph) == 2

    def test_never_merges_generic_issuers(self) -> None:
        # Certificate issuers appear across unrelated targets; merging them
        # would fuse every domain they ever signed.
        graph = EntityGraph()
        graph.add_entity(org("Let's Encrypt"))
        graph.add_entity(org("Lets Encrypt"))

        report = Correlator().correlate(graph)
        assert report.merged == []
        assert len(graph) == 2

    def test_better_corroborated_entity_survives(self) -> None:
        from security_assistant.osint.models import Observation

        graph = EntityGraph()
        graph.add_entity(org("Acme Widget", source="osint.whois"))
        strong = graph.add_entity(org("Acme Widgets", source="osint.whois"))
        strong.observations.append(Observation(source="osint.tls"))

        Correlator().correlate(graph)
        assert len(graph) == 1
        # The node with two corroborating sources is the one that survives.
        assert graph.by_type(EntityType.ORGANIZATION)[0].canonical == "acme widgets"

    def test_borderline_scores_are_proposed_not_applied(self) -> None:
        graph = EntityGraph()
        graph.add_entity(org("Acme Widgets"))
        graph.add_entity(org("Acme Widget"))

        correlator = Correlator(
            CorrelatorConfig(
                merge_threshold=0.99, review_threshold=0.5, organization_similarity=0.8
            )
        )
        report = correlator.correlate(graph)

        assert report.merged == []
        assert len(report.proposed) == 1
        assert len(graph) == 2  # nothing applied

    def test_evidence_is_recorded_with_a_rationale(self) -> None:
        graph = EntityGraph()
        graph.add_entity(org("Acme Widgets"))
        graph.add_entity(org("Acme Widget"))

        report = Correlator().correlate(graph)
        candidate = report.merged[0]
        assert candidate.evidence
        assert "organization_name_similarity" in candidate.rationale


class TestDomainResolution:
    def test_merges_www_alias_into_the_apex(self) -> None:
        graph = EntityGraph()
        graph.add_entity(domain("example.com"))
        graph.add_entity(domain("www.example.com"))

        report = Correlator().correlate(graph)

        assert len(report.merged) == 1
        # The apex is the surviving identity, not the www alias.
        assert "domain:example.com" in graph
        assert "domain:www.example.com" not in graph

    def test_does_not_merge_unrelated_subdomains(self) -> None:
        graph = EntityGraph()
        graph.add_entity(domain("example.com"))
        graph.add_entity(domain("api.example.com"))

        report = Correlator().correlate(graph)
        assert report.merged == []
        assert len(graph) == 2


class TestLinkInference:
    def test_infers_subdomain_containment(self) -> None:
        graph = EntityGraph()
        graph.add_entity(domain("example.com"))
        graph.add_entity(domain("api.example.com"))

        report = Correlator().correlate(graph)
        inferred = {(r.source_key, r.type, r.target_key) for r in report.inferred}
        assert (
            "domain:api.example.com",
            EdgeType.SUBDOMAIN_OF,
            "domain:example.com",
        ) in inferred

    def test_associates_domains_sharing_an_address(self) -> None:
        graph = EntityGraph()
        a = graph.add_entity(domain("a.com"))
        b = graph.add_entity(domain("b.com"))
        address = graph.add_entity(ip("203.0.113.10"))
        graph.add_relationship(Relationship.create(a, address, EdgeType.RESOLVES_TO))
        graph.add_relationship(Relationship.create(b, address, EdgeType.RESOLVES_TO))

        report = Correlator().correlate(graph)
        associations = [
            r for r in report.inferred if r.type is EdgeType.ASSOCIATED_WITH
        ]
        assert len(associations) == 1
        # Co-residency is a hint, never treated as proof of ownership.
        assert associations[0].confidence <= 0.4

    def test_ignores_high_fanout_shared_hosting(self) -> None:
        graph = EntityGraph()
        address = graph.add_entity(ip("203.0.113.10"))
        for index in range(12):
            host = graph.add_entity(domain(f"host{index}.com"))
            graph.add_relationship(Relationship.create(host, address, EdgeType.RESOLVES_TO))

        report = Correlator().correlate(graph)
        assert [r for r in report.inferred if r.type is EdgeType.ASSOCIATED_WITH] == []

    def test_links_email_to_its_own_domain(self) -> None:
        graph = EntityGraph()
        graph.add_entity(domain("example.com"))
        graph.add_entity(email("admin@example.com"))

        report = Correlator().correlate(graph)
        uses = [r for r in report.inferred if r.type is EdgeType.USES_EMAIL]
        assert len(uses) == 1
        assert uses[0].target_key == "email:admin@example.com"

    def test_ignores_public_email_providers(self) -> None:
        # A shared gmail.com domain says nothing about common ownership.
        graph = EntityGraph()
        graph.add_entity(domain("gmail.com"))
        graph.add_entity(email("someone@gmail.com"))

        report = Correlator().correlate(graph)
        assert [r for r in report.inferred if r.type is EdgeType.USES_EMAIL] == []

    def test_never_duplicates_an_existing_edge(self) -> None:
        graph = EntityGraph()
        parent = graph.add_entity(domain("example.com"))
        child = graph.add_entity(domain("api.example.com"))
        graph.add_relationship(
            Relationship.create(child, parent, EdgeType.SUBDOMAIN_OF)
        )

        report = Correlator().correlate(graph)
        assert [r for r in report.inferred if r.type is EdgeType.SUBDOMAIN_OF] == []

    def test_inference_can_be_disabled(self) -> None:
        graph = EntityGraph()
        graph.add_entity(domain("example.com"))
        graph.add_entity(domain("api.example.com"))

        correlator = Correlator(
            CorrelatorConfig(
                infer_subdomains=False,
                infer_shared_infrastructure=False,
                infer_email_domains=False,
            )
        )
        assert correlator.correlate(graph).inferred == []


class TestDryRun:
    def test_apply_false_changes_nothing(self) -> None:
        graph = EntityGraph()
        graph.add_entity(org("Acme Widgets"))
        graph.add_entity(org("Acme Widget"))
        graph.add_entity(domain("example.com"))
        graph.add_entity(domain("api.example.com"))
        before = len(graph)
        before_edges = len(graph.relationships)

        report = Correlator().correlate(graph, apply=False)

        assert report.merged  # it still reports what it would do
        assert report.inferred
        assert len(graph) == before
        assert len(graph.relationships) == before_edges


class TestReport:
    def test_summary_and_serialization(self) -> None:
        graph = EntityGraph()
        graph.add_entity(org("Acme Widgets"))
        graph.add_entity(org("Acme Widget"))

        report = Correlator().correlate(graph)
        assert "merged 1" in report.summary()
        payload = report.to_dict()
        assert payload["entities_removed"] == 1
        assert payload["merged"][0]["evidence"]


class TestConfigValidation:
    @pytest.mark.parametrize(
        "kwargs",
        [
            {"merge_threshold": 0.0},
            {"merge_threshold": 1.5},
            {"review_threshold": 0.99, "merge_threshold": 0.5},
            {"max_shared_ip_fanout": 0},
        ],
    )
    def test_rejects_invalid_config(self, kwargs: dict) -> None:
        with pytest.raises(ValueError):
            CorrelatorConfig(**kwargs)


class TestBuildGraphFromPayloads:
    def test_assembles_collector_output(self) -> None:
        graph = EntityGraph()
        d = graph.add_entity(domain("example.com"))
        a = graph.add_entity(ip("93.184.216.34"))
        graph.add_relationship(Relationship.create(d, a, EdgeType.RESOLVES_TO))
        payload = graph.to_dict()

        rebuilt = build_graph_from_payloads([payload])
        assert len(rebuilt) == 2
        assert len(rebuilt.relationships) == 1

    def test_merges_overlapping_payloads_from_several_collectors(self) -> None:
        first = {
            "entities": [
                Entity.create(EntityType.DOMAIN, "example.com", source="osint.dns").to_dict()
            ],
            "relationships": [],
        }
        second = {
            "entities": [
                Entity.create(EntityType.DOMAIN, "example.com", source="osint.tls").to_dict()
            ],
            "relationships": [],
        }
        rebuilt = build_graph_from_payloads([first, second])

        assert len(rebuilt) == 1
        assert rebuilt.require("domain:example.com").sources == ["osint.dns", "osint.tls"]

    def test_skips_relationships_with_missing_endpoints(self) -> None:
        payload = {
            "entities": [Entity.create(EntityType.DOMAIN, "example.com").to_dict()],
            "relationships": [
                Relationship.create(
                    "domain:example.com", "domain:ghost.com", EdgeType.ALIAS_OF
                ).to_dict()
            ],
        }
        rebuilt = build_graph_from_payloads([payload])
        assert len(rebuilt) == 1
        assert rebuilt.relationships == []

    def test_ignores_non_dict_payloads(self) -> None:
        assert len(build_graph_from_payloads(["nonsense", 42])) == 0  # type: ignore[list-item]

    def test_skips_malformed_entities(self) -> None:
        payload = {"entities": [{"type": "domain"}], "relationships": []}
        assert len(build_graph_from_payloads([payload])) == 0


class TestEndToEnd:
    def test_realistic_pipeline(self) -> None:
        """DNS + WHOIS + TLS output, correlated into one coherent graph."""
        graph = EntityGraph("engagement")

        apex = graph.add_entity(domain("example.com"))
        www = graph.add_entity(domain("www.example.com"))
        api = graph.add_entity(domain("api.example.com"))
        address = graph.add_entity(ip("93.184.216.34"))
        registrant = graph.add_entity(org("Acme Widgets"))
        duplicate_org = graph.add_entity(org("Acme Widget"))
        contact = graph.add_entity(email("admin@example.com"))

        graph.add_relationship(Relationship.create(apex, address, EdgeType.RESOLVES_TO))
        graph.add_relationship(Relationship.create(www, address, EdgeType.RESOLVES_TO))
        graph.add_relationship(Relationship.create(apex, registrant, EdgeType.REGISTERED_BY))
        graph.add_relationship(Relationship.create(api, duplicate_org, EdgeType.REGISTERED_BY))
        graph.add_relationship(
            Relationship.create(apex, contact, EdgeType.REGISTRANT_CONTACT)
        )

        report = Correlator().correlate(graph)

        # www folded into the apex; the two Acme spellings folded together.
        assert "domain:www.example.com" not in graph
        assert len(graph.by_type(EntityType.ORGANIZATION)) == 1
        assert report.entities_removed == 2

        # api.example.com is now linked to the surviving org and to its parent.
        org_key = graph.by_type(EntityType.ORGANIZATION)[0].key
        assert graph.shortest_path("domain:api.example.com", org_key)
        assert any(
            r.type is EdgeType.SUBDOMAIN_OF and r.source_key == "domain:api.example.com"
            for r in graph.relationships
        )

        # And the whole thing still round-trips.
        assert len(EntityGraph.from_json(graph.to_json())) == len(graph)
