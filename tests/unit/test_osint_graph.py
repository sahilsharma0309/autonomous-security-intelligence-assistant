"""Tests for the OSINT entity graph and its exports."""

from __future__ import annotations

import json

import pytest

from security_assistant.osint.graph import (
    EntityGraph,
    NetworkXNotInstalledError,
)
from security_assistant.osint.models import (
    EdgeType,
    Entity,
    EntityType,
    Relationship,
)


def domain(name: str, **kwargs: object) -> Entity:
    return Entity.create(EntityType.DOMAIN, name, **kwargs)  # type: ignore[arg-type]


def ip(address: str) -> Entity:
    return Entity.create(EntityType.IP_ADDRESS, address)


@pytest.fixture
def graph() -> EntityGraph:
    """A small graph: example.com and www resolve to one IP, plus an org."""
    g = EntityGraph("test")
    apex = g.add_entity(domain("example.com"))
    www = g.add_entity(domain("www.example.com"))
    address = g.add_entity(ip("93.184.216.34"))
    org = g.add_entity(Entity.create(EntityType.ORGANIZATION, "Acme Inc."))

    g.add_relationship(Relationship.create(apex, address, EdgeType.RESOLVES_TO))
    g.add_relationship(Relationship.create(www, address, EdgeType.RESOLVES_TO))
    g.add_relationship(Relationship.create(apex, org, EdgeType.REGISTERED_BY))
    return g


class TestMutation:
    def test_add_and_len(self, graph: EntityGraph) -> None:
        assert len(graph) == 4
        assert "domain:example.com" in graph

    def test_adding_same_entity_merges_rather_than_duplicates(self) -> None:
        g = EntityGraph()
        first = g.add_entity(domain("example.com", confidence=0.6))
        second = g.add_entity(domain("EXAMPLE.com.", confidence=0.6))
        assert len(g) == 1
        assert first is second
        assert second.confidence == pytest.approx(0.84)

    def test_adding_same_relationship_merges(self, graph: EntityGraph) -> None:
        before = len(graph.relationships)
        graph.add_relationship(
            Relationship.create(
                "domain:example.com", "ip_address:93.184.216.34", EdgeType.RESOLVES_TO
            )
        )
        assert len(graph.relationships) == before

    def test_relationship_requires_existing_endpoints(self) -> None:
        g = EntityGraph()
        g.add_entity(domain("a.com"))
        with pytest.raises(KeyError, match="not in the graph"):
            g.add_relationship(
                Relationship.create("domain:a.com", "domain:ghost.com", EdgeType.ALIAS_OF)
            )

    def test_connect_adds_endpoints_and_edge(self) -> None:
        g = EntityGraph()
        g.connect(domain("a.com"), ip("1.1.1.1"), EdgeType.RESOLVES_TO)
        assert len(g) == 2
        assert len(g.relationships) == 1

    def test_remove_entity_removes_its_edges(self, graph: EntityGraph) -> None:
        assert graph.remove_entity("ip_address:93.184.216.34")
        assert len(graph) == 3
        assert all(r.target_key != "ip_address:93.184.216.34" for r in graph.relationships)

    def test_remove_missing_entity_is_false(self, graph: EntityGraph) -> None:
        assert graph.remove_entity("domain:nope.com") is False

    def test_require_raises_for_missing(self, graph: EntityGraph) -> None:
        with pytest.raises(KeyError):
            graph.require("domain:nope.com")


class TestMergeEntities:
    def test_rewires_edges_onto_the_primary(self, graph: EntityGraph) -> None:
        graph.merge_entities("domain:example.com", "domain:www.example.com")

        assert "domain:www.example.com" not in graph
        assert len(graph) == 3
        # The www node's RESOLVES_TO edge is now the apex's; it already had an
        # identical one, so the two collapse into a single edge.
        resolves = [r for r in graph.relationships if r.type is EdgeType.RESOLVES_TO]
        assert len(resolves) == 1
        assert resolves[0].source_key == "domain:example.com"

    def test_records_the_duplicate_value_as_an_alias(self, graph: EntityGraph) -> None:
        graph.merge_entities("domain:example.com", "domain:www.example.com")
        assert "www.example.com" in graph.require("domain:example.com").attributes["aliases"]

    def test_drops_edges_that_would_become_self_loops(self) -> None:
        g = EntityGraph()
        a = g.add_entity(domain("a.com"))
        b = g.add_entity(domain("b.com"))
        g.add_relationship(Relationship.create(a, b, EdgeType.ALIAS_OF))
        g.merge_entities("domain:a.com", "domain:b.com")
        assert len(g) == 1
        assert g.relationships == []

    def test_refuses_to_merge_different_types(self) -> None:
        g = EntityGraph()
        g.add_entity(domain("a.com"))
        g.add_entity(ip("1.1.1.1"))
        with pytest.raises(ValueError, match="different types"):
            g.merge_entities("domain:a.com", "ip_address:1.1.1.1")

    def test_merging_into_itself_is_a_noop(self, graph: EntityGraph) -> None:
        before = len(graph)
        graph.merge_entities("domain:example.com", "domain:example.com")
        assert len(graph) == before


class TestTraversal:
    def test_neighbors_directed_and_undirected(self, graph: EntityGraph) -> None:
        assert {e.key for e in graph.neighbors("domain:example.com")} == {
            "ip_address:93.184.216.34",
            "organization:acme",
        }
        # The IP has no outbound edges, but two domains point at it.
        assert graph.neighbors("ip_address:93.184.216.34") == []
        assert len(graph.neighbors("ip_address:93.184.216.34", directed=False)) == 2

    def test_neighbor_order_is_deterministic(self, graph: EntityGraph) -> None:
        # Ordered by edge key, so repeated runs agree.
        assert [e.key for e in graph.neighbors("domain:example.com")] == [
            "organization:acme",
            "ip_address:93.184.216.34",
        ]

    def test_neighbors_filtered_by_edge_type(self, graph: EntityGraph) -> None:
        found = graph.neighbors("domain:example.com", edge_type=EdgeType.REGISTERED_BY)
        assert [e.key for e in found] == ["organization:acme"]

    def test_degree(self, graph: EntityGraph) -> None:
        assert graph.degree("domain:example.com") == 2
        assert graph.degree("ip_address:93.184.216.34") == 2

    def test_by_type(self, graph: EntityGraph) -> None:
        assert len(graph.by_type(EntityType.DOMAIN)) == 2

    def test_find_filters(self, graph: EntityGraph) -> None:
        assert len(graph.find(entity_type=EntityType.DOMAIN)) == 2
        assert graph.find(min_confidence=1.1) == []
        assert graph.find(source="osint.dns") == []

    def test_shortest_path(self, graph: EntityGraph) -> None:
        path = graph.shortest_path("domain:www.example.com", "organization:acme")
        assert [e.key for e in path] == [
            "domain:www.example.com",
            "ip_address:93.184.216.34",
            "domain:example.com",
            "organization:acme",
        ]

    def test_shortest_path_to_self(self, graph: EntityGraph) -> None:
        assert len(graph.shortest_path("domain:example.com", "domain:example.com")) == 1

    def test_shortest_path_when_disconnected(self, graph: EntityGraph) -> None:
        graph.add_entity(domain("island.com"))
        assert graph.shortest_path("domain:example.com", "domain:island.com") == []

    def test_shortest_path_with_unknown_endpoint(self, graph: EntityGraph) -> None:
        assert graph.shortest_path("domain:example.com", "domain:ghost.com") == []

    def test_components_largest_first(self, graph: EntityGraph) -> None:
        graph.add_entity(domain("island.com"))
        components = graph.components()
        assert len(components) == 2
        assert len(components[0]) == 4
        assert [e.key for e in components[1]] == ["domain:island.com"]


class TestStats:
    def test_counts(self, graph: EntityGraph) -> None:
        stats = graph.stats()
        assert stats.entities == 4
        assert stats.relationships == 3
        assert stats.entities_by_type["domain"] == 2
        assert stats.relationships_by_type["resolves_to"] == 2
        assert stats.isolated_entities == 0

    def test_isolated_counted(self, graph: EntityGraph) -> None:
        graph.add_entity(domain("island.com"))
        assert graph.stats().isolated_entities == 1


class TestJsonExport:
    def test_round_trip_preserves_graph(self, graph: EntityGraph) -> None:
        restored = EntityGraph.from_json(graph.to_json())

        assert len(restored) == len(graph)
        assert {e.key for e in restored} == {e.key for e in graph}
        assert {r.key for r in restored.relationships} == {r.key for r in graph.relationships}

    def test_round_trip_preserves_provenance(self) -> None:
        g = EntityGraph()
        g.add_entity(domain("example.com", source="osint.dns", detail="A record"))
        restored = EntityGraph.from_json(g.to_json())
        assert restored.require("domain:example.com").sources == ["osint.dns"]

    def test_export_is_json_serializable(self, graph: EntityGraph) -> None:
        parsed = json.loads(graph.to_json())
        assert parsed["schema_version"] == "1.0"
        assert len(parsed["entities"]) == 4
        assert "stats" in parsed

    def test_rejects_unknown_schema_version(self) -> None:
        with pytest.raises(ValueError, match="Unsupported graph schema version"):
            EntityGraph.from_dict({"schema_version": "99.0", "entities": []})

    def test_rejects_non_object_json(self) -> None:
        with pytest.raises(ValueError, match="must decode to an object"):
            EntityGraph.from_json("[]")


class TestCypherExport:
    def test_emits_one_statement_per_element(self, graph: EntityGraph) -> None:
        statements = graph.to_cypher()
        assert len(statements) == len(graph) + len(graph.relationships)

    def test_statements_are_idempotent_merges(self, graph: EntityGraph) -> None:
        for statement in graph.to_cypher():
            assert "MERGE" in statement["query"]
            assert "CREATE " not in statement["query"]

    def test_values_are_parameterized_not_interpolated(self, graph: EntityGraph) -> None:
        # Entity values must never reach the query text.
        for statement in graph.to_cypher():
            assert "example.com" not in statement["query"]
            assert statement["parameters"]

    def test_labels_are_pascal_case(self) -> None:
        g = EntityGraph()
        g.add_entity(ip("1.1.1.1"))
        assert ":IpAddress" in g.to_cypher()[0]["query"]

    def test_relationship_types_are_upper_case(self, graph: EntityGraph) -> None:
        queries = " ".join(s["query"] for s in graph.to_cypher())
        assert "RESOLVES_TO" in queries

    def test_nested_attributes_are_json_encoded(self) -> None:
        g = EntityGraph()
        g.add_entity(domain("example.com", attributes={"nested": {"a": 1}}))
        params = g.to_cypher()[0]["parameters"]
        assert json.loads(params["attributes"]) == {"nested": {"a": 1}}


class TestNetworkXExport:
    def test_exports_or_raises_actionably(self, graph: EntityGraph) -> None:
        try:
            exported = graph.to_networkx()
        except NetworkXNotInstalledError as exc:
            # The optional extra is absent; the error must tell you how to fix it.
            assert "networkx is required" in str(exc)
            assert "osint" in str(exc)
            return

        assert exported.number_of_nodes() == 4
        assert exported.number_of_edges() == 3
        assert exported.nodes["domain:example.com"]["type"] == "domain"


class TestMergeGraph:
    def test_folds_another_graph_in(self, graph: EntityGraph) -> None:
        other = EntityGraph()
        other.connect(domain("other.com"), ip("8.8.8.8"), EdgeType.RESOLVES_TO)
        graph.merge_graph(other)
        assert len(graph) == 6
        assert "domain:other.com" in graph
