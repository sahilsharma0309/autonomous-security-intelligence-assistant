"""The OSINT entity graph.

:class:`EntityGraph` is the Maltego-style link graph: typed entities joined by
typed, weighted relationships, assembled incrementally as collectors report
observations.

**On storage.** The graph keeps its own adjacency index rather than holding a
``networkx`` object as the source of truth. Two reasons: the assistant must
build graphs in environments where the optional ``osint`` extra is not
installed, and merge-on-insert semantics (an entity observed twice becomes one
node with combined confidence) are clearer implemented directly than layered
over a general-purpose graph library. NetworkX is used where it is genuinely
better -- algorithms and interop -- via :meth:`EntityGraph.to_networkx`, which
returns a real ``nx.MultiDiGraph``.

Three exports are supported:

* :meth:`to_networkx` -- ``nx.MultiDiGraph`` for algorithms and visualization.
* :meth:`to_cypher` -- parameterized Neo4j ``MERGE`` statements, idempotent so
  re-ingesting a graph updates rather than duplicates.
* :meth:`to_json` / :meth:`from_json` -- lossless round-trip for persistence.
"""

from __future__ import annotations

import json
import logging
from collections import defaultdict, deque
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from security_assistant.osint.models import (
    EdgeType,
    Entity,
    EntityType,
    Observation,
    Relationship,
)

logger = logging.getLogger(__name__)

# NetworkX is an optional extra; only `to_networkx` needs it.
_nx: Any
try:  # pragma: no cover - depends on which extras are installed
    import networkx

    _nx = networkx
except ImportError:  # pragma: no cover
    _nx = None

__all__ = ["EntityGraph", "GraphStats", "NetworkXNotInstalledError"]

JSON_SCHEMA_VERSION = "1.0"


class NetworkXNotInstalledError(RuntimeError):
    """Raised by :meth:`EntityGraph.to_networkx` without the ``osint`` extra."""

    def __init__(self) -> None:
        super().__init__(
            "networkx is required for this export. Install the OSINT extra: "
            "`poetry install -E osint` or `pip install networkx`."
        )


@dataclass(frozen=True, slots=True)
class GraphStats:
    """A summary of graph size and composition."""

    entities: int
    relationships: int
    entities_by_type: dict[str, int]
    relationships_by_type: dict[str, int]
    isolated_entities: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "entities": self.entities,
            "relationships": self.relationships,
            "entities_by_type": dict(self.entities_by_type),
            "relationships_by_type": dict(self.relationships_by_type),
            "isolated_entities": self.isolated_entities,
        }


class EntityGraph:
    """A directed multigraph of OSINT entities.

    Insertion is merge-on-conflict: adding an entity whose key already exists
    folds the new observation into the existing node instead of creating a
    duplicate, which is what keeps the graph coherent when several collectors
    report the same fact.

    >>> graph = EntityGraph()
    >>> domain = graph.add_entity(Entity.create(EntityType.DOMAIN, "example.com"))
    >>> ip = graph.add_entity(Entity.create(EntityType.IP_ADDRESS, "93.184.216.34"))
    >>> _ = graph.add_relationship(
    ...     Relationship.create(domain, ip, EdgeType.RESOLVES_TO)
    ... )
    >>> len(graph)
    2
    """

    __slots__ = ("_entities", "_in", "_name", "_out", "_relationships")

    def __init__(self, name: str = "osint") -> None:
        self._name = name
        self._entities: dict[str, Entity] = {}
        # (source, type, target) -> Relationship
        self._relationships: dict[tuple[str, str, str], Relationship] = {}
        self._out: dict[str, set[tuple[str, str, str]]] = defaultdict(set)
        self._in: dict[str, set[tuple[str, str, str]]] = defaultdict(set)

    # -- basic access ------------------------------------------------------ #
    @property
    def name(self) -> str:
        return self._name

    def __len__(self) -> int:
        return len(self._entities)

    def __contains__(self, key: object) -> bool:
        return isinstance(key, str) and key in self._entities

    def __iter__(self) -> Iterator[Entity]:
        return iter(self._entities.values())

    @property
    def entities(self) -> list[Entity]:
        """All entities, ordered by key for deterministic output."""
        return [self._entities[k] for k in sorted(self._entities)]

    @property
    def relationships(self) -> list[Relationship]:
        """All relationships, ordered by key."""
        return [self._relationships[k] for k in sorted(self._relationships)]

    def get(self, key: str) -> Entity | None:
        """Return the entity with ``key``, or ``None``."""
        return self._entities.get(key)

    def require(self, key: str) -> Entity:
        """Return the entity with ``key``, raising ``KeyError`` if absent."""
        entity = self._entities.get(key)
        if entity is None:
            raise KeyError(f"No entity {key!r} in graph {self._name!r}")
        return entity

    # -- mutation ---------------------------------------------------------- #
    def add_entity(self, entity: Entity) -> Entity:
        """Add or merge ``entity``; returns the resident node.

        The returned object is the one now in the graph, which may be a
        pre-existing node the argument was folded into -- always use the
        return value rather than the argument afterwards.
        """
        existing = self._entities.get(entity.key)
        if existing is not None:
            return existing.merge(entity)
        self._entities[entity.key] = entity
        return entity

    def add_entities(self, entities: Iterable[Entity]) -> list[Entity]:
        """Add or merge several entities."""
        return [self.add_entity(e) for e in entities]

    def add_relationship(self, relationship: Relationship) -> Relationship:
        """Add or merge a relationship.

        Both endpoints must already exist; a dangling edge would make the graph
        unserializable and every traversal a special case.
        """
        for key in (relationship.source_key, relationship.target_key):
            if key not in self._entities:
                raise KeyError(
                    f"Cannot add relationship {relationship.key}: "
                    f"endpoint {key!r} is not in the graph"
                )

        existing = self._relationships.get(relationship.key)
        if existing is not None:
            return existing.merge(relationship)

        self._relationships[relationship.key] = relationship
        self._out[relationship.source_key].add(relationship.key)
        self._in[relationship.target_key].add(relationship.key)
        return relationship

    def connect(
        self,
        source: Entity,
        target: Entity,
        edge_type: EdgeType,
        **kwargs: Any,
    ) -> Relationship:
        """Add both endpoints and the edge between them in one call."""
        resident_source = self.add_entity(source)
        resident_target = self.add_entity(target)
        return self.add_relationship(
            Relationship.create(resident_source, resident_target, edge_type, **kwargs)
        )

    def remove_entity(self, key: str) -> bool:
        """Remove an entity and every edge touching it."""
        if key not in self._entities:
            return False
        for edge_key in list(self._out.pop(key, set())):
            self._drop_relationship(edge_key)
        for edge_key in list(self._in.pop(key, set())):
            self._drop_relationship(edge_key)
        del self._entities[key]
        return True

    def _drop_relationship(self, edge_key: tuple[str, str, str]) -> None:
        relationship = self._relationships.pop(edge_key, None)
        if relationship is None:
            return
        self._out[relationship.source_key].discard(edge_key)
        self._in[relationship.target_key].discard(edge_key)

    def merge_entities(self, primary_key: str, duplicate_key: str) -> Entity:
        """Collapse ``duplicate_key`` into ``primary_key``.

        Used by the correlator once entity resolution decides two nodes are the
        same thing. Edges on the duplicate are rewritten onto the primary;
        anything that would become a self-loop is dropped rather than kept as a
        meaningless edge.
        """
        if primary_key == duplicate_key:
            return self.require(primary_key)

        primary = self.require(primary_key)
        duplicate = self.require(duplicate_key)

        if primary.type is not duplicate.type:
            raise ValueError(
                f"Refusing to merge entities of different types: {primary.type} vs {duplicate.type}"
            )

        # Same type but different canonical value: keep the duplicate's value
        # as an alias so the original observation is not lost.
        if primary.canonical != duplicate.canonical:
            aliases = primary.attributes.setdefault("aliases", [])
            if isinstance(aliases, list) and duplicate.value not in aliases:
                aliases.append(duplicate.value)

        for name, value in duplicate.attributes.items():
            if name != "aliases":
                primary.attributes.setdefault(name, value)
        known = {(o.source, o.detail) for o in primary.observations}
        for observation in duplicate.observations:
            if (observation.source, observation.detail) not in known:
                primary.observations.append(observation)
        primary.first_seen = min(primary.first_seen, duplicate.first_seen)
        primary.last_seen = max(primary.last_seen, duplicate.last_seen)

        rewired: list[Relationship] = []
        for edge_key in list(self._out.get(duplicate_key, set())):
            relationship = self._relationships[edge_key]
            if relationship.target_key != primary_key:
                rewired.append(self._rebuild(relationship, primary_key, relationship.target_key))
        for edge_key in list(self._in.get(duplicate_key, set())):
            relationship = self._relationships[edge_key]
            if relationship.source_key != primary_key:
                rewired.append(self._rebuild(relationship, relationship.source_key, primary_key))

        self.remove_entity(duplicate_key)
        for relationship in rewired:
            self.add_relationship(relationship)

        logger.debug("Merged entity %s into %s", duplicate_key, primary_key)
        return primary

    @staticmethod
    def _rebuild(relationship: Relationship, source_key: str, target_key: str) -> Relationship:
        """Copy a relationship onto new endpoints, preserving provenance."""
        return Relationship(
            source_key=source_key,
            target_key=target_key,
            type=relationship.type,
            confidence=relationship.confidence,
            attributes=dict(relationship.attributes),
            observations=list(relationship.observations),
            first_seen=relationship.first_seen,
            last_seen=relationship.last_seen,
        )

    # -- traversal --------------------------------------------------------- #
    def out_edges(self, key: str) -> list[Relationship]:
        """Relationships where ``key`` is the source."""
        return [self._relationships[k] for k in sorted(self._out.get(key, set()))]

    def in_edges(self, key: str) -> list[Relationship]:
        """Relationships where ``key`` is the target."""
        return [self._relationships[k] for k in sorted(self._in.get(key, set()))]

    def edges(self, key: str) -> list[Relationship]:
        """All relationships touching ``key``, in either direction."""
        combined = self._out.get(key, set()) | self._in.get(key, set())
        return [self._relationships[k] for k in sorted(combined)]

    def neighbors(
        self, key: str, *, edge_type: EdgeType | None = None, directed: bool = True
    ) -> list[Entity]:
        """Entities adjacent to ``key``.

        With ``directed=False`` the edge direction is ignored, which is usually
        what an analyst means by "what is this connected to".
        """
        edges = self.out_edges(key) if directed else self.edges(key)
        neighbor_keys: list[str] = []
        for relationship in edges:
            if edge_type is not None and relationship.type is not edge_type:
                continue
            other = (
                relationship.target_key
                if relationship.source_key == key
                else relationship.source_key
            )
            if other != key and other not in neighbor_keys:
                neighbor_keys.append(other)
        return [self._entities[k] for k in neighbor_keys if k in self._entities]

    def degree(self, key: str) -> int:
        """Total number of edges touching ``key``."""
        return len(self._out.get(key, set())) + len(self._in.get(key, set()))

    def by_type(self, entity_type: EntityType) -> list[Entity]:
        """All entities of one type, ordered by key."""
        return [e for e in self.entities if e.type is entity_type]

    def find(
        self,
        *,
        entity_type: EntityType | None = None,
        min_confidence: float = 0.0,
        source: str | None = None,
    ) -> list[Entity]:
        """Entities matching every supplied criterion."""
        results = self.entities
        if entity_type is not None:
            results = [e for e in results if e.type is entity_type]
        if min_confidence > 0.0:
            results = [e for e in results if e.confidence >= min_confidence]
        if source is not None:
            results = [e for e in results if source in e.sources]
        return results

    def shortest_path(self, start: str, end: str) -> list[Entity]:
        """Fewest-hops path between two entities, ignoring edge direction.

        Returns ``[]`` when no path exists. Breadth-first, so the result is a
        genuine minimum-hop path rather than merely a path.
        """
        if start not in self._entities or end not in self._entities:
            return []
        if start == end:
            return [self._entities[start]]

        previous: dict[str, str | None] = {start: None}
        queue: deque[str] = deque([start])

        while queue:
            current = queue.popleft()
            for neighbor in self.neighbors(current, directed=False):
                if neighbor.key in previous:
                    continue
                previous[neighbor.key] = current
                if neighbor.key == end:
                    path: list[str] = []
                    cursor: str | None = end
                    while cursor is not None:
                        path.append(cursor)
                        cursor = previous[cursor]
                    return [self._entities[k] for k in reversed(path)]
                queue.append(neighbor.key)

        return []

    def components(self) -> list[list[Entity]]:
        """Connected components, ignoring edge direction.

        Ordered largest-first: the biggest cluster is usually the target's real
        infrastructure, and the singletons are unlinked observations.
        """
        seen: set[str] = set()
        found: list[list[Entity]] = []

        for key in sorted(self._entities):
            if key in seen:
                continue
            cluster: list[str] = []
            queue: deque[str] = deque([key])
            seen.add(key)
            while queue:
                current = queue.popleft()
                cluster.append(current)
                for neighbor in self.neighbors(current, directed=False):
                    if neighbor.key not in seen:
                        seen.add(neighbor.key)
                        queue.append(neighbor.key)
            found.append([self._entities[k] for k in sorted(cluster)])

        found.sort(key=lambda c: (-len(c), c[0].key))
        return found

    def stats(self) -> GraphStats:
        """Summarize the graph's size and composition."""
        by_entity: dict[str, int] = defaultdict(int)
        for entity in self._entities.values():
            by_entity[entity.type.value] += 1
        by_edge: dict[str, int] = defaultdict(int)
        for relationship in self._relationships.values():
            by_edge[relationship.type.value] += 1
        isolated = sum(1 for k in self._entities if self.degree(k) == 0)
        return GraphStats(
            entities=len(self._entities),
            relationships=len(self._relationships),
            entities_by_type=dict(by_entity),
            relationships_by_type=dict(by_edge),
            isolated_entities=isolated,
        )

    def merge_graph(self, other: EntityGraph) -> EntityGraph:
        """Fold another graph into this one."""
        for entity in other.entities:
            self.add_entity(entity)
        for relationship in other.relationships:
            self.add_relationship(relationship)
        return self

    # -- exports ----------------------------------------------------------- #
    def to_networkx(self) -> Any:
        """Export as a ``networkx.MultiDiGraph``.

        Node ids are entity keys; the :class:`Entity` is attached as the
        ``entity`` attribute alongside flattened fields for algorithms that
        expect scalars. Raises :class:`NetworkXNotInstalledError` if the
        optional dependency is absent.
        """
        if _nx is None:
            raise NetworkXNotInstalledError

        graph = _nx.MultiDiGraph(name=self._name)
        for entity in self.entities:
            graph.add_node(
                entity.key,
                entity=entity,
                type=entity.type.value,
                value=entity.value,
                canonical=entity.canonical,
                confidence=entity.confidence,
                sources=entity.sources,
                **{f"attr_{k}": v for k, v in entity.attributes.items()},
            )
        for relationship in self.relationships:
            graph.add_edge(
                relationship.source_key,
                relationship.target_key,
                key=relationship.type.value,
                relationship=relationship,
                type=relationship.type.value,
                confidence=relationship.confidence,
                weight=relationship.confidence,
                sources=relationship.sources,
            )
        return graph

    def to_cypher(self, *, batch_label: str = "OsintEntity") -> list[dict[str, Any]]:
        """Export as parameterized Neo4j statements.

        Returns ``{"query": ..., "parameters": {...}}`` dicts ready for
        ``session.run(**statement)``. Every statement is a ``MERGE``, so
        re-ingesting the same graph updates properties rather than duplicating
        nodes. Values are passed as parameters, never interpolated into the
        query string.

        Labels are derived from entity types and relationship types are
        upper-cased per Neo4j convention; both come from closed enums, so no
        collector-supplied text ever reaches the query text.
        """
        statements: list[dict[str, Any]] = []

        for entity in self.entities:
            label = _pascal_case(entity.type.value)
            statements.append(
                {
                    "query": (
                        f"MERGE (n:{batch_label}:{label} {{key: $key}}) "
                        "SET n.value = $value, "
                        "    n.canonical = $canonical, "
                        "    n.confidence = $confidence, "
                        "    n.sources = $sources, "
                        "    n.first_seen = $first_seen, "
                        "    n.last_seen = $last_seen, "
                        "    n.attributes = $attributes"
                    ),
                    "parameters": {
                        "key": entity.key,
                        "value": entity.value,
                        "canonical": entity.canonical,
                        "confidence": round(entity.confidence, 4),
                        "sources": entity.sources,
                        "first_seen": entity.first_seen.isoformat(),
                        "last_seen": entity.last_seen.isoformat(),
                        # Neo4j properties must be primitives, so nested
                        # attribute maps are stored as a JSON string.
                        "attributes": json.dumps(entity.attributes, default=str, sort_keys=True),
                    },
                }
            )

        for relationship in self.relationships:
            rel_type = relationship.type.value.upper()
            statements.append(
                {
                    "query": (
                        f"MATCH (a:{batch_label} {{key: $source}}) "
                        f"MATCH (b:{batch_label} {{key: $target}}) "
                        f"MERGE (a)-[r:{rel_type}]->(b) "
                        "SET r.confidence = $confidence, "
                        "    r.sources = $sources, "
                        "    r.first_seen = $first_seen, "
                        "    r.last_seen = $last_seen, "
                        "    r.attributes = $attributes"
                    ),
                    "parameters": {
                        "source": relationship.source_key,
                        "target": relationship.target_key,
                        "confidence": round(relationship.confidence, 4),
                        "sources": relationship.sources,
                        "first_seen": relationship.first_seen.isoformat(),
                        "last_seen": relationship.last_seen.isoformat(),
                        "attributes": json.dumps(
                            relationship.attributes, default=str, sort_keys=True
                        ),
                    },
                }
            )

        return statements

    def to_dict(self) -> dict[str, Any]:
        """Export the whole graph as a JSON-serializable mapping."""
        return {
            "schema_version": JSON_SCHEMA_VERSION,
            "name": self._name,
            "entities": [e.to_dict() for e in self.entities],
            "relationships": [r.to_dict() for r in self.relationships],
            "stats": self.stats().to_dict(),
        }

    def to_json(self, *, indent: int | None = 2) -> str:
        """Serialize the graph to a JSON string."""
        return json.dumps(self.to_dict(), indent=indent, default=str, sort_keys=False)

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> EntityGraph:
        """Rebuild a graph from :meth:`to_dict` output."""
        version = payload.get("schema_version")
        if version != JSON_SCHEMA_VERSION:
            raise ValueError(
                f"Unsupported graph schema version {version!r}; expected {JSON_SCHEMA_VERSION!r}"
            )

        graph = cls(name=str(payload.get("name", "osint")))

        for raw in payload.get("entities", []):
            graph.add_entity(_entity_from_dict(raw))
        for raw in payload.get("relationships", []):
            graph.add_relationship(_relationship_from_dict(raw))
        return graph

    @classmethod
    def from_json(cls, text: str) -> EntityGraph:
        """Rebuild a graph from a JSON string."""
        parsed = json.loads(text)
        if not isinstance(parsed, dict):
            raise ValueError("Graph JSON must decode to an object")
        return cls.from_dict(parsed)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"<EntityGraph {self._name!r} entities={len(self._entities)} "
            f"relationships={len(self._relationships)}>"
        )


def _pascal_case(value: str) -> str:
    """``ip_address`` -> ``IpAddress`` for Neo4j labels."""
    return "".join(part.capitalize() for part in value.split("_") if part)


def _observations_from(raw: Sequence[Mapping[str, Any]]) -> list[Observation]:
    return [
        Observation(
            source=str(item.get("source", "")),
            collected_at=_parse_dt(item.get("collected_at")),
            detail=str(item.get("detail", "")),
            run_id=str(item.get("run_id", "")),
        )
        for item in raw
    ]


def _parse_dt(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str) and value:
        try:
            return datetime.fromisoformat(value)
        except ValueError:  # pragma: no cover - defensive
            pass
    from security_assistant.core.types import utcnow

    return utcnow()


def _entity_from_dict(raw: Mapping[str, Any]) -> Entity:
    return Entity(
        type=EntityType(raw["type"]),
        value=str(raw["value"]),
        canonical=str(raw["canonical"]),
        attributes=dict(raw.get("attributes", {})),
        confidence=float(raw.get("confidence", 1.0)),
        observations=_observations_from(raw.get("observations", [])),
        first_seen=_parse_dt(raw.get("first_seen")),
        last_seen=_parse_dt(raw.get("last_seen")),
    )


def _relationship_from_dict(raw: Mapping[str, Any]) -> Relationship:
    return Relationship(
        source_key=str(raw["source"]),
        target_key=str(raw["target"]),
        type=EdgeType(raw["type"]),
        confidence=float(raw.get("confidence", 1.0)),
        attributes=dict(raw.get("attributes", {})),
        observations=_observations_from(raw.get("observations", [])),
        first_seen=_parse_dt(raw.get("first_seen")),
        last_seen=_parse_dt(raw.get("last_seen")),
    )
