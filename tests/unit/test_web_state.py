"""Tests for dashboard state and the telemetry broadcaster.

The property that matters: a browser tab that stops reading must lose frames
rather than apply backpressure to the daemon's health loop.
"""

from __future__ import annotations

import asyncio

from security_assistant.osint.models import EdgeType, Entity, EntityType, Relationship
from security_assistant.web.state import (
    MAX_EVENTS,
    MAX_SCANS,
    Broadcaster,
    DashboardState,
    drain,
)
from tests.unit.conftest import run


def graph_payload() -> dict[str, object]:
    """Collector-shaped output for two linked entities."""
    domain = Entity.create(EntityType.DOMAIN, "example.com", source="osint.dns")
    address = Entity.create(EntityType.IP_ADDRESS, "192.0.2.10", source="osint.dns")
    edge = Relationship.create(domain, address, EdgeType.RESOLVES_TO)
    return {
        "entities": [domain.to_dict(), address.to_dict()],
        "relationships": [edge.to_dict()],
    }


class TestBroadcaster:
    def test_delivers_to_every_subscriber(self) -> None:
        async def scenario() -> tuple[int, dict[str, object], dict[str, object]]:
            b = Broadcaster()
            q1, q2 = b.subscribe(), b.subscribe()
            delivered = b.publish("test", {"n": 1})
            return delivered, await q1.get(), await q2.get()

        delivered, first, second = run(scenario())
        assert delivered == 2
        assert first["kind"] == "test"
        assert second == first, "both subscribers see the same frame"

    def test_a_stalled_client_loses_frames_instead_of_blocking(self) -> None:
        """Telemetry is a live view. Blocking the producer behind a dead tab
        would let a browser stall the daemon's health loop."""

        async def scenario() -> tuple[int, int]:
            b = Broadcaster(queue_size=2)
            b.subscribe()  # never drained
            for i in range(10):
                b.publish("frame", {"i": i})
            return b.dropped_frames, b.client_count

        dropped, clients = run(scenario())
        assert dropped == 8
        assert clients == 1

    def test_unsubscribe_stops_delivery(self) -> None:
        async def scenario() -> int:
            b = Broadcaster()
            q = b.subscribe()
            b.unsubscribe(q)
            return b.publish("test", {})

        assert run(scenario()) == 0

    def test_publish_with_no_clients_is_harmless(self) -> None:
        assert Broadcaster().publish("test", {}) == 0

    def test_drain_returns_none_on_idle(self) -> None:
        """The socket loop uses this to send keepalives instead of blocking
        forever on a quiet connection."""

        async def scenario() -> object:
            return await drain(asyncio.Queue(), timeout=0.01)

        assert run(scenario()) is None


class TestDashboardState:
    def test_ingests_collector_payloads_into_the_graph(self) -> None:
        state = DashboardState()
        stats = state.ingest_graph_payloads([graph_payload()])

        assert stats["entities"] == 2
        assert stats["relationships"] == 1
        assert "domain:example.com" in state.graph

    def test_repeated_ingestion_merges_rather_than_duplicates(self) -> None:
        state = DashboardState()
        state.ingest_graph_payloads([graph_payload()])
        stats = state.ingest_graph_payloads([graph_payload()])
        assert stats["entities"] == 2

    def test_graph_payload_is_cytoscape_shaped(self) -> None:
        state = DashboardState()
        state.ingest_graph_payloads([graph_payload()])
        payload = state.graph_payload()

        assert all("data" in n for n in payload["nodes"])
        assert all({"id", "source", "target"} <= set(e["data"]) for e in payload["edges"])

    def test_graph_payload_is_capped_and_says_so(self) -> None:
        state = DashboardState()
        for i in range(30):
            state.graph.add_entity(Entity.create(EntityType.DOMAIN, f"h{i}.example"))
        payload = state.graph_payload(limit=10)

        assert len(payload["nodes"]) == 10
        assert payload["truncated"] is True

    def test_edges_to_trimmed_nodes_are_dropped(self) -> None:
        """A dangling edge would break the renderer."""
        state = DashboardState()
        state.ingest_graph_payloads([graph_payload()])
        payload = state.graph_payload(limit=1)

        node_ids = {n["data"]["id"] for n in payload["nodes"]}
        for edge in payload["edges"]:
            assert edge["data"]["source"] in node_ids
            assert edge["data"]["target"] in node_ids

    def test_entity_detail(self) -> None:
        state = DashboardState()
        state.ingest_graph_payloads([graph_payload()])
        detail = state.entity_detail("domain:example.com")

        assert detail is not None
        assert detail["degree"] == 1
        assert detail["neighbors"]

    def test_entity_detail_for_unknown_key(self) -> None:
        assert DashboardState().entity_detail("domain:nope.test") is None

    def test_assets_are_replaced_by_address_not_appended(self) -> None:
        state = DashboardState()
        state.record_assets([{"address": "192.0.2.10", "device_class": "camera"}])
        state.record_assets([{"address": "192.0.2.10", "device_class": "router"}])

        assert len(state.assets) == 1
        assert state.assets[0]["device_class"] == "router"

    def test_assets_without_an_address_are_ignored(self) -> None:
        state = DashboardState()
        assert state.record_assets([{"device_class": "camera"}, "junk"]) == 0  # type: ignore[list-item]

    def test_scans_are_newest_first_and_bounded(self) -> None:
        state = DashboardState()
        for i in range(MAX_SCANS + 20):
            state.record_scan({"url": f"https://x{i}.test/"})

        assert len(state.scans) == MAX_SCANS
        assert state.scans[0]["url"].endswith(f"{MAX_SCANS + 19}.test/")

    def test_events_are_bounded(self) -> None:
        state = DashboardState()
        for i in range(MAX_EVENTS + 50):
            state.record_event("tick", {"i": i})
        assert len(state.events) == MAX_EVENTS

    def test_console_log_is_bounded_and_skips_blanks(self) -> None:
        state = DashboardState()
        state.log("")
        state.log("   ")
        state.log("real line")
        assert list(state.console_log) == ["real line"]

    def test_snapshot_covers_every_panel(self) -> None:
        state = DashboardState()
        state.update_tunnel({"state": "up"})
        state.update_health({"overall": "ok"})
        state.update_leaks({"verdict": "protected"})
        snapshot = state.snapshot()

        for key in ("graph", "assets", "scans", "tunnel", "health", "leaks", "events"):
            assert key in snapshot
        assert snapshot["tunnel"]["state"] == "up"

    def test_updates_are_broadcast(self) -> None:
        async def scenario() -> dict[str, object]:
            state = DashboardState()
            queue = state.broadcaster.subscribe()
            state.update_tunnel({"state": "degraded"})
            return await queue.get()

        frame = run(scenario())
        assert frame["kind"] == "tunnel.updated"

    def test_clear_resets_the_projection(self) -> None:
        state = DashboardState()
        state.ingest_graph_payloads([graph_payload()])
        state.record_scan({"url": "https://x.test/"})
        state.clear()

        assert len(state.graph) == 0
        assert not state.scans
