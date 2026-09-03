"""Shared dashboard state and the telemetry broadcast hub.

Holds what the dashboard displays -- the entity graph, discovered assets, URL
assessments, tunnel and health telemetry, and a bounded event log -- and
pushes updates to connected WebSocket clients.

Three constraints shape it.

**Everything is bounded.** Scans, events and log lines are held in
``deque(maxlen=...)``. A dashboard left open for a week on a busy engagement
must not become the reason the daemon runs out of memory, and an unbounded
in-memory log is the classic way that happens.

**A slow client cannot stall the server.** Broadcast puts onto per-client
queues with a fixed size; a client that stops draining has messages dropped
rather than applying backpressure to the producer. Telemetry is a live view,
so a stalled browser tab losing frames is correct behaviour -- blocking the
daemon's health loop behind it would not be.

**Nothing here is authoritative.** This is a projection for display, rebuilt
from module output. The graph, the tunnel state and the audit trail live in
their own modules; a bug in the dashboard can make it show the wrong thing,
but cannot corrupt what the assistant knows.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections import deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from security_assistant.core.types import utcnow
from security_assistant.osint.graph import EntityGraph

logger = logging.getLogger(__name__)

__all__ = [
    "MAX_EVENTS",
    "MAX_SCANS",
    "Broadcaster",
    "DashboardState",
    "EventRecord",
]

MAX_EVENTS = 500
MAX_SCANS = 100
MAX_ASSETS = 500
MAX_LOG_LINES = 2000

#: Per-client outbound queue depth. Small on purpose: a client this far behind
#: is not going to catch up, and holding more only delays noticing.
CLIENT_QUEUE_SIZE = 64


@dataclass(frozen=True, slots=True)
class EventRecord:
    """One thing that happened, for the dashboard's activity feed."""

    kind: str
    payload: Mapping[str, Any]
    at: Any = field(default_factory=utcnow)

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "payload": dict(self.payload), "at": self.at.isoformat()}


class Broadcaster:
    """Fan-out of telemetry frames to connected clients."""

    def __init__(self, queue_size: int = CLIENT_QUEUE_SIZE) -> None:
        self._clients: set[asyncio.Queue[dict[str, Any]]] = set()
        self._queue_size = queue_size
        self._dropped = 0

    @property
    def client_count(self) -> int:
        return len(self._clients)

    @property
    def dropped_frames(self) -> int:
        return self._dropped

    def subscribe(self) -> asyncio.Queue[dict[str, Any]]:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=self._queue_size)
        self._clients.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[dict[str, Any]]) -> None:
        self._clients.discard(queue)

    def publish(self, kind: str, payload: Mapping[str, Any]) -> int:
        """Push a frame to every client. Returns how many received it.

        Never awaits and never blocks: a full queue means that client is not
        keeping up, and its frame is dropped. Telemetry is a live view, so a
        stalled tab should lose frames rather than slow the producer.
        """
        frame = {"kind": kind, "payload": dict(payload), "at": utcnow().isoformat()}
        delivered = 0
        for queue in list(self._clients):
            try:
                queue.put_nowait(frame)
                delivered += 1
            except asyncio.QueueFull:
                self._dropped += 1
        return delivered

    def close(self) -> None:
        self._clients.clear()


class DashboardState:
    """What the dashboard shows.

    Deliberately a projection: modules own the truth, this owns the view.
    """

    def __init__(self, broadcaster: Broadcaster | None = None) -> None:
        self.graph = EntityGraph("dashboard")
        self.broadcaster = broadcaster or Broadcaster()

        self.assets: deque[dict[str, Any]] = deque(maxlen=MAX_ASSETS)
        self.scans: deque[dict[str, Any]] = deque(maxlen=MAX_SCANS)
        self.events: deque[EventRecord] = deque(maxlen=MAX_EVENTS)
        self.console_log: deque[str] = deque(maxlen=MAX_LOG_LINES)

        self.tunnel: dict[str, Any] = {}
        self.health: dict[str, Any] = {}
        self.leaks: dict[str, Any] = {}
        self.killswitch: dict[str, Any] = {"engaged": False}
        self.started_at = utcnow()

    # -- recording -------------------------------------------------------- #
    def record_event(self, kind: str, payload: Mapping[str, Any]) -> EventRecord:
        record = EventRecord(kind=kind, payload=dict(payload))
        self.events.append(record)
        self.broadcaster.publish(kind, record.payload)
        return record

    def log(self, line: str) -> None:
        """Append a console line and stream it to clients."""
        text = line.rstrip()
        if not text:
            return
        self.console_log.append(text)
        self.broadcaster.publish("console.line", {"line": text})

    def ingest_graph_payloads(self, payloads: Iterable[Any]) -> dict[str, Any]:
        """Fold collector output into the dashboard graph."""
        from security_assistant.osint.correlator import build_graph_from_payloads

        incoming = build_graph_from_payloads(payloads, name="incoming")
        self.graph.merge_graph(incoming)

        stats = self.graph.stats().to_dict()
        self.broadcaster.publish("graph.updated", stats)
        return stats

    def record_assets(self, devices: Iterable[Mapping[str, Any]]) -> int:
        """Record discovered IoT assets, replacing any with the same address."""
        added = 0
        for device in devices:
            if not isinstance(device, Mapping):
                continue
            address = str(device.get("address", "")).strip()
            if not address:
                continue
            existing = [a for a in self.assets if a.get("address") == address]
            for stale in existing:
                self.assets.remove(stale)
            self.assets.append(dict(device))
            added += 1
        if added:
            self.broadcaster.publish("assets.updated", {"count": len(self.assets)})
        return added

    def record_scan(self, assessment: Mapping[str, Any]) -> dict[str, Any]:
        """Record a URL assessment."""
        entry = dict(assessment)
        entry.setdefault("at", utcnow().isoformat())
        self.scans.appendleft(entry)
        self.broadcaster.publish("scan.completed", entry)
        return entry

    def update_tunnel(self, payload: Mapping[str, Any]) -> None:
        self.tunnel = dict(payload)
        self.broadcaster.publish("tunnel.updated", self.tunnel)

    def update_health(self, payload: Mapping[str, Any]) -> None:
        self.health = dict(payload)
        self.broadcaster.publish("health.updated", self.health)

    def update_leaks(self, payload: Mapping[str, Any]) -> None:
        self.leaks = dict(payload)
        self.broadcaster.publish("leaks.updated", self.leaks)

    def update_killswitch(self, payload: Mapping[str, Any]) -> None:
        self.killswitch = dict(payload)
        self.broadcaster.publish("killswitch.updated", self.killswitch)

    # -- reading ---------------------------------------------------------- #
    def graph_payload(self, limit: int = 500) -> dict[str, Any]:
        """Graph shaped for Cytoscape, capped so a huge graph cannot wedge
        the browser."""
        entities = self.graph.entities[:limit]
        keys = {e.key for e in entities}
        nodes = [
            {
                "data": {
                    "id": e.key,
                    "label": e.value[:48],
                    "type": e.type.value,
                    "confidence": round(e.confidence, 3),
                    "sources": e.sources,
                }
            }
            for e in entities
        ]
        edges = [
            {
                "data": {
                    "id": f"{r.source_key}|{r.type.value}|{r.target_key}",
                    "source": r.source_key,
                    "target": r.target_key,
                    "label": r.type.value,
                    "confidence": round(r.confidence, 3),
                }
            }
            for r in self.graph.relationships
            if r.source_key in keys and r.target_key in keys
        ]
        return {
            "nodes": nodes,
            "edges": edges,
            "stats": self.graph.stats().to_dict(),
            "truncated": len(self.graph) > limit,
        }

    def entity_detail(self, key: str) -> dict[str, Any] | None:
        """Everything known about one entity, for the inspector panel."""
        entity = self.graph.get(key)
        if entity is None:
            return None
        return {
            "entity": entity.to_dict(),
            "neighbors": [n.to_dict() for n in self.graph.neighbors(key, directed=False)],
            "edges": [r.to_dict() for r in self.graph.edges(key)],
            "degree": self.graph.degree(key),
        }

    def snapshot(self) -> dict[str, Any]:
        """The full current view, sent on WebSocket connect."""
        return {
            "graph": self.graph.stats().to_dict(),
            "assets": list(self.assets)[-100:],
            "scans": list(self.scans)[:25],
            "tunnel": dict(self.tunnel),
            "health": dict(self.health),
            "leaks": dict(self.leaks),
            "killswitch": dict(self.killswitch),
            "events": [e.to_dict() for e in list(self.events)[-50:]],
            "clients": self.broadcaster.client_count,
            "dropped_frames": self.broadcaster.dropped_frames,
            "started_at": self.started_at.isoformat(),
        }

    def clear(self) -> None:
        """Reset the projection. Does not touch any module's own state."""
        self.graph = EntityGraph("dashboard")
        self.assets.clear()
        self.scans.clear()
        self.events.clear()
        self.console_log.clear()
        self.broadcaster.publish("state.cleared", {})


async def drain(
    queue: asyncio.Queue[dict[str, Any]], timeout: float = 1.0
) -> dict[str, Any] | None:
    """Await one frame, or return ``None`` on timeout.

    Used by the WebSocket loop so it can send periodic keepalives instead of
    blocking forever on an idle connection.
    """
    with contextlib.suppress(TimeoutError, asyncio.TimeoutError):
        return await asyncio.wait_for(queue.get(), timeout=timeout)
    return None
