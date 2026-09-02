"""Tests for the vector-backed long-term memory."""

from __future__ import annotations

import pytest

from security_assistant.core import (
    HashingEmbeddingProvider,
    InMemoryVectorStore,
    LongTermMemory,
    MemoryRecord,
    cosine_similarity,
)
from security_assistant.core.exceptions import MemoryBackendError
from tests.unit.conftest import run


class TestCosineSimilarity:
    def test_identical_vectors(self) -> None:
        assert cosine_similarity([1.0, 0.0], [1.0, 0.0]) == pytest.approx(1.0)

    def test_orthogonal_vectors(self) -> None:
        assert cosine_similarity([1.0, 0.0], [0.0, 1.0]) == pytest.approx(0.0)

    def test_zero_vector_is_safe(self) -> None:
        assert cosine_similarity([0.0, 0.0], [1.0, 1.0]) == 0.0

    def test_length_mismatch_rejected(self) -> None:
        with pytest.raises(ValueError, match="length mismatch"):
            cosine_similarity([1.0], [1.0, 2.0])


class TestHashingEmbeddingProvider:
    def test_is_deterministic(self) -> None:
        provider = HashingEmbeddingProvider(dimension=64)
        first, second = run(provider.embed(["example.com nginx", "example.com nginx"]))
        assert first == second

    def test_dimension_respected(self) -> None:
        provider = HashingEmbeddingProvider(dimension=32)
        assert len(run(provider.embed(["hello"]))[0]) == 32

    def test_related_text_scores_above_unrelated(self) -> None:
        provider = HashingEmbeddingProvider()
        vectors = run(
            provider.embed(
                [
                    "example.com runs nginx on port 443",
                    "example.com nginx tls",
                    "sourdough bread baking schedule",
                ]
            )
        )
        related = cosine_similarity(vectors[0], vectors[1])
        unrelated = cosine_similarity(vectors[0], vectors[2])
        assert related > unrelated

    def test_empty_text_yields_zero_vector(self) -> None:
        provider = HashingEmbeddingProvider(dimension=16)
        assert run(provider.embed([""]))[0] == [0.0] * 16

    def test_rejects_tiny_dimension(self) -> None:
        with pytest.raises(ValueError):
            HashingEmbeddingProvider(dimension=4)


class TestInMemoryVectorStore:
    def test_requires_embedding(self) -> None:
        store = InMemoryVectorStore()
        with pytest.raises(MemoryBackendError, match="no embedding"):
            run(store.add([MemoryRecord(text="no vector")]))

    def test_add_get_delete_count(self) -> None:
        store = InMemoryVectorStore()

        async def scenario() -> tuple:
            record = MemoryRecord(text="x", embedding=[1.0, 0.0])
            await store.add([record])
            fetched = await store.get(record.id)
            count = await store.count()
            deleted = await store.delete(record.id)
            missing = await store.delete(record.id)
            return fetched, count, deleted, missing

        fetched, count, deleted, missing = run(scenario())
        assert fetched is not None and count == 1
        assert deleted is True and missing is False

    def test_query_respects_k_and_orders_by_score(self) -> None:
        store = InMemoryVectorStore()

        async def scenario() -> list[MemoryRecord]:
            await store.add(
                [
                    MemoryRecord(text="near", embedding=[1.0, 0.0]),
                    MemoryRecord(text="far", embedding=[0.0, 1.0]),
                ]
            )
            return await store.query([1.0, 0.0], k=1)

        hits = run(scenario())
        assert len(hits) == 1
        assert hits[0].text == "near"

    def test_metadata_filter(self) -> None:
        store = InMemoryVectorStore()

        async def scenario() -> list[MemoryRecord]:
            await store.add(
                [
                    MemoryRecord(text="a", embedding=[1.0, 0.0], metadata={"kind": "host"}),
                    MemoryRecord(text="b", embedding=[1.0, 0.0], metadata={"kind": "note"}),
                ]
            )
            return await store.query([1.0, 0.0], k=5, where={"kind": "host"})

        hits = run(scenario())
        assert [h.text for h in hits] == ["a"]

    def test_dimension_mismatch_is_skipped_not_fatal(self) -> None:
        store = InMemoryVectorStore()

        async def scenario() -> list[MemoryRecord]:
            await store.add(
                [
                    MemoryRecord(text="ok", embedding=[1.0, 0.0]),
                    MemoryRecord(text="stale", embedding=[1.0, 0.0, 0.0]),
                ]
            )
            return await store.query([1.0, 0.0], k=5)

        hits = run(scenario())
        assert [h.text for h in hits] == ["ok"]

    def test_zero_k_returns_nothing(self) -> None:
        assert run(InMemoryVectorStore().query([1.0], k=0)) == []


class TestLongTermMemory:
    def test_remember_and_recall(self) -> None:
        memory = LongTermMemory()

        async def scenario() -> list[MemoryRecord]:
            await memory.remember(
                "example.com runs nginx 1.24 on port 443", {"target": "example.com"}
            )
            await memory.remember("Unrelated note about sourdough bread")
            return await memory.recall("what web server does example.com run", k=3)

        hits = run(scenario())
        assert hits, "expected at least one recalled memory"
        assert "nginx" in hits[0].text
        assert all("sourdough" not in h.text for h in hits)

    def test_namespaces_are_isolated(self) -> None:
        memory = LongTermMemory()

        async def scenario() -> tuple:
            await memory.remember("default namespace note about widgets")
            other = memory.scoped("engagement-2")
            await other.remember("second namespace note about widgets")
            return (
                await memory.size(),
                await other.size(),
                await other.recall("widgets", k=5),
            )

        default_size, other_size, hits = run(scenario())
        assert default_size == 1
        assert other_size == 1
        assert all(h.namespace == "engagement-2" for h in hits)

    def test_remember_many(self) -> None:
        memory = LongTermMemory()

        async def scenario() -> int:
            await memory.remember_many(
                [("first finding", {"n": 1}), ("second finding", {"n": 2})]
            )
            return await memory.size()

        assert run(scenario()) == 2

    def test_forget(self) -> None:
        memory = LongTermMemory()

        async def scenario() -> tuple[bool, bool]:
            record_id = await memory.remember("temporary")
            return await memory.forget(record_id), await memory.forget(record_id)

        assert run(scenario()) == (True, False)

    def test_empty_text_rejected(self) -> None:
        with pytest.raises(ValueError, match="empty text"):
            run(LongTermMemory().remember("   "))

    def test_empty_query_returns_nothing(self) -> None:
        assert run(LongTermMemory().recall("")) == []

    def test_min_score_filters_weak_matches(self) -> None:
        memory = LongTermMemory()

        async def scenario() -> list[MemoryRecord]:
            await memory.remember("completely unrelated content here")
            return await memory.recall("zzzz nonsense query", k=5, min_score=0.99)

        assert run(scenario()) == []

    def test_record_serialization_omits_embedding(self) -> None:
        record = MemoryRecord(text="t", embedding=[1.0], score=0.5)
        payload = record.to_dict()
        assert "embedding" not in payload
        assert payload["score"] == 0.5
