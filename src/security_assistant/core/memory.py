"""Long-term memory backed by a vector store.

The agent needs to recall what it learned about a target across runs -- which
hosts were already enumerated, which findings were triaged, what the operator
decided last time. This module provides that as a small, swappable interface.

Two concerns are separated so either can be replaced independently:

* :class:`EmbeddingProvider` turns text into vectors.
* :class:`VectorStore` persists vectors and answers similarity queries.

The default implementations (:class:`HashingEmbeddingProvider` and
:class:`InMemoryVectorStore`) need no external service, so the agent is fully
functional out of the box and in tests. Swapping in a hosted embedding model
and a real vector database (Chroma, Qdrant, pgvector) is an implementation of
these two protocols and nothing else.

NumPy is used automatically when present for the similarity search and falls
back to pure Python otherwise, so the core keeps its zero-dependency promise.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol, runtime_checkable

from security_assistant.core.exceptions import MemoryBackendError
from security_assistant.core.types import new_id, utcnow

logger = logging.getLogger(__name__)

# NumPy accelerates the similarity search when available, but the pure-Python
# path below is equivalent, so the core keeps its zero-dependency promise.
_np: Any
try:  # pragma: no cover - exercised implicitly by whichever path is available
    import numpy

    _np = numpy
    _HAS_NUMPY = True
except ImportError:  # pragma: no cover
    _np = None
    _HAS_NUMPY = False

__all__ = [
    "EmbeddingProvider",
    "HashingEmbeddingProvider",
    "InMemoryVectorStore",
    "LongTermMemory",
    "MemoryRecord",
    "VectorStore",
    "cosine_similarity",
]

_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9._:-]*")


def _tokenize(text: str) -> list[str]:
    """Lowercase word/host-ish tokenizer.

    Keeps dots, colons and hyphens inside tokens so ``api.example.com`` and
    ``CVE-2024-1234`` survive as single meaningful units rather than being
    shredded into noise.
    """
    return _TOKEN_RE.findall(text.lower())


def cosine_similarity(a: Sequence[float], b: Sequence[float]) -> float:
    """Cosine similarity of two equal-length vectors, in ``[-1.0, 1.0]``."""
    if len(a) != len(b):
        raise ValueError(f"Vector length mismatch: {len(a)} != {len(b)}")
    if _HAS_NUMPY:
        va, vb = _np.asarray(a, dtype=float), _np.asarray(b, dtype=float)
        denom = float(_np.linalg.norm(va) * _np.linalg.norm(vb))
        return float(va.dot(vb) / denom) if denom else 0.0

    dot = sum(x * y for x, y in zip(a, b, strict=True))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(y * y for y in b))
    denom = norm_a * norm_b
    return dot / denom if denom else 0.0


@dataclass(slots=True)
class MemoryRecord:
    """One durable memory."""

    text: str
    id: str = field(default_factory=lambda: new_id("mem"))
    namespace: str = "default"
    metadata: dict[str, Any] = field(default_factory=dict)
    embedding: list[float] = field(default_factory=list)
    created_at: datetime = field(default_factory=utcnow)
    score: float | None = None
    """Similarity to the query, populated only on recall results."""

    def to_dict(self) -> dict[str, Any]:
        """JSON-serializable view; the embedding is deliberately omitted."""
        return {
            "id": self.id,
            "namespace": self.namespace,
            "text": self.text,
            "metadata": dict(self.metadata),
            "created_at": self.created_at.isoformat(),
            "score": round(self.score, 6) if self.score is not None else None,
        }

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        preview = self.text[:60] + ("..." if len(self.text) > 60 else "")
        score = f" score={self.score:.3f}" if self.score is not None else ""
        return f"<MemoryRecord {self.id} ns={self.namespace}{score} {preview!r}>"


@runtime_checkable
class EmbeddingProvider(Protocol):
    """Turns text into fixed-length vectors."""

    @property
    def dimension(self) -> int:  # pragma: no cover - protocol declaration
        ...

    async def embed(
        self, texts: Sequence[str]
    ) -> list[list[float]]:  # pragma: no cover - protocol declaration
        ...


class HashingEmbeddingProvider:
    """Deterministic offline embeddings via the hashing trick.

    Tokens are hashed into a fixed-width vector with sub-linear term weighting
    and signed buckets to limit collision bias, then L2-normalized. There is no
    model, no network call and no state, which makes it ideal for tests and for
    running the agent in an air-gapped environment.

    It captures lexical overlap only -- it has no notion of synonymy. For
    production recall quality, swap in a real embedding model; the interface is
    identical.
    """

    __slots__ = ("_dimension",)

    def __init__(self, dimension: int = 512) -> None:
        if dimension < 16:
            raise ValueError("Embedding dimension must be at least 16")
        self._dimension = dimension

    @property
    def dimension(self) -> int:
        return self._dimension

    async def embed(self, texts: Sequence[str]) -> list[list[float]]:
        return [self._embed_one(text) for text in texts]

    def _embed_one(self, text: str) -> list[float]:
        vector = [0.0] * self._dimension
        tokens = _tokenize(text)
        if not tokens:
            return vector

        counts: dict[str, int] = {}
        for token in tokens:
            counts[token] = counts.get(token, 0) + 1

        for token, count in counts.items():
            digest = hashlib.blake2b(token.encode("utf-8"), digest_size=8).digest()
            index = int.from_bytes(digest[:4], "big") % self._dimension
            sign = 1.0 if digest[4] & 1 else -1.0
            # Sub-linear scaling keeps a repeated token from dominating.
            vector[index] += sign * (1.0 + math.log(count))

        norm = math.sqrt(sum(v * v for v in vector))
        if norm:
            vector = [v / norm for v in vector]
        return vector

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<HashingEmbeddingProvider dim={self._dimension}>"


@runtime_checkable
class VectorStore(Protocol):
    """Persists embedded records and answers similarity queries."""

    async def add(
        self, records: Sequence[MemoryRecord]
    ) -> list[str]:  # pragma: no cover - protocol
        ...

    async def query(
        self,
        embedding: Sequence[float],
        *,
        k: int = 5,
        namespace: str | None = None,
        where: Mapping[str, Any] | None = None,
    ) -> list[MemoryRecord]:  # pragma: no cover - protocol
        ...

    async def get(self, record_id: str) -> MemoryRecord | None:  # pragma: no cover
        ...

    async def delete(self, record_id: str) -> bool:  # pragma: no cover - protocol
        ...

    async def count(self, namespace: str | None = None) -> int:  # pragma: no cover
        ...


class InMemoryVectorStore:
    """Brute-force vector store held in process memory.

    Exact search with no index, which is the right trade-off up to roughly tens
    of thousands of records -- comfortably more than a single engagement
    produces. Beyond that, swap in an ANN-backed store.

    All mutating operations are guarded by an :class:`asyncio.Lock` so
    concurrent plan steps can write safely.
    """

    __slots__ = ("_lock", "_records")

    def __init__(self) -> None:
        self._records: dict[str, MemoryRecord] = {}
        self._lock = asyncio.Lock()

    async def add(self, records: Sequence[MemoryRecord]) -> list[str]:
        async with self._lock:
            for record in records:
                if not record.embedding:
                    raise MemoryBackendError(
                        f"Record {record.id} has no embedding; embed before storing"
                    )
                self._records[record.id] = record
        return [r.id for r in records]

    async def query(
        self,
        embedding: Sequence[float],
        *,
        k: int = 5,
        namespace: str | None = None,
        where: Mapping[str, Any] | None = None,
    ) -> list[MemoryRecord]:
        if k <= 0:
            return []

        async with self._lock:
            candidates = [
                record
                for record in self._records.values()
                if (namespace is None or record.namespace == namespace)
                and _matches(record.metadata, where)
            ]

        scored: list[MemoryRecord] = []
        for record in candidates:
            try:
                score = cosine_similarity(embedding, record.embedding)
            except ValueError:
                # Dimension drift, e.g. after switching embedding providers.
                logger.warning(
                    "Skipping record %s: embedding dimension mismatch", record.id
                )
                continue
            hit = MemoryRecord(
                id=record.id,
                text=record.text,
                namespace=record.namespace,
                metadata=dict(record.metadata),
                embedding=record.embedding,
                created_at=record.created_at,
                score=score,
            )
            scored.append(hit)

        scored.sort(key=lambda r: (r.score or 0.0), reverse=True)
        return scored[:k]

    async def get(self, record_id: str) -> MemoryRecord | None:
        async with self._lock:
            return self._records.get(record_id)

    async def delete(self, record_id: str) -> bool:
        async with self._lock:
            return self._records.pop(record_id, None) is not None

    async def count(self, namespace: str | None = None) -> int:
        async with self._lock:
            if namespace is None:
                return len(self._records)
            return sum(1 for r in self._records.values() if r.namespace == namespace)

    async def clear(self, namespace: str | None = None) -> int:
        """Delete every record (optionally within one namespace)."""
        async with self._lock:
            if namespace is None:
                removed = len(self._records)
                self._records.clear()
                return removed
            doomed = [k for k, v in self._records.items() if v.namespace == namespace]
            for key in doomed:
                del self._records[key]
            return len(doomed)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<InMemoryVectorStore records={len(self._records)}>"


def _matches(metadata: Mapping[str, Any], where: Mapping[str, Any] | None) -> bool:
    """Exact-match metadata filter; a value may be a list meaning "any of"."""
    if not where:
        return True
    for key, expected in where.items():
        actual = metadata.get(key)
        if isinstance(expected, (list, tuple, set)):
            if actual not in expected:
                return False
        elif actual != expected:
            return False
    return True


class LongTermMemory:
    """High-level memory API used by the agent.

    Wraps an embedding provider and a vector store behind three verbs --
    :meth:`remember`, :meth:`recall`, :meth:`forget` -- and namespaces records
    per engagement so one client's intelligence never leaks into another's
    recall.
    """

    def __init__(
        self,
        store: VectorStore | None = None,
        embedder: EmbeddingProvider | None = None,
        *,
        namespace: str = "default",
        min_score: float = 0.05,
    ) -> None:
        self._store: VectorStore = store or InMemoryVectorStore()
        self._embedder: EmbeddingProvider = embedder or HashingEmbeddingProvider()
        self._namespace = namespace
        self._min_score = min_score

    @property
    def namespace(self) -> str:
        return self._namespace

    @property
    def store(self) -> VectorStore:
        return self._store

    def scoped(self, namespace: str) -> LongTermMemory:
        """Return a view over the same store bound to another namespace."""
        return LongTermMemory(
            self._store,
            self._embedder,
            namespace=namespace,
            min_score=self._min_score,
        )

    async def remember(
        self,
        text: str,
        metadata: Mapping[str, Any] | None = None,
        *,
        namespace: str | None = None,
        record_id: str | None = None,
    ) -> str:
        """Store ``text`` and return its record id."""
        if not text or not text.strip():
            raise ValueError("Cannot remember empty text")

        vectors = await self._embedder.embed([text])
        record = MemoryRecord(
            id=record_id or new_id("mem"),
            text=text,
            namespace=namespace or self._namespace,
            metadata=dict(metadata or {}),
            embedding=vectors[0],
        )
        await self._store.add([record])
        logger.debug("Remembered record=%s ns=%s", record.id, record.namespace)
        return record.id

    async def remember_many(
        self,
        items: Sequence[tuple[str, Mapping[str, Any]]],
        *,
        namespace: str | None = None,
    ) -> list[str]:
        """Store several ``(text, metadata)`` pairs in one embedding batch."""
        if not items:
            return []
        texts = [text for text, _ in items]
        vectors = await self._embedder.embed(texts)
        records = [
            MemoryRecord(
                text=text,
                namespace=namespace or self._namespace,
                metadata=dict(meta or {}),
                embedding=vector,
            )
            for (text, meta), vector in zip(items, vectors, strict=True)
        ]
        return await self._store.add(records)

    async def recall(
        self,
        query: str,
        *,
        k: int = 5,
        namespace: str | None = None,
        where: Mapping[str, Any] | None = None,
        min_score: float | None = None,
    ) -> list[MemoryRecord]:
        """Return up to ``k`` records most similar to ``query``.

        Results below the similarity floor are dropped, so an unrelated query
        returns nothing instead of the least-bad match.
        """
        if not query or not query.strip():
            return []

        vectors = await self._embedder.embed([query])
        hits = await self._store.query(
            vectors[0],
            k=k,
            namespace=namespace or self._namespace,
            where=where,
        )
        floor = self._min_score if min_score is None else min_score
        return [h for h in hits if (h.score or 0.0) >= floor]

    async def forget(self, record_id: str) -> bool:
        """Delete one record; returns whether it existed."""
        return await self._store.delete(record_id)

    async def size(self, namespace: str | None = None) -> int:
        """Number of stored records in the namespace."""
        return await self._store.count(namespace or self._namespace)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"<LongTermMemory ns={self._namespace!r} "
            f"store={type(self._store).__name__} "
            f"embedder={type(self._embedder).__name__}>"
        )
