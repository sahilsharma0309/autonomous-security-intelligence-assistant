"""Resource and health monitoring for the daemon.

Collects CPU, memory, disk, network latency and worker-pool occupancy, and
grades them against thresholds.

``psutil`` is used when installed and a ``/proc``-based reader stands in when
it is not, so the daemon reports real numbers on Linux with no dependencies at
all. Where a metric genuinely cannot be read, it is reported as ``None`` and
graded :attr:`HealthGrade.UNKNOWN` -- never as zero. A missing metric rendered
as ``0%`` looks like an idle, healthy system, which is the most misleading
possible answer.
"""

from __future__ import annotations

import contextlib
import logging
import os
import shutil
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Protocol, runtime_checkable

from security_assistant.core.types import utcnow

logger = logging.getLogger(__name__)

_psutil: Any
try:  # pragma: no cover - depends on which extras are installed
    import psutil

    _psutil = psutil
except ImportError:  # pragma: no cover
    _psutil = None

__all__ = [
    "HealthGrade",
    "HealthReport",
    "HealthThresholds",
    "MetricReader",
    "ProcMetricReader",
    "PsutilMetricReader",
    "ResourceSnapshot",
    "default_reader",
]


class HealthGrade(StrEnum):
    """How a metric or the system as a whole is doing."""

    OK = "ok"
    WARN = "warn"
    CRITICAL = "critical"
    UNKNOWN = "unknown"
    """The metric could not be read. Not the same as OK."""

    @property
    def is_bad(self) -> bool:
        return self in (HealthGrade.WARN, HealthGrade.CRITICAL)


@dataclass(slots=True)
class ResourceSnapshot:
    """One reading of the host's resources.

    Every field is optional: a metric that could not be read is ``None``.
    """

    cpu_percent: float | None = None
    memory_percent: float | None = None
    memory_available_mb: float | None = None
    disk_percent: float | None = None
    load_average_1m: float | None = None
    cpu_count: int | None = None
    open_files: int | None = None
    taken_at: Any = field(default_factory=utcnow)
    source: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "cpu_percent": self.cpu_percent,
            "memory_percent": self.memory_percent,
            "memory_available_mb": self.memory_available_mb,
            "disk_percent": self.disk_percent,
            "load_average_1m": self.load_average_1m,
            "cpu_count": self.cpu_count,
            "open_files": self.open_files,
            "source": self.source,
            "taken_at": self.taken_at.isoformat(),
        }


@runtime_checkable
class MetricReader(Protocol):
    """Reads host resource metrics."""

    name: str

    def read(self) -> ResourceSnapshot:  # pragma: no cover - protocol declaration
        ...


class PsutilMetricReader:
    """Full metrics via ``psutil``."""

    name = "psutil"

    __slots__ = ("_path",)

    def __init__(self, disk_path: str = "/") -> None:
        self._path = disk_path

    def read(self) -> ResourceSnapshot:
        if _psutil is None:  # pragma: no cover - guarded by default_reader
            return ResourceSnapshot(source="psutil-unavailable")

        snapshot = ResourceSnapshot(source=self.name)
        try:
            # interval=None returns the value since the last call, which is
            # what a polling daemon wants; a blocking interval would stall
            # the event loop.
            snapshot.cpu_percent = float(_psutil.cpu_percent(interval=None))
            snapshot.cpu_count = int(_psutil.cpu_count() or 0) or None
            memory = _psutil.virtual_memory()
            snapshot.memory_percent = float(memory.percent)
            snapshot.memory_available_mb = round(memory.available / 1_048_576, 1)
            snapshot.disk_percent = float(_psutil.disk_usage(self._path).percent)
        except Exception as exc:  # noqa: BLE001 - psutil raises platform errors
            logger.debug("psutil read failed: %s", exc)

        snapshot.load_average_1m = _load_average()
        return snapshot


class ProcMetricReader:
    """Dependency-free metrics from ``/proc`` and the standard library.

    CPU percent needs two samples to mean anything, so the first read reports
    ``None`` rather than inventing a number from a single sample.
    """

    name = "proc"

    __slots__ = ("_path", "_previous")

    def __init__(self, disk_path: str = "/") -> None:
        self._path = disk_path
        self._previous: tuple[float, float] | None = None

    def read(self) -> ResourceSnapshot:
        snapshot = ResourceSnapshot(source=self.name)
        snapshot.cpu_percent = self._cpu_percent()
        snapshot.cpu_count = os.cpu_count()
        snapshot.load_average_1m = _load_average()

        total_kb, available_kb = _meminfo()
        if total_kb and available_kb is not None:
            snapshot.memory_percent = round(100.0 * (total_kb - available_kb) / total_kb, 1)
            snapshot.memory_available_mb = round(available_kb / 1024, 1)

        try:
            usage = shutil.disk_usage(self._path)
            snapshot.disk_percent = round(100.0 * usage.used / usage.total, 1)
        except OSError:  # pragma: no cover - unusual filesystem
            pass

        return snapshot

    def _cpu_percent(self) -> float | None:
        stat = _proc_stat()
        if stat is None:
            return None
        idle, total = stat

        previous = self._previous
        self._previous = (idle, total)
        if previous is None:
            # First sample: a percentage needs a delta, and guessing one
            # would be a fabricated reading.
            return None

        idle_delta = idle - previous[0]
        total_delta = total - previous[1]
        if total_delta <= 0:
            return None
        return round(100.0 * (1.0 - idle_delta / total_delta), 1)


def _proc_stat() -> tuple[float, float] | None:
    try:
        with open("/proc/stat", encoding="utf-8") as handle:
            line = handle.readline()
    except OSError:
        return None
    if not line.startswith("cpu "):
        return None
    fields = [float(v) for v in line.split()[1:] if v.replace(".", "").isdigit()]
    if len(fields) < 5:
        return None
    idle = fields[3] + (fields[4] if len(fields) > 4 else 0.0)
    return idle, sum(fields)


def _meminfo() -> tuple[float, float | None]:
    try:
        with open("/proc/meminfo", encoding="utf-8") as handle:
            values: dict[str, float] = {}
            for line in handle:
                key, _, rest = line.partition(":")
                parts = rest.split()
                if parts and parts[0].isdigit():
                    values[key.strip()] = float(parts[0])
    except OSError:
        return 0.0, None
    return values.get("MemTotal", 0.0), values.get("MemAvailable")


def _load_average() -> float | None:
    try:
        return round(os.getloadavg()[0], 2)
    except (OSError, AttributeError):  # pragma: no cover - unsupported platform
        return None


def default_reader(disk_path: str = "/") -> MetricReader:
    """Best reader available here."""
    if _psutil is not None:  # pragma: no cover - depends on the environment
        return PsutilMetricReader(disk_path)
    return ProcMetricReader(disk_path)


@dataclass(slots=True)
class HealthThresholds:
    """When a metric counts as degraded."""

    cpu_warn: float = 80.0
    cpu_critical: float = 95.0
    memory_warn: float = 85.0
    memory_critical: float = 95.0
    disk_warn: float = 85.0
    disk_critical: float = 95.0
    latency_warn_ms: float = 250.0
    latency_critical_ms: float = 1000.0
    worker_saturation_warn: float = 0.9

    def __post_init__(self) -> None:
        for warn, critical, name in (
            (self.cpu_warn, self.cpu_critical, "cpu"),
            (self.memory_warn, self.memory_critical, "memory"),
            (self.disk_warn, self.disk_critical, "disk"),
            (self.latency_warn_ms, self.latency_critical_ms, "latency"),
        ):
            if warn > critical:
                raise ValueError(
                    f"{name}_warn ({warn}) must not exceed {name}_critical ({critical})"
                )

    def grade(self, value: float | None, warn: float, critical: float) -> HealthGrade:
        if value is None:
            return HealthGrade.UNKNOWN
        if value >= critical:
            return HealthGrade.CRITICAL
        if value >= warn:
            return HealthGrade.WARN
        return HealthGrade.OK


@dataclass(slots=True)
class HealthReport:
    """A graded snapshot of the whole system."""

    snapshot: ResourceSnapshot
    grades: dict[str, HealthGrade] = field(default_factory=dict)
    latency_ms: float | None = None
    workers_busy: int = 0
    workers_total: int = 0
    notes: list[str] = field(default_factory=list)
    generated_at: Any = field(default_factory=utcnow)

    @property
    def overall(self) -> HealthGrade:
        """Worst grade wins; UNKNOWN never masquerades as OK."""
        values = list(self.grades.values())
        if any(g is HealthGrade.CRITICAL for g in values):
            return HealthGrade.CRITICAL
        if any(g is HealthGrade.WARN for g in values):
            return HealthGrade.WARN
        if values and all(g is HealthGrade.UNKNOWN for g in values):
            return HealthGrade.UNKNOWN
        return HealthGrade.OK if values else HealthGrade.UNKNOWN

    @property
    def healthy(self) -> bool:
        return self.overall is HealthGrade.OK

    @property
    def worker_saturation(self) -> float | None:
        if self.workers_total <= 0:
            return None
        return round(self.workers_busy / self.workers_total, 3)

    def to_dict(self) -> dict[str, Any]:
        return {
            "overall": self.overall.value,
            "healthy": self.healthy,
            "grades": {k: v.value for k, v in self.grades.items()},
            "latency_ms": self.latency_ms,
            "workers_busy": self.workers_busy,
            "workers_total": self.workers_total,
            "worker_saturation": self.worker_saturation,
            "notes": list(self.notes),
            "snapshot": self.snapshot.to_dict(),
            "generated_at": self.generated_at.isoformat(),
        }


@runtime_checkable
class LatencyProbe(Protocol):
    """Measures network round-trip latency."""

    async def latency_ms(self) -> float | None:  # pragma: no cover - protocol
        ...


class TcpLatencyProbe:
    """Measures latency with a TCP connect, not ICMP.

    ``ping`` needs raw sockets or a setuid binary, which is exactly the sort
    of privilege this project avoids; a TCP connect to a known host measures
    the same thing well enough and needs nothing.
    """

    __slots__ = ("_host", "_port", "_timeout")

    def __init__(self, host: str = "1.1.1.1", port: int = 443, timeout: float = 5.0) -> None:
        self._host = host
        self._port = port
        self._timeout = timeout

    async def latency_ms(self) -> float | None:
        import asyncio

        started = time.monotonic()
        writer = None
        try:
            _reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self._host, self._port), timeout=self._timeout
            )
            return round((time.monotonic() - started) * 1000, 1)
        except (TimeoutError, OSError):
            return None
        finally:
            if writer is not None:
                writer.close()
                with contextlib.suppress(OSError):  # best effort
                    await writer.wait_closed()


class HealthMonitor:
    """Produces graded health reports."""

    def __init__(
        self,
        reader: MetricReader | None = None,
        thresholds: HealthThresholds | None = None,
        latency_probe: LatencyProbe | None = None,
    ) -> None:
        self._reader = reader or default_reader()
        self._thresholds = thresholds or HealthThresholds()
        self._latency = latency_probe

    @property
    def thresholds(self) -> HealthThresholds:
        return self._thresholds

    async def check(self, *, workers_busy: int = 0, workers_total: int = 0) -> HealthReport:
        """Take a reading and grade it."""
        snapshot = self._reader.read()
        report = HealthReport(
            snapshot=snapshot, workers_busy=workers_busy, workers_total=workers_total
        )
        thresholds = self._thresholds

        report.grades["cpu"] = thresholds.grade(
            snapshot.cpu_percent, thresholds.cpu_warn, thresholds.cpu_critical
        )
        report.grades["memory"] = thresholds.grade(
            snapshot.memory_percent, thresholds.memory_warn, thresholds.memory_critical
        )
        report.grades["disk"] = thresholds.grade(
            snapshot.disk_percent, thresholds.disk_warn, thresholds.disk_critical
        )

        if self._latency is not None:
            report.latency_ms = await self._latency.latency_ms()
            report.grades["latency"] = thresholds.grade(
                report.latency_ms,
                thresholds.latency_warn_ms,
                thresholds.latency_critical_ms,
            )
            if report.latency_ms is None:
                report.notes.append("network latency probe did not complete")

        saturation = report.worker_saturation
        if saturation is not None:
            report.grades["workers"] = (
                HealthGrade.WARN
                if saturation >= thresholds.worker_saturation_warn
                else HealthGrade.OK
            )

        for name, grade in report.grades.items():
            if grade is HealthGrade.UNKNOWN:
                report.notes.append(f"{name} could not be measured")

        return report

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<HealthMonitor reader={self._reader.name}>"


def summarize(reports: Sequence[HealthReport]) -> Mapping[str, Any]:
    """Aggregate several reports."""
    if not reports:
        return {"count": 0, "worst": HealthGrade.UNKNOWN.value}
    order = [HealthGrade.OK, HealthGrade.UNKNOWN, HealthGrade.WARN, HealthGrade.CRITICAL]
    worst = max((r.overall for r in reports), key=order.index)
    return {"count": len(reports), "worst": worst.value}
