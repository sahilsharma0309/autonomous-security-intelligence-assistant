"""System health daemon: monitoring, worker supervision, service templates.

Runs the assistant as a long-lived background service. Three concerns:

* :mod:`~security_assistant.daemon.health` -- CPU, memory, disk, latency and
  worker occupancy, graded against thresholds. A metric that cannot be read is
  ``UNKNOWN``, never ``0``.
* :mod:`~security_assistant.daemon.service` -- the asyncio loop: heartbeat,
  health sampling, tunnel supervision, and worker restart budgets.
* :mod:`~security_assistant.network.privileges` -- the systemd and launchd
  templates that install it.

Recovery is bounded everywhere. A worker gets a restart budget inside a rolling
window and is then marked ``FAILED``; a tunnel gets bounded attempts and then
``NEEDS_OPERATOR``. Unbounded retries hide faults rather than fixing them.
"""

from __future__ import annotations

from security_assistant.daemon.health import (
    HealthGrade,
    HealthMonitor,
    HealthReport,
    HealthThresholds,
    MetricReader,
    ProcMetricReader,
    PsutilMetricReader,
    ResourceSnapshot,
    TcpLatencyProbe,
    default_reader,
)
from security_assistant.daemon.service import (
    DaemonConfig,
    DaemonState,
    SecurityDaemon,
    WorkerSpec,
    WorkerState,
    WorkerStatus,
    WorkerSupervisor,
)

__all__ = [
    "DaemonConfig",
    "DaemonState",
    "HealthGrade",
    "HealthMonitor",
    "HealthReport",
    "HealthThresholds",
    "MetricReader",
    "ProcMetricReader",
    "PsutilMetricReader",
    "ResourceSnapshot",
    "SecurityDaemon",
    "TcpLatencyProbe",
    "WorkerSpec",
    "WorkerState",
    "WorkerStatus",
    "WorkerSupervisor",
    "default_reader",
]
