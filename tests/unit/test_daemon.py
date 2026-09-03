"""Tests for health monitoring, worker supervision, and the daemon loop.

Two properties matter most and are tested hardest: an unreadable metric is
never reported as a healthy zero, and a crashing worker is restarted a bounded
number of times and then reported rather than restarted forever.
"""

from __future__ import annotations

import asyncio

import pytest

from security_assistant.daemon.health import (
    HealthGrade,
    HealthMonitor,
    HealthReport,
    HealthThresholds,
    ProcMetricReader,
    ResourceSnapshot,
    summarize,
)
from security_assistant.daemon.service import (
    DaemonConfig,
    SecurityDaemon,
    WorkerSpec,
    WorkerState,
    WorkerSupervisor,
)
from security_assistant.network.vpn import (
    RecoveryState,
    TunnelState,
    TunnelSupervisor,
    VpnConfig,
    VpnManager,
)
from tests.unit.conftest import run


class StaticReader:
    """A reader returning whatever the test dictates."""

    name = "static"

    def __init__(self, snapshot: ResourceSnapshot) -> None:
        self.snapshot = snapshot

    def read(self) -> ResourceSnapshot:
        return self.snapshot


class TestThresholds:
    def test_grades_by_band(self) -> None:
        thresholds = HealthThresholds()
        assert thresholds.grade(10.0, 80.0, 95.0) is HealthGrade.OK
        assert thresholds.grade(85.0, 80.0, 95.0) is HealthGrade.WARN
        assert thresholds.grade(99.0, 80.0, 95.0) is HealthGrade.CRITICAL

    def test_unreadable_metric_is_unknown_not_ok(self) -> None:
        """A missing metric rendered as 0% would look like an idle, healthy
        system -- the most misleading possible answer."""
        assert HealthThresholds().grade(None, 80.0, 95.0) is HealthGrade.UNKNOWN

    def test_rejects_inverted_thresholds(self) -> None:
        with pytest.raises(ValueError, match="cpu_warn"):
            HealthThresholds(cpu_warn=99.0, cpu_critical=50.0)


class TestHealthMonitor:
    def test_healthy_system(self) -> None:
        monitor = HealthMonitor(
            StaticReader(ResourceSnapshot(cpu_percent=5.0, memory_percent=30.0, disk_percent=40.0))
        )
        report = run(monitor.check())
        assert report.overall is HealthGrade.OK
        assert report.healthy is True

    def test_worst_grade_wins(self) -> None:
        monitor = HealthMonitor(
            StaticReader(ResourceSnapshot(cpu_percent=5.0, memory_percent=99.0, disk_percent=10.0))
        )
        report = run(monitor.check())
        assert report.overall is HealthGrade.CRITICAL

    def test_all_unknown_is_unknown_not_healthy(self) -> None:
        report = run(HealthMonitor(StaticReader(ResourceSnapshot())).check())
        assert report.overall is HealthGrade.UNKNOWN
        assert report.healthy is False
        assert report.notes

    def test_worker_saturation_warns(self) -> None:
        monitor = HealthMonitor(
            StaticReader(ResourceSnapshot(cpu_percent=1.0, memory_percent=1.0, disk_percent=1.0))
        )
        report = run(monitor.check(workers_busy=10, workers_total=10))
        assert report.worker_saturation == 1.0
        assert report.grades["workers"] is HealthGrade.WARN

    def test_no_workers_reports_no_saturation(self) -> None:
        report = HealthReport(snapshot=ResourceSnapshot())
        assert report.worker_saturation is None

    def test_latency_probe_failure_is_noted(self) -> None:
        class DeadProbe:
            async def latency_ms(self) -> float | None:
                return None

        monitor = HealthMonitor(
            StaticReader(ResourceSnapshot(cpu_percent=1.0, memory_percent=1.0, disk_percent=1.0)),
            latency_probe=DeadProbe(),
        )
        report = run(monitor.check())
        assert report.grades["latency"] is HealthGrade.UNKNOWN
        assert any("latency" in n for n in report.notes)

    def test_serializes(self) -> None:
        payload = run(
            HealthMonitor(StaticReader(ResourceSnapshot(cpu_percent=1.0))).check()
        ).to_dict()
        assert "overall" in payload
        assert "snapshot" in payload


class TestProcMetricReader:
    def test_first_cpu_sample_is_none_not_zero(self) -> None:
        """A percentage needs two samples; inventing one from a single read
        would be a fabricated reading."""
        assert ProcMetricReader().read().cpu_percent is None

    def test_second_sample_produces_a_number_where_proc_exists(self) -> None:
        reader = ProcMetricReader()
        reader.read()
        second = reader.read()
        # On Linux this is a float; elsewhere /proc is absent and None is the
        # honest answer. Both are acceptable; a fabricated 0.0 is not.
        assert second.cpu_percent is None or 0.0 <= second.cpu_percent <= 100.0

    def test_reports_its_source(self) -> None:
        assert ProcMetricReader().read().source == "proc"


class TestWorkerSupervisor:
    def test_runs_a_worker_to_completion(self) -> None:
        done: list[str] = []

        async def worker() -> None:
            done.append("ran")

        async def scenario() -> None:
            supervisor = WorkerSupervisor()
            supervisor.register(WorkerSpec("ok", worker))
            await supervisor.start_all()
            await asyncio.sleep(0.05)
            await supervisor.stop_all(0.1)

        run(scenario())
        assert done == ["ran"]

    def test_restarts_a_crashing_worker_then_gives_up(self) -> None:
        """Bounded self-healing: restart a few times, then report the fault
        instead of hiding it in a loop."""
        attempts: list[int] = []

        async def crasher() -> None:
            attempts.append(1)
            raise RuntimeError("boom")

        async def scenario() -> WorkerSupervisor:
            supervisor = WorkerSupervisor()
            supervisor.register(
                WorkerSpec(
                    "crasher",
                    crasher,
                    max_restarts=3,
                    restart_delay_seconds=0.001,
                    restart_window_seconds=60.0,
                )
            )
            await supervisor.start_all()
            await asyncio.sleep(0.5)
            await supervisor.stop_all(0.1)
            return supervisor

        supervisor = run(scenario())
        status = supervisor.statuses["crasher"]

        assert status.state is WorkerState.FAILED
        assert "boom" in status.last_error
        assert len(attempts) <= 5  # bounded, not infinite
        assert supervisor.failed == ["crasher"]

    def test_failed_worker_is_not_restarted_until_reset(self) -> None:
        async def crasher() -> None:
            raise RuntimeError("boom")

        async def scenario() -> WorkerSupervisor:
            supervisor = WorkerSupervisor()
            supervisor.register(
                WorkerSpec("c", crasher, max_restarts=1, restart_delay_seconds=0.001)
            )
            await supervisor.start_all()
            await asyncio.sleep(0.2)
            await supervisor.start("c")  # must be refused
            await asyncio.sleep(0.05)
            await supervisor.stop_all(0.1)
            return supervisor

        supervisor = run(scenario())
        assert supervisor.statuses["c"].state is WorkerState.FAILED

    def test_operator_reset_clears_failure(self) -> None:
        async def crasher() -> None:
            raise RuntimeError("boom")

        async def scenario() -> WorkerSupervisor:
            supervisor = WorkerSupervisor()
            supervisor.register(
                WorkerSpec("c", crasher, max_restarts=1, restart_delay_seconds=0.001)
            )
            await supervisor.start_all()
            await asyncio.sleep(0.2)
            await supervisor.stop_all(0.1)
            return supervisor

        supervisor = run(scenario())
        status = supervisor.reset("c")
        assert status.state is WorkerState.STOPPED
        assert status.last_error == ""

    def test_duplicate_registration_is_rejected(self) -> None:
        async def worker() -> None:
            return None

        supervisor = WorkerSupervisor()
        supervisor.register(WorkerSpec("dup", worker))
        with pytest.raises(ValueError, match="already registered"):
            supervisor.register(WorkerSpec("dup", worker))

    def test_unknown_worker_raises(self) -> None:
        with pytest.raises(KeyError):
            run(WorkerSupervisor().start("nope"))

    def test_empty_name_is_rejected(self) -> None:
        async def worker() -> None:
            return None

        with pytest.raises(ValueError, match="must not be empty"):
            WorkerSpec("  ", worker)


class FakeBackend:
    name = "fake"

    def __init__(self, state: TunnelState) -> None:
        self.state = state

    async def status(self, interface: str):  # type: ignore[no-untyped-def]
        from security_assistant.network.vpn import TunnelStatus

        return TunnelStatus(interface=interface, backend=self.name, state=self.state)

    async def up(self, interface: str):  # type: ignore[no-untyped-def]
        return await self.status(interface)

    async def down(self, interface: str):  # type: ignore[no-untyped-def]
        return await self.status(interface)


class TestDaemonLoop:
    def test_runs_a_bounded_number_of_iterations(self) -> None:
        daemon = SecurityDaemon(
            config=DaemonConfig(
                health_interval_seconds=0.01,
                tunnel_interval_seconds=0.01,
                heartbeat_interval_seconds=0.01,
                max_iterations=3,
                install_signal_handlers=False,
            ),
            health=HealthMonitor(StaticReader(ResourceSnapshot(cpu_percent=1.0))),
        )
        state = run(daemon.run())

        assert state.iterations == 3
        assert state.stopped is True
        assert state.heartbeats >= 1
        assert state.last_health is not None

    def test_emits_lifecycle_events(self) -> None:
        events: list[str] = []
        daemon = SecurityDaemon(
            config=DaemonConfig(
                health_interval_seconds=0.01,
                tunnel_interval_seconds=0.01,
                heartbeat_interval_seconds=0.01,
                max_iterations=2,
                install_signal_handlers=False,
            ),
            health=HealthMonitor(StaticReader(ResourceSnapshot(cpu_percent=1.0))),
            on_event=lambda name, payload: events.append(name),
        )
        run(daemon.run())

        assert "daemon.started" in events
        assert "daemon.heartbeat" in events
        assert "daemon.stopped" in events

    def test_a_raising_listener_does_not_kill_the_daemon(self) -> None:
        def bad_listener(name: str, payload: object) -> None:
            raise RuntimeError("listener exploded")

        daemon = SecurityDaemon(
            config=DaemonConfig(
                health_interval_seconds=0.01,
                tunnel_interval_seconds=0.01,
                heartbeat_interval_seconds=0.01,
                max_iterations=2,
                install_signal_handlers=False,
            ),
            health=HealthMonitor(StaticReader(ResourceSnapshot(cpu_percent=1.0))),
            on_event=bad_listener,
        )
        state = run(daemon.run())
        assert state.stopped is True

    def test_supervises_the_tunnel(self) -> None:
        supervisor = TunnelSupervisor(
            VpnManager(FakeBackend(TunnelState.UP), VpnConfig(interface="wg0"))
        )
        daemon = SecurityDaemon(
            config=DaemonConfig(
                health_interval_seconds=0.01,
                tunnel_interval_seconds=0.01,
                heartbeat_interval_seconds=0.01,
                max_iterations=2,
                install_signal_handlers=False,
            ),
            health=HealthMonitor(StaticReader(ResourceSnapshot(cpu_percent=1.0))),
            tunnel=supervisor,
        )
        state = run(daemon.run())

        assert state.last_tunnel is not None
        assert state.last_tunnel.state is RecoveryState.HEALTHY

    def test_a_health_check_failure_does_not_stop_the_loop(self) -> None:
        class BrokenReader:
            name = "broken"

            def read(self) -> ResourceSnapshot:
                raise OSError("cannot read /proc")

        daemon = SecurityDaemon(
            config=DaemonConfig(
                health_interval_seconds=0.01,
                tunnel_interval_seconds=0.01,
                heartbeat_interval_seconds=0.01,
                max_iterations=2,
                install_signal_handlers=False,
            ),
            health=HealthMonitor(BrokenReader()),
        )
        state = run(daemon.run())
        assert state.iterations == 2
        assert state.stopped is True

    def test_failed_workers_are_escalated_into_the_health_report(self) -> None:
        async def crasher() -> None:
            raise RuntimeError("boom")

        workers = WorkerSupervisor()
        workers.register(WorkerSpec("c", crasher, max_restarts=1, restart_delay_seconds=0.001))
        daemon = SecurityDaemon(
            config=DaemonConfig(
                health_interval_seconds=0.01,
                tunnel_interval_seconds=0.01,
                heartbeat_interval_seconds=0.01,
                max_iterations=6,
                install_signal_handlers=False,
            ),
            health=HealthMonitor(StaticReader(ResourceSnapshot(cpu_percent=1.0))),
            workers=workers,
        )
        state = run(daemon.run())

        assert state.last_health is not None
        assert state.last_health.grades.get("workers") is HealthGrade.CRITICAL

    def test_request_stop_ends_the_loop(self) -> None:
        async def scenario() -> object:
            daemon = SecurityDaemon(
                config=DaemonConfig(
                    health_interval_seconds=0.01,
                    tunnel_interval_seconds=0.01,
                    heartbeat_interval_seconds=0.01,
                    install_signal_handlers=False,
                ),
                health=HealthMonitor(StaticReader(ResourceSnapshot(cpu_percent=1.0))),
            )
            task = asyncio.create_task(daemon.run())
            await asyncio.sleep(0.05)
            daemon.request_stop("test asked")
            return await task

        state = run(scenario())
        assert state.stopped is True  # type: ignore[attr-defined]
        assert "test asked" in state.stop_reason  # type: ignore[attr-defined]

    def test_config_rejects_non_positive_intervals(self) -> None:
        with pytest.raises(ValueError, match="must be positive"):
            DaemonConfig(health_interval_seconds=0)


class TestSummaries:
    def test_summarize_reports_worst(self) -> None:
        ok = HealthReport(snapshot=ResourceSnapshot(), grades={"cpu": HealthGrade.OK})
        bad = HealthReport(snapshot=ResourceSnapshot(), grades={"cpu": HealthGrade.CRITICAL})
        assert summarize([ok, bad])["worst"] == "critical"

    def test_summarize_empty(self) -> None:
        assert summarize([])["count"] == 0
