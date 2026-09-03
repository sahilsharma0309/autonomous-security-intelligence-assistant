"""End-to-end integration across all five modules.

This is the test that would catch a regression in how the assistant fits
together: one registry holding every capability, one authorization scope
governing all of them, one graph collecting what they find, and one daemon
supervising the tunnel underneath.

Every system and network dependency is injected, so it runs with no root, no
network, and no optional packages.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from typing import Any

from security_assistant.core import (
    Agent,
    AgentConfig,
    AuthorizationScope,
    RiskLevel,
    TaskStatus,
    ToolRegistry,
)
from security_assistant.daemon import (
    DaemonConfig,
    HealthMonitor,
    ResourceSnapshot,
    SecurityDaemon,
    WorkerSpec,
    WorkerSupervisor,
)
from security_assistant.iot import ALL_IOT_TOOLS
from security_assistant.network import (
    DryRunRunner,
    KillSwitch,
    LockoutGuard,
    RecordingRunner,
    TunnelSupervisor,
    VpnConfig,
    VpnManager,
    build_iptables_plan,
)
from security_assistant.network.vpn import RecoveryState, TunnelState, TunnelStatus
from security_assistant.osint import (
    ALL_COLLECTORS,
    Correlator,
    EntityType,
    build_graph_from_payloads,
)
from security_assistant.threat import ALL_THREAT_TOOLS
from security_assistant.threat.models import SandboxReport

ENGAGEMENT = ["example.com", "paypa1.com", "collector.example", "192.0.2.10"]


# --------------------------------------------------------------------------- #
# Injected doubles
# --------------------------------------------------------------------------- #
class Resolver:
    async def resolve(self, name: str, record_type: str) -> list[str]:
        table = {
            "example.com": {"A": ["192.0.2.10"], "MX": ["10 mail.example.com."]},
            "collector.example": {"A": ["192.0.2.10"]},
        }
        return list(table.get(name, {}).get(record_type, []))


class Whois:
    async def lookup(self, domain: str) -> Mapping[str, Any]:
        return {"org": "Acme Widgets Ltd", "emails": ["admin@example.com"]}


class Tls:
    async def fetch(self, host: str, port: int, *, verify: bool) -> Mapping[str, Any]:
        return {
            "subject": ((("commonName", host),),),
            "issuer": ((("organizationName", "Let's Encrypt"),),),
            "subjectAltName": (("DNS", host),),
            "notAfter": "Sep  1 12:00:00 2035 GMT",
            "_version": "TLSv1.3",
            "_cipher": ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
        }


class Shodan:
    async def host(self, ip: str) -> Mapping[str, Any]:
        return {
            "ip_str": ip,
            "data": [
                {"port": 554, "transport": "tcp", "product": "Hikvision RTSP"},
                {"port": 80, "transport": "tcp", "product": "lighttpd"},
            ],
        }

    async def search(self, query: str, *, limit: int = 100) -> Mapping[str, Any]:
        return {"matches": []}


class VirusTotal:
    async def report(self, indicator_type: str, indicator: str) -> Mapping[str, Any]:
        return {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 7, "harmless": 60},
                    "categories": {"Sophos": "phishing"},
                }
            }
        }


class Urlscan:
    async def search(self, query: str, *, size: int = 20) -> Mapping[str, Any]:
        return {"results": []}

    async def submit(self, url: str, options: Any) -> Mapping[str, Any]:
        return {"uuid": "scan-1"}

    async def result(self, scan_id: str) -> Mapping[str, Any]:
        return {}


class Inspector:
    async def inspect(self, url: str) -> SandboxReport:
        return SandboxReport(
            initial_url=url,
            final_url="https://collector.example/harvest",
            engine="container",
            status=200,
            contacted_domains=["collector.example"],
            has_password_input=True,
        )


class TunnelBackend:
    """A tunnel whose state the test drives."""

    name = "fake"

    def __init__(self, state: TunnelState = TunnelState.UP) -> None:
        self.state = state
        self.up_calls = 0

    async def status(self, interface: str) -> TunnelStatus:
        return TunnelStatus(interface=interface, backend=self.name, state=self.state)

    async def up(self, interface: str) -> TunnelStatus:
        self.up_calls += 1
        return await self.status(interface)

    async def down(self, interface: str) -> TunnelStatus:
        return TunnelStatus(interface=interface, backend=self.name, state=TunnelState.DOWN)


def full_registry() -> ToolRegistry:
    registry = ToolRegistry("assistant")
    registry.register_all(ALL_COLLECTORS)
    registry.register_all(ALL_IOT_TOOLS)
    registry.register_all(ALL_THREAT_TOOLS)
    return registry


def scope(max_risk: RiskLevel = RiskLevel.ACTIVE) -> AuthorizationScope:
    return AuthorizationScope(
        allow=ENGAGEMENT,
        max_risk=max_risk,
        authorization_reference="ENG-FULL-1",
        engagement="full-stack",
    )


def context() -> dict[str, Any]:
    return {
        "dns_resolver": Resolver(),
        "whois_client": Whois(),
        "tls_fetcher": Tls(),
        "search_client": Shodan(),
        "virustotal_client": VirusTotal(),
        "urlscan_client": Urlscan(),
        "sandbox_inspector": Inspector(),
    }


class TestEveryModuleRegistersTogether:
    def test_one_registry_holds_every_capability(self) -> None:
        registry = full_registry()
        names = set(registry.names)

        assert any(n.startswith("osint.") for n in names)
        assert any(n.startswith("iot.") for n in names)
        assert any(n.startswith("threat.") for n in names)
        assert len(registry) >= 14

    def test_no_tool_name_collides(self) -> None:
        registry = full_registry()
        assert len(registry.names) == len(set(registry.names))

    def test_every_tool_is_scope_gated(self) -> None:
        """One authorization model governs all five modules."""
        for spec in full_registry().specs:
            assert spec.requires_scope, spec.name
            assert spec.target_argument, spec.name

    def test_every_tool_declares_limits(self) -> None:
        for spec in full_registry().specs:
            assert spec.timeout_seconds > 0, spec.name
            assert spec.rate_limit_per_minute > 0, spec.name


class TestCrossModuleAssessment:
    def test_osint_and_iot_converge_on_one_graph(self) -> None:
        agent = Agent(full_registry(), scope(), config=AgentConfig(name="full"))
        osint = asyncio.run(agent.run("Map surface", target="example.com", context=context()))
        iot = asyncio.run(agent.run("Discover assets", target="192.0.2.10", context=context()))

        graph = build_graph_from_payloads(
            [*osint.values_by_tool().values(), *iot.values_by_tool().values()]
        )

        # The domain resolves to the address the device answers on, and
        # nothing wired those two modules together.
        assert "domain:example.com" in graph
        assert "ip_address:192.0.2.10" in graph
        assert graph.shortest_path("domain:example.com", "ip_address:192.0.2.10")

    def test_threat_findings_join_the_same_graph(self) -> None:
        agent = Agent(full_registry(), scope())
        osint = asyncio.run(agent.run("Map surface", target="collector.example", context=context()))
        threat = asyncio.run(
            agent.run("Assess link", target="https://paypa1.com/login", context=context())
        )

        graph = build_graph_from_payloads(
            [*osint.values_by_tool().values(), *threat.values_by_tool().values()]
        )

        assert "url:https://paypa1.com/login" in graph
        assert "ip_address:192.0.2.10" in graph
        assert graph.shortest_path("url:https://paypa1.com/login", "ip_address:192.0.2.10")

    def test_correlation_runs_over_the_combined_graph(self) -> None:
        agent = Agent(full_registry(), scope())
        results = [
            asyncio.run(agent.run("Map", target="example.com", context=context())),
            asyncio.run(agent.run("Assets", target="192.0.2.10", context=context())),
        ]
        graph = build_graph_from_payloads([v for r in results for v in r.values_by_tool().values()])
        report = Correlator().correlate(graph)

        assert report.entities_after == len(graph)
        assert graph.by_type(EntityType.DOMAIN)

    def test_graph_round_trips_with_every_entity_type(self) -> None:
        from security_assistant.osint import EntityGraph

        agent = Agent(full_registry(), scope())
        results = [
            asyncio.run(agent.run("Map", target="example.com", context=context())),
            asyncio.run(agent.run("Assets", target="192.0.2.10", context=context())),
            asyncio.run(agent.run("Assess", target="https://paypa1.com/login", context=context())),
        ]
        graph = build_graph_from_payloads([v for r in results for v in r.values_by_tool().values()])
        restored = EntityGraph.from_json(graph.to_json())
        assert {e.key for e in restored} == {e.key for e in graph}


class TestAuthorizationGovernsEverything:
    def test_out_of_scope_target_is_refused_across_all_modules(self) -> None:
        agent = Agent(full_registry(), scope())
        result = asyncio.run(agent.run("Assess", target="not-authorized.test", context=context()))

        assert result.status is TaskStatus.FAILED
        assert result.denied
        assert not result.succeeded

    def test_passive_engagement_runs_only_passive_tools(self) -> None:
        agent = Agent(full_registry(), scope(RiskLevel.PASSIVE))
        result = asyncio.run(agent.run("Passive survey", target="example.com", context=context()))

        registry = full_registry()
        for tool_result in result.results:
            spec = registry.get(tool_result.tool_name).spec
            assert spec.risk is RiskLevel.PASSIVE, spec.name

    def test_intrusive_tools_need_an_intrusive_scope(self) -> None:
        registry = full_registry()
        intrusive = [s.name for s in registry.specs if s.risk is RiskLevel.INTRUSIVE]
        assert intrusive, "expected at least one INTRUSIVE tool"

        agent = Agent(registry, scope(RiskLevel.ACTIVE))
        result = asyncio.run(agent.run("Survey", target="192.0.2.10", context=context()))
        assert not any(r.tool_name in intrusive for r in result.results)


class TestDaemonSupervisesTheStack:
    def test_daemon_reports_healthy_tunnel_and_health(self) -> None:
        class Reader:
            name = "static"

            def read(self) -> ResourceSnapshot:
                return ResourceSnapshot(cpu_percent=10.0, memory_percent=20.0, disk_percent=30.0)

        supervisor = TunnelSupervisor(
            VpnManager(TunnelBackend(TunnelState.UP), VpnConfig(interface="wg0"))
        )
        daemon = SecurityDaemon(
            config=DaemonConfig(
                health_interval_seconds=0.01,
                tunnel_interval_seconds=0.01,
                heartbeat_interval_seconds=0.01,
                max_iterations=3,
                install_signal_handlers=False,
            ),
            health=HealthMonitor(Reader()),
            tunnel=supervisor,
        )
        state = asyncio.run(daemon.run())

        assert state.last_health is not None
        assert state.last_health.healthy is True
        assert state.last_tunnel is not None
        assert state.last_tunnel.state is RecoveryState.HEALTHY

    def test_daemon_escalates_an_unrecoverable_tunnel(self) -> None:
        """Autonomous recovery is bounded: after the budget it asks for a
        human rather than looping."""
        clock = [0.0]
        backend = TunnelBackend(TunnelState.DOWN)
        supervisor = TunnelSupervisor(
            VpnManager(
                backend,
                VpnConfig(
                    interface="wg0",
                    max_reconnect_attempts=2,
                    reconnect_backoff_seconds=0.0,
                ),
            ),
            clock=lambda: clock[0],
        )
        daemon = SecurityDaemon(
            config=DaemonConfig(
                health_interval_seconds=0.01,
                tunnel_interval_seconds=0.01,
                heartbeat_interval_seconds=0.01,
                max_iterations=6,
                install_signal_handlers=False,
            ),
            health=HealthMonitor(
                type("R", (), {"name": "s", "read": lambda self: ResourceSnapshot()})()
            ),
            tunnel=supervisor,
        )
        state = asyncio.run(daemon.run())

        assert state.last_tunnel is not None
        assert state.last_tunnel.state is RecoveryState.NEEDS_OPERATOR
        assert backend.up_calls == 2  # bounded, not unbounded

    def test_daemon_and_workers_shut_down_cleanly(self) -> None:
        started: list[str] = []

        async def worker() -> None:
            started.append("up")
            await asyncio.sleep(3600)

        workers = WorkerSupervisor()
        workers.register(WorkerSpec("long", worker))
        daemon = SecurityDaemon(
            config=DaemonConfig(
                health_interval_seconds=0.01,
                tunnel_interval_seconds=0.01,
                heartbeat_interval_seconds=0.01,
                max_iterations=2,
                shutdown_grace_seconds=0.2,
                install_signal_handlers=False,
            ),
            health=HealthMonitor(
                type("R", (), {"name": "s", "read": lambda self: ResourceSnapshot()})()
            ),
            workers=workers,
        )
        state = asyncio.run(daemon.run())

        assert started == ["up"]
        assert state.stopped is True


class TestSystemChangesRequireOptIn:
    def test_vpn_defaults_to_a_dry_run(self) -> None:
        runner = DryRunRunner()
        manager = VpnManager(config=VpnConfig(interface="wg0"), runner=runner)
        status = asyncio.run(manager.status())

        assert status.state is TunnelState.UNKNOWN
        assert "dry run" in status.detail

    def test_killswitch_refuses_an_unsafe_plan_before_touching_the_firewall(self) -> None:
        runner = RecordingRunner()
        unsafe = build_iptables_plan("wg0")  # no endpoint exemption

        try:
            asyncio.run(KillSwitch(runner, LockoutGuard()).apply(unsafe))
        except Exception as exc:  # noqa: BLE001 - asserting the refusal
            assert "never reconnect" in str(exc)
        else:  # pragma: no cover - the guard must refuse
            raise AssertionError("guard should have refused")

        assert runner.calls == []

    def test_a_safe_killswitch_plan_applies_and_releases(self) -> None:
        runner = RecordingRunner()
        switch = KillSwitch(runner, LockoutGuard())
        plan = build_iptables_plan(
            "wg0", endpoints=["203.0.113.5:51820"], admin_cidrs=["198.51.100.0/24"]
        )

        asyncio.run(switch.apply(plan, confirm_within=None))
        assert switch.engaged is True

        asyncio.run(switch.release())
        assert switch.engaged is False
        assert runner.ran("iptables -P OUTPUT ACCEPT")
