"""Tests for VPN status parsing and the bounded recovery state machine.

The central behaviour under test is that a live interface with a stale
handshake is *not* reported as connected, and that autonomous recovery stops
rather than looping forever.
"""

from __future__ import annotations

import time

import pytest

from security_assistant.network.commands import CommandResult, RecordingRunner
from security_assistant.network.vpn import (
    STALE_HANDSHAKE_SECONDS,
    OpenVpnBackend,
    RecoveryState,
    TunnelState,
    TunnelSupervisor,
    VpnConfig,
    VpnError,
    VpnManager,
    WireGuardBackend,
    backend_for,
    parse_wg_dump,
    summarize,
)
from tests.unit.conftest import run


def wg_dump(handshake_epoch: int) -> str:
    """A realistic two-line `wg show <iface> dump`."""
    interface_line = "privkey\tpubkey\t51820\toff"
    peer_line = f"peerkey\t(none)\t203.0.113.5:51820\t0.0.0.0/0\t{handshake_epoch}\t1024\t2048\t25"
    return f"{interface_line}\n{peer_line}\n"


class TestParseWgDump:
    def test_recent_handshake_is_up(self) -> None:
        status = parse_wg_dump(wg_dump(int(time.time())), "wg0")
        assert status.state is TunnelState.UP
        assert status.connected is True
        assert status.endpoint == "203.0.113.5:51820"
        assert status.allowed_ips == ["0.0.0.0/0"]
        assert status.rx_bytes == 1024

    def test_stale_handshake_is_degraded_not_up(self) -> None:
        """The core distinction: the interface is up, the tunnel is not."""
        stale = int(time.time()) - int(STALE_HANDSHAKE_SECONDS) - 60
        status = parse_wg_dump(wg_dump(stale), "wg0")

        assert status.state is TunnelState.DEGRADED
        assert status.connected is False
        assert "not responding" in status.detail

    def test_no_handshake_yet_is_connecting(self) -> None:
        status = parse_wg_dump(wg_dump(0), "wg0")
        assert status.state is TunnelState.CONNECTING

    def test_empty_output_is_down(self) -> None:
        assert parse_wg_dump("", "wg0").state is TunnelState.DOWN

    def test_interface_without_peer_is_down(self) -> None:
        status = parse_wg_dump("privkey\tpubkey\t51820\toff\n", "wg0")
        assert status.state is TunnelState.DOWN
        assert "no peer" in status.detail

    def test_malformed_dump_is_unknown_not_down(self) -> None:
        # Guessing DOWN from an unparseable dump would be a fabricated fact.
        status = parse_wg_dump("a\tb\nx\ty\n", "wg0")
        assert status.state is TunnelState.UNKNOWN

    def test_none_endpoint_is_blank(self) -> None:
        line = "peerkey\t(none)\t(none)\t(none)\t0\t0\t0\t0"
        status = parse_wg_dump(f"iface\n{line}\n", "wg0")
        assert status.endpoint == ""
        assert status.allowed_ips == []

    def test_serializes_with_truncated_key(self) -> None:
        payload = parse_wg_dump(wg_dump(int(time.time())), "wg0").to_dict()
        assert payload["state"] == "up"
        assert payload["public_key"].endswith("...")


class TestWireGuardBackend:
    def test_status_parses_a_live_dump(self) -> None:
        runner = RecordingRunner(
            results={
                "wg show": CommandResult(
                    argv=(), returncode=0, stdout=wg_dump(int(time.time())), executed=True
                )
            }
        )
        status = run(WireGuardBackend(runner).status("wg0"))
        assert status.state is TunnelState.UP

    def test_missing_interface_is_down(self) -> None:
        runner = RecordingRunner(
            results={
                "wg show": CommandResult(
                    argv=(), returncode=1, stderr="No such device", executed=True
                )
            }
        )
        assert run(WireGuardBackend(runner).status("wg0")).state is TunnelState.DOWN

    def test_dry_run_reports_unknown_not_down(self) -> None:
        """A dry run has no idea what the real state is; saying DOWN would be
        a guess presented as a fact."""
        from security_assistant.network.commands import DryRunRunner

        status = run(WireGuardBackend(DryRunRunner()).status("wg0"))
        assert status.state is TunnelState.UNKNOWN
        assert "dry run" in status.detail

    def test_up_invokes_wg_quick(self) -> None:
        runner = RecordingRunner()
        run(WireGuardBackend(runner).up("wg0"))
        assert runner.ran("wg-quick up wg0")

    def test_down_invokes_wg_quick(self) -> None:
        runner = RecordingRunner()
        run(WireGuardBackend(runner).down("wg0"))
        assert runner.ran("wg-quick down wg0")

    def test_up_failure_raises(self) -> None:
        runner = RecordingRunner(
            results={
                "wg-quick": CommandResult(
                    argv=(), returncode=1, stderr="config missing", executed=True
                )
            }
        )
        with pytest.raises(VpnError, match="wg-quick up"):
            run(WireGuardBackend(runner).up("wg0"))

    @pytest.mark.parametrize("bad", ["wg0; rm -rf /", "", "a" * 40, "eth0 wlan0"])
    def test_rejects_invalid_interface_names(self, bad: str) -> None:
        with pytest.raises(VpnError, match="Invalid interface"):
            run(WireGuardBackend(RecordingRunner()).status(bad))


class TestOpenVpnBackend:
    def test_inactive_unit_is_down(self) -> None:
        runner = RecordingRunner(
            results={
                "systemctl is-active": CommandResult(
                    argv=(), returncode=3, stdout="inactive", executed=True
                )
            }
        )
        assert run(OpenVpnBackend(runner).status("tun0")).state is TunnelState.DOWN

    def test_active_unit_with_interface_is_up(self) -> None:
        runner = RecordingRunner(
            results={
                "systemctl is-active": CommandResult(
                    argv=(), returncode=0, stdout="active", executed=True
                ),
                "ip link": CommandResult(argv=(), returncode=0, executed=True),
            }
        )
        status = run(OpenVpnBackend(runner).status("tun0"))
        assert status.state is TunnelState.UP
        # The weaker evidence must be stated, not implied equal to WireGuard's.
        assert "no handshake counter" in status.detail

    def test_active_unit_without_interface_is_connecting(self) -> None:
        runner = RecordingRunner(
            results={
                "systemctl is-active": CommandResult(
                    argv=(), returncode=0, stdout="active", executed=True
                ),
                "ip link": CommandResult(argv=(), returncode=1, executed=True),
            }
        )
        assert run(OpenVpnBackend(runner).status("tun0")).state is TunnelState.CONNECTING


class TestBackendFactory:
    @pytest.mark.parametrize("name", ["wireguard", "wg", "WireGuard"])
    def test_wireguard_names(self, name: str) -> None:
        assert backend_for(name).name == "wireguard"

    @pytest.mark.parametrize("name", ["openvpn", "ovpn"])
    def test_openvpn_names(self, name: str) -> None:
        assert backend_for(name).name == "openvpn"

    def test_unknown_backend(self) -> None:
        with pytest.raises(VpnError, match="Unknown VPN backend"):
            backend_for("tailscale")


class TestVpnConfig:
    def test_auto_reconnect_defaults_on(self) -> None:
        assert VpnConfig().auto_reconnect is True

    def test_killswitch_defaults_off(self) -> None:
        # Rewriting the host firewall needs a deliberate decision.
        assert VpnConfig().killswitch_enabled is False

    def test_backoff_is_exponential_and_capped(self) -> None:
        config = VpnConfig(reconnect_backoff_seconds=2.0, max_backoff_seconds=20.0)
        assert config.backoff_for(1) == 2.0
        assert config.backoff_for(2) == 4.0
        assert config.backoff_for(3) == 8.0
        assert config.backoff_for(10) == 20.0  # capped

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"max_reconnect_attempts": 0},
            {"reconnect_backoff_seconds": -1},
            {"reconnect_backoff_seconds": 100, "max_backoff_seconds": 10},
            {"interface": "bad name"},
        ],
    )
    def test_rejects_invalid_config(self, kwargs: dict) -> None:
        with pytest.raises(ValueError):
            VpnConfig(**kwargs)


class FakeBackend:
    """A backend whose state the test drives directly."""

    name = "fake"

    def __init__(self, states: list[TunnelState]) -> None:
        self.states = states
        self.index = 0
        self.up_calls = 0
        self.down_calls = 0

    def _next(self) -> TunnelState:
        state = self.states[min(self.index, len(self.states) - 1)]
        return state

    async def status(self, interface: str):  # type: ignore[no-untyped-def]
        from security_assistant.network.vpn import TunnelStatus

        return TunnelStatus(interface=interface, backend=self.name, state=self._next())

    async def up(self, interface: str):  # type: ignore[no-untyped-def]
        from security_assistant.network.vpn import TunnelStatus

        self.up_calls += 1
        self.index += 1
        return TunnelStatus(interface=interface, backend=self.name, state=self._next())

    async def down(self, interface: str):  # type: ignore[no-untyped-def]
        from security_assistant.network.vpn import TunnelStatus

        self.down_calls += 1
        return TunnelStatus(interface=interface, backend=self.name, state=TunnelState.DOWN)


class TestSupervisorStateMachine:
    @staticmethod
    def _supervisor(
        states: list[TunnelState], **config: object
    ) -> tuple[TunnelSupervisor, FakeBackend, list[float]]:
        clock = [0.0]
        backend = FakeBackend(states)
        settings = VpnConfig(
            interface="wg0",
            max_reconnect_attempts=3,
            reconnect_backoff_seconds=1.0,
            **config,  # type: ignore[arg-type]
        )
        supervisor = TunnelSupervisor(VpnManager(backend, settings), clock=lambda: clock[0])
        return supervisor, backend, clock

    def test_healthy_tunnel_needs_no_action(self) -> None:
        supervisor, backend, _ = self._supervisor([TunnelState.UP])
        status = run(supervisor.tick())

        assert status.state is RecoveryState.HEALTHY
        assert backend.up_calls == 0
        assert status.attempts == 0

    def test_down_tunnel_triggers_recovery(self) -> None:
        supervisor, backend, _ = self._supervisor([TunnelState.DOWN])
        run(supervisor.tick())
        assert backend.up_calls == 1

    def test_stale_handshake_triggers_recovery(self) -> None:
        """A DEGRADED tunnel is black-holing traffic; it must be repaired."""
        supervisor, backend, _ = self._supervisor([TunnelState.DEGRADED])
        run(supervisor.tick())
        assert backend.up_calls == 1

    def test_degraded_can_be_left_alone_when_configured(self) -> None:
        supervisor, backend, _ = self._supervisor(
            [TunnelState.DEGRADED], treat_degraded_as_down=False
        )
        run(supervisor.tick())
        assert backend.up_calls == 0

    def test_recovery_succeeds_and_resets_counters(self) -> None:
        supervisor, _backend, _ = self._supervisor([TunnelState.DOWN, TunnelState.UP])
        status = run(supervisor.tick())

        assert status.state is RecoveryState.HEALTHY
        assert status.attempts == 0
        assert status.last_error == ""

    def test_attempts_are_bounded_and_terminate(self) -> None:
        """The whole point: recovery stops and asks for a human."""
        supervisor, backend, clock = self._supervisor([TunnelState.DOWN])

        for _ in range(10):
            status = run(supervisor.tick())
            if status.needs_operator:
                break
            clock[0] += 100

        assert status.state is RecoveryState.NEEDS_OPERATOR
        assert status.attempts == 3
        assert backend.up_calls == 3

    def test_terminal_state_stops_further_attempts(self) -> None:
        supervisor, backend, clock = self._supervisor([TunnelState.DOWN])
        for _ in range(10):
            run(supervisor.tick())
            clock[0] += 100
        attempts_at_terminal = backend.up_calls

        for _ in range(5):
            run(supervisor.tick())
            clock[0] += 100

        assert backend.up_calls == attempts_at_terminal

    def test_backoff_delays_the_next_attempt(self) -> None:
        supervisor, backend, _clock = self._supervisor([TunnelState.DOWN])
        run(supervisor.tick())
        assert backend.up_calls == 1

        # Clock has not advanced: still in backoff, no new attempt.
        status = run(supervisor.tick())
        assert status.state is RecoveryState.BACKOFF
        assert backend.up_calls == 1
        assert status.next_attempt_after > 0

    def test_operator_reset_clears_terminal_state(self) -> None:
        supervisor, _backend, clock = self._supervisor([TunnelState.DOWN])
        for _ in range(10):
            run(supervisor.tick())
            clock[0] += 100
        assert supervisor.status.needs_operator

        status = supervisor.reset()
        assert status.state is RecoveryState.HEALTHY
        assert status.attempts == 0

    def test_auto_reconnect_disabled_reports_without_acting(self) -> None:
        supervisor, backend, _ = self._supervisor([TunnelState.DOWN], auto_reconnect=False)
        status = run(supervisor.tick())

        assert status.state is RecoveryState.DEGRADED
        assert backend.up_calls == 0
        assert "auto-reconnect disabled" in status.last_error

    def test_connecting_is_not_treated_as_a_fault(self) -> None:
        supervisor, backend, _ = self._supervisor([TunnelState.CONNECTING])
        run(supervisor.tick())
        assert backend.up_calls == 0

    def test_status_serializes(self) -> None:
        supervisor, _backend, _ = self._supervisor([TunnelState.UP])
        payload = run(supervisor.tick()).to_dict()
        assert payload["state"] == "healthy"
        assert payload["needs_operator"] is False


class TestManagerHelpers:
    def test_connect_is_idempotent_when_already_up(self) -> None:
        backend = FakeBackend([TunnelState.UP])
        run(VpnManager(backend, VpnConfig()).connect())
        assert backend.up_calls == 0

    def test_reconnect_once_cycles_the_tunnel(self) -> None:
        backend = FakeBackend([TunnelState.DOWN, TunnelState.UP])
        run(VpnManager(backend, VpnConfig()).reconnect_once())
        assert backend.down_calls == 1
        assert backend.up_calls == 1

    def test_summarize_counts_states(self) -> None:
        from security_assistant.network.vpn import TunnelStatus

        result = summarize(
            [
                TunnelStatus("wg0", state=TunnelState.UP),
                TunnelStatus("wg1", state=TunnelState.DEGRADED),
                TunnelStatus("wg2", state=TunnelState.DOWN),
            ]
        )
        assert result == {"total": 3, "connected": 1, "degraded": 1, "down": 1}
