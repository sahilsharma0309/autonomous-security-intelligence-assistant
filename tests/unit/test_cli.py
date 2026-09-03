"""Tests for the unified CLI.

Command logic is tested directly through the ``run_*`` coroutines, and the
Typer bindings through its ``CliRunner``. The property that matters most:
nothing dangerous happens without an explicit flag.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from security_assistant import cli as cli_module
from security_assistant.cli import (
    app,
    build_scope,
    main,
    run_url_scan,
    run_vpn_action,
)
from security_assistant.core.types import RiskLevel
from tests.unit.conftest import run

runner = CliRunner()


class TestScopeConstruction:
    def test_targets_become_the_allow_list(self) -> None:
        scope = build_scope(["example.com"], "active")
        assert scope.permits("example.com", RiskLevel.ACTIVE)

    def test_empty_scope_authorizes_nothing(self) -> None:
        """Forgetting --scope must be a refusal, not an unbounded scan."""
        scope = build_scope([], "active")
        assert not scope.permits("example.com", RiskLevel.PASSIVE)

    def test_max_risk_is_parsed(self) -> None:
        assert build_scope(["x.test"], "passive").max_risk is RiskLevel.PASSIVE
        assert build_scope(["x.test"], "intrusive").max_risk is RiskLevel.INTRUSIVE


class TestVpnCommandLogic:
    def test_status_is_a_dry_run_by_default(self) -> None:
        """The CLI must not touch the system unless asked."""
        payload = run(run_vpn_action("status", interface="wg0"))
        assert payload["executed"] is False
        assert payload["state"] == "unknown"
        assert "dry run" in payload["detail"]

    def test_connect_is_a_dry_run_by_default(self) -> None:
        payload = run(run_vpn_action("connect", interface="wg0"))
        assert payload["executed"] is False

    def test_unknown_action_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown VPN action"):
            run(run_vpn_action("obliterate"))

    def test_invalid_interface_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="Invalid interface"):
            run(run_vpn_action("status", interface="wg0; rm -rf /"))


class TestScanCommandLogic:
    def test_scopes_to_the_urls_own_host_by_default(self) -> None:
        payload = run(run_url_scan("https://paypa1.com/login"))
        assert payload["status"] in {"succeeded", "partial", "failed"}
        assert payload["risk_score"] > 0
        assert not payload["denied"]

    def test_out_of_scope_url_is_denied(self) -> None:
        payload = run(run_url_scan("https://paypa1.com/login", scope_targets=["other.example"]))
        assert payload["denied"]
        assert payload["risk_score"] == 0.0

    def test_passive_risk_excludes_active_tools(self) -> None:
        payload = run(run_url_scan("https://paypa1.com/login", max_risk="passive"))
        assert "threat.url_inspect" not in payload["tools_run"]

    def test_extra_brands_are_honoured(self) -> None:
        payload = run(
            run_url_scan(
                "https://acmebnk.com/",
                max_risk="passive",
                brands=["acmebank.com"],
            )
        )
        assert any(f["code"] == "typosquat" for f in payload["findings"])


class TestCliBindings:
    def test_help_lists_every_command_group(self) -> None:
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        for command in ("scan", "recon", "vpn", "run-daemon", "privileges"):
            assert command in result.output

    def test_version(self) -> None:
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output

    def test_vpn_status_renders_and_warns_about_dry_run(self) -> None:
        result = runner.invoke(app, ["vpn", "status"])
        assert result.exit_code == 0
        assert "dry run" in result.output

    def test_vpn_status_json(self) -> None:
        import json

        result = runner.invoke(app, ["vpn", "status", "--json"])
        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["executed"] is False

    def test_scan_url_renders(self) -> None:
        result = runner.invoke(app, ["scan", "url", "https://paypa1.com/login"])
        assert result.exit_code == 0
        assert "Threat assessment" in result.output

    def test_scan_url_json(self) -> None:
        import json

        result = runner.invoke(app, ["scan", "url", "https://paypa1.com/login", "--json"])
        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["risk_score"] > 0

    def test_privileges_emits_reviewable_sudoers(self) -> None:
        result = runner.invoke(app, ["privileges", "--interface", "wg0"])
        assert result.exit_code == 0
        assert "NOPASSWD" in result.output
        assert "visudo" in result.output

    def test_privileges_warns_when_firewall_grants_are_requested(self) -> None:
        result = runner.invoke(app, ["privileges", "--killswitch"])
        assert result.exit_code == 0
        assert "HIGH RISK" in result.output

    def test_privileges_systemd(self) -> None:
        result = runner.invoke(app, ["privileges", "--systemd"])
        assert result.exit_code == 0
        assert "NoNewPrivileges=yes" in result.output

    def test_daemon_runs_bounded_iterations(self) -> None:
        result = runner.invoke(app, ["run-daemon", "--iterations", "1"])
        assert result.exit_code == 0
        assert "daemon" in result.output.lower()

    def test_recon_osint_renders(self) -> None:
        result = runner.invoke(app, ["recon", "osint", "example.com", "--max-risk", "passive"])
        assert result.exit_code == 0
        assert "OSINT" in result.output

    def test_no_args_shows_help_not_a_traceback(self) -> None:
        result = runner.invoke(app, [])
        assert "Usage" in result.output


class TestFlagSafetyDefaults:
    def test_static_fallback_is_off_by_default(self) -> None:
        """The sandbox fails closed unless the operator opts in."""
        import inspect

        signature = inspect.signature(cli_module.scan_url)
        assert signature.parameters["allow_static_fallback"].default is False

    def test_execute_is_off_by_default_on_every_vpn_command(self) -> None:
        import inspect

        for command in (
            cli_module.vpn_status,
            cli_module.vpn_connect,
            cli_module.vpn_disconnect,
        ):
            assert inspect.signature(command).parameters["execute"].default is False

    def test_daemon_auto_reconnect_is_on_unless_disabled(self) -> None:
        import inspect

        parameter = inspect.signature(cli_module.run_daemon).parameters["no_auto_reconnect"]
        assert parameter.default is False


class TestMainEntryPoint:
    def test_returns_zero_on_success(self) -> None:
        assert main(["version"]) == 0

    def test_returns_nonzero_on_bad_command(self) -> None:
        assert main(["definitely-not-a-command"]) != 0

    def test_main_module_delegates_to_cli(self) -> None:
        from security_assistant.main import main as module_main

        assert module_main(["version"]) == 0

    def test_a_deliberate_failure_reaches_the_process_exit_code(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A refused start must not exit 0.

        Click handles ``typer.Exit`` itself when ``standalone_mode`` is off and
        returns the code rather than raising it, so ``main`` has to read the
        return value. Otherwise a systemd unit or a Makefile reads a refusal as
        success and never restarts, never alerts.
        """
        monkeypatch.delenv("DASHBOARD_SECRET_KEY", raising=False)
        assert main(["dashboard", "--scope", "example.com"]) == 2
