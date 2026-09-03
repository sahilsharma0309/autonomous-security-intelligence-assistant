"""Tests for the privileged-command boundary.

This module decides what the assistant is allowed to run on the operator's own
machine, so the tests are written around what it must *refuse*.
"""

from __future__ import annotations

import pytest

from security_assistant.network.commands import (
    ALLOWED_BINARIES,
    CommandError,
    CommandResult,
    DryRunRunner,
    Escalation,
    RecordingRunner,
    SubprocessRunner,
    default_runner,
    detect_escalation,
)
from tests.unit.conftest import run


class TestDefaultIsInert:
    def test_default_runner_does_not_execute(self) -> None:
        """Importing and calling this module must change nothing."""
        runner = default_runner()
        assert isinstance(runner, DryRunRunner)

        result = run(runner.run(["wg", "show", "wg0", "dump"]))
        assert result.executed is False
        assert result.ok is True

    def test_dry_run_records_intent(self) -> None:
        runner = DryRunRunner()
        run(runner.run(["wg-quick", "up", "wg0"], privileged=True))
        assert runner.calls == [("wg-quick", "up", "wg0")]

    def test_dry_run_can_script_stdout_for_parser_tests(self) -> None:
        runner = DryRunRunner({"wg": "interface-line\npeer-line"})
        result = run(runner.run(["wg", "show", "wg0", "dump"]))
        assert "peer-line" in result.stdout


class TestBinaryAllowlist:
    @pytest.mark.parametrize("binary", ["bash", "sh", "curl", "python", "rm", "nc", "dd"])
    def test_refuses_binaries_outside_the_allowlist(self, binary: str) -> None:
        """A bug must not be able to turn the privileged path into a shell."""
        with pytest.raises(CommandError, match="not in the allowed binary set"):
            run(DryRunRunner().run([binary, "-c", "echo hi"]))

    @pytest.mark.parametrize("binary", ["wg", "wg-quick", "iptables", "nft", "ip"])
    def test_allows_networking_utilities(self, binary: str) -> None:
        assert run(DryRunRunner().run([binary, "--version"])).ok

    def test_allowlist_contains_no_shell(self) -> None:
        assert not {"sh", "bash", "zsh", "env", "python"} & ALLOWED_BINARIES

    def test_absolute_paths_are_matched_by_basename(self) -> None:
        assert run(DryRunRunner().run(["/usr/bin/wg", "show"])).ok

    def test_refuses_empty_command(self) -> None:
        with pytest.raises(CommandError, match="empty command"):
            run(DryRunRunner().run([]))

    def test_refuses_nul_bytes(self) -> None:
        with pytest.raises(CommandError, match="NUL"):
            run(DryRunRunner().run(["wg", "show\x00evil"]))


class TestNoShellInterpolation:
    def test_metacharacters_are_inert_arguments(self) -> None:
        """An interface name containing a semicolon is a bad argument, not a
        second command, because no shell is ever involved."""
        runner = DryRunRunner()
        run(runner.run(["wg", "show", "wg0; rm -rf /", "dump"]))
        assert runner.calls[0] == ("wg", "show", "wg0; rm -rf /", "dump")


class TestEscalation:
    def test_sudo_prefix_is_non_interactive(self) -> None:
        # -n means a missing sudoers rule fails immediately instead of a
        # daemon hanging forever on a password prompt with no terminal.
        assert Escalation.SUDO.prefix() == ("sudo", "-n")

    def test_pkexec_prefix(self) -> None:
        assert Escalation.PKEXEC.prefix() == ("pkexec",)

    def test_none_prefix_is_empty(self) -> None:
        assert Escalation.NONE.prefix() == ()

    def test_detect_returns_a_valid_method(self) -> None:
        assert detect_escalation() in set(Escalation)

    def test_subprocess_runner_must_be_built_explicitly(self) -> None:
        runner = SubprocessRunner(Escalation.NONE)
        assert runner.escalation is Escalation.NONE


class TestRecordingRunner:
    def test_matches_by_command_prefix(self) -> None:
        runner = RecordingRunner(
            results={"wg show": CommandResult(argv=(), returncode=0, stdout="dump")}
        )
        result = run(runner.run(["wg", "show", "wg0", "dump"]))
        assert result.stdout == "dump"

    def test_check_raises_on_failure(self) -> None:
        runner = RecordingRunner(
            results={"wg-quick": CommandResult(argv=(), returncode=1, stderr="boom")}
        )
        with pytest.raises(CommandError, match="Command failed"):
            run(runner.run(["wg-quick", "up", "wg0"], check=True))

    def test_ran_helper(self) -> None:
        runner = RecordingRunner()
        run(runner.run(["ip", "route", "show"]))
        assert runner.ran("ip route") is True
        assert runner.ran("iptables") is False


class TestCommandResult:
    def test_ok_reflects_returncode(self) -> None:
        assert CommandResult(argv=("wg",), returncode=0).ok
        assert not CommandResult(argv=("wg",), returncode=1).ok

    def test_serializes_and_truncates(self) -> None:
        payload = CommandResult(argv=("wg", "show"), stdout="x" * 10000).to_dict()
        assert payload["command"] == "wg show"
        assert len(payload["stdout"]) <= 4000
