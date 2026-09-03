"""Tests for leak validation and emitted privilege grants.

The rule under test throughout the leak checks: a check that could not run
reports UNKNOWN, never OK. Reporting an unperformed check as a pass is how an
operator ends up trusting protection they do not have.
"""

from __future__ import annotations

import pytest

from security_assistant.network.commands import CommandResult, DryRunRunner, RecordingRunner
from security_assistant.network.leaks import (
    LeakStatus,
    LeakValidator,
    parse_resolvectl_dns,
)
from security_assistant.network.privileges import (
    PrivilegeGrant,
    grants_for_killswitch,
    grants_for_wireguard,
    launchd_plist,
    plan_for,
    sudoers_file,
    sudoers_rules,
    systemd_unit,
)
from tests.unit.conftest import run

RESOLVECTL = """\
Global
       Protocols: -LLMNR -mDNS
Link 2 (eth0)
    DNS Servers: 192.168.1.1 8.8.8.8
Link 5 (wg0)
    DNS Servers: 10.2.0.1
"""


class FakeProbe:
    def __init__(self, address: str = "", error: Exception | None = None) -> None:
        self.address = address
        self.error = error

    async def public_ip(self) -> str:
        if self.error is not None:
            raise self.error
        return self.address


def checks(report) -> dict:  # type: ignore[no-untyped-def]
    return {c.name: c for c in report.checks}


class TestPublicIpCheck:
    def test_unchanged_address_is_a_leak(self) -> None:
        validator = LeakValidator(RecordingRunner(), FakeProbe("203.0.113.9"))
        report = run(validator.validate("wg0", baseline_ip="203.0.113.9"))
        assert checks(report)["public_ip"].status is LeakStatus.LEAK
        assert report.leaking is True

    def test_changed_address_is_ok(self) -> None:
        validator = LeakValidator(RecordingRunner(), FakeProbe("198.51.100.7"))
        report = run(validator.validate("wg0", baseline_ip="203.0.113.9"))
        assert checks(report)["public_ip"].status is LeakStatus.OK

    def test_missing_baseline_is_unknown_not_ok(self) -> None:
        validator = LeakValidator(RecordingRunner(), FakeProbe("198.51.100.7"))
        report = run(validator.validate("wg0"))
        check = checks(report)["public_ip"]
        assert check.status is LeakStatus.UNKNOWN
        assert "baseline" in check.detail

    def test_probe_failure_is_unknown_not_ok(self) -> None:
        validator = LeakValidator(RecordingRunner(), FakeProbe(error=OSError("no net")))
        report = run(validator.validate("wg0", baseline_ip="203.0.113.9"))
        assert checks(report)["public_ip"].status is LeakStatus.UNKNOWN

    def test_no_probe_configured_is_unknown(self) -> None:
        report = run(LeakValidator(RecordingRunner()).validate("wg0"))
        assert checks(report)["public_ip"].status is LeakStatus.UNKNOWN


class TestDefaultRouteCheck:
    def test_route_via_tunnel_is_ok(self) -> None:
        runner = RecordingRunner(
            results={
                "ip route": CommandResult(
                    argv=(), returncode=0, stdout="default dev wg0 scope link", executed=True
                )
            }
        )
        report = run(LeakValidator(runner).validate("wg0"))
        assert checks(report)["default_route"].status is LeakStatus.OK

    def test_route_bypassing_tunnel_is_a_leak(self) -> None:
        runner = RecordingRunner(
            results={
                "ip route": CommandResult(
                    argv=(),
                    returncode=0,
                    stdout="default via 192.168.1.1 dev eth0",
                    executed=True,
                )
            }
        )
        report = run(LeakValidator(runner).validate("wg0"))
        check = checks(report)["default_route"]
        assert check.status is LeakStatus.LEAK
        assert "bypasses the tunnel" in check.detail

    def test_dry_run_is_unknown(self) -> None:
        report = run(LeakValidator(DryRunRunner()).validate("wg0"))
        assert checks(report)["default_route"].status is LeakStatus.UNKNOWN


class TestDnsCheck:
    def test_parses_resolvectl_per_link(self) -> None:
        parsed = parse_resolvectl_dns(RESOLVECTL)
        assert parsed["eth0"] == ["192.168.1.1", "8.8.8.8"]
        assert parsed["wg0"] == ["10.2.0.1"]

    def test_resolver_outside_expected_set_is_a_leak(self) -> None:
        runner = RecordingRunner(
            results={
                "resolvectl": CommandResult(argv=(), returncode=0, stdout=RESOLVECTL, executed=True)
            }
        )
        report = run(LeakValidator(runner).validate("wg0", expected_dns=["10.2.0.1"]))
        check = checks(report)["dns"]
        assert check.status is LeakStatus.LEAK
        assert "8.8.8.8" in check.observed

    def test_only_expected_resolvers_is_ok(self) -> None:
        output = "Link 5 (wg0)\n    DNS Servers: 10.2.0.1\n"
        runner = RecordingRunner(
            results={
                "resolvectl": CommandResult(argv=(), returncode=0, stdout=output, executed=True)
            }
        )
        report = run(LeakValidator(runner).validate("wg0", expected_dns=["10.2.0.1"]))
        assert checks(report)["dns"].status is LeakStatus.OK

    def test_public_resolver_off_tunnel_is_a_leak_without_expectations(self) -> None:
        output = "Link 2 (eth0)\n    DNS Servers: 8.8.8.8\n"
        runner = RecordingRunner(
            results={
                "resolvectl": CommandResult(argv=(), returncode=0, stdout=output, executed=True)
            }
        )
        report = run(LeakValidator(runner).validate("wg0"))
        assert checks(report)["dns"].status is LeakStatus.LEAK

    def test_no_resolvers_reported_is_unknown(self) -> None:
        runner = RecordingRunner(
            results={"resolvectl": CommandResult(argv=(), returncode=0, stdout="", executed=True)}
        )
        report = run(LeakValidator(runner).validate("wg0"))
        assert checks(report)["dns"].status is LeakStatus.UNKNOWN


class TestVerdict:
    def test_inconclusive_is_not_protected(self) -> None:
        """The whole point: unknown must never read as safe."""
        report = run(LeakValidator(DryRunRunner()).validate("wg0"))
        assert report.leaking is False
        assert report.verdict == "inconclusive"
        assert report.inconclusive

    def test_leaking_wins_over_inconclusive(self) -> None:
        runner = RecordingRunner(
            results={
                "ip route": CommandResult(
                    argv=(), returncode=0, stdout="default dev eth0", executed=True
                )
            }
        )
        report = run(LeakValidator(runner).validate("wg0"))
        assert report.verdict == "leaking"

    def test_serializes(self) -> None:
        payload = run(LeakValidator(DryRunRunner()).validate("wg0")).to_dict()
        assert payload["verdict"] in {"protected", "leaking", "inconclusive"}
        assert len(payload["checks"]) == 3


class TestPrivilegeGrants:
    def test_wireguard_grants_are_argument_bound(self) -> None:
        """`NOPASSWD: wg-quick` would allow bringing up ANY config; binding
        the arguments makes the grant 'may bring up wg0'."""
        grants = grants_for_wireguard("wg0")
        commands = [g.sudoers_command() for g in grants]
        assert any(c.endswith("wg-quick up wg0") for c in commands)
        assert all("wg0" in c for c in commands)

    def test_firewall_grants_are_flagged_high_risk(self) -> None:
        assert all(g.high_risk for g in grants_for_killswitch())
        assert not any(g.high_risk for g in grants_for_wireguard("wg0"))

    def test_sudoers_rules_mark_high_risk_lines(self) -> None:
        rules = sudoers_rules("svc", grants_for_killswitch())
        assert all("HIGH RISK" in r for r in rules)

    def test_sudoers_file_warns_about_firewall_grants(self) -> None:
        text = sudoers_file("svc", [*grants_for_wireguard("wg0"), *grants_for_killswitch()])
        assert "!! HIGH RISK !!" in text
        assert "close to a grant of root" in text
        assert "visudo -c -f" in text

    def test_sudoers_file_without_firewall_has_no_warning(self) -> None:
        text = sudoers_file("svc", grants_for_wireguard("wg0"))
        assert "HIGH RISK" not in text

    def test_rejects_a_bad_user_name(self) -> None:
        with pytest.raises(ValueError, match="Invalid system user"):
            sudoers_rules("root; rm -rf /", grants_for_wireguard("wg0"))

    def test_uses_absolute_paths(self) -> None:
        # A bare name would let a binary earlier on PATH satisfy the rule.
        for rule in sudoers_rules("svc", grants_for_wireguard("wg0")):
            command = rule.split("NOPASSWD:")[1].strip()
            assert command.startswith("/")

    def test_grant_without_arguments_is_just_the_path(self) -> None:
        assert PrivilegeGrant("nft").sudoers_command().endswith("nft")


class TestServiceTemplates:
    def test_systemd_unit_is_hardened(self) -> None:
        unit = systemd_unit()
        for directive in (
            "NoNewPrivileges=yes",
            "ProtectSystem=strict",
            "PrivateTmp=yes",
            "CapabilityBoundingSet=CAP_NET_ADMIN",
            "RestrictSUIDSGID=yes",
        ):
            assert directive in unit

    def test_systemd_unit_does_not_run_as_root(self) -> None:
        assert "User=root" not in systemd_unit()
        assert "User=security-assistant" in systemd_unit()

    def test_systemd_unit_restarts_on_failure(self) -> None:
        assert "Restart=on-failure" in systemd_unit()

    def test_launchd_plist_is_valid_xml(self) -> None:
        import xml.etree.ElementTree as ET

        ET.fromstring(launchd_plist())

    def test_plan_for_wireguard_without_killswitch(self) -> None:
        plan = plan_for(backend="wireguard", interface="wg0")
        assert plan.includes_firewall is False
        assert "HIGH RISK" not in plan.sudoers()

    def test_plan_for_openvpn(self) -> None:
        plan = plan_for(backend="openvpn", interface="tun0")
        assert any("openvpn-client@tun0" in g.sudoers_command() for g in plan.grants)
