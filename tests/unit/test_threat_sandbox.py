"""Tests for the sandbox boundary.

The container arguments are asserted individually rather than as a blob:
each one is a specific containment property, and a silent regression in any
of them would weaken isolation without failing anything else.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any, ClassVar

import pytest

from security_assistant.threat.models import SandboxReport
from security_assistant.threat.safety import UnsafeUrlError
from security_assistant.threat.sandbox import (
    DOM_EXCERPT_LIMIT,
    ContainerSandbox,
    SandboxConfig,
    StaticInspector,
    default_inspector,
    docker_available,
    report_from_payload,
)
from tests.unit.conftest import run


class FakeFetcher:
    """Serves canned HTTP responses without a network."""

    def __init__(self, responses: dict[str, tuple[int, dict[str, str], str]]) -> None:
        self.responses = responses
        self.requested: list[str] = []

    async def get(self, url: str) -> tuple[int, Mapping[str, str], str]:
        self.requested.append(url)
        if url not in self.responses:
            raise ConnectionError(f"no canned response for {url}")
        return self.responses[url]


class TestContainerArguments:
    """Each assertion pins one containment property."""

    @staticmethod
    def command(**overrides: Any) -> list[str]:
        config = SandboxConfig(**overrides)
        return ContainerSandbox(config)._command("https://x.test/")

    def test_container_is_removed_after_the_run(self) -> None:
        assert "--rm" in self.command()

    def test_runs_as_a_non_root_user(self) -> None:
        assert "--user=1000:1000" in self.command()

    def test_drops_all_capabilities(self) -> None:
        assert "--cap-drop=ALL" in self.command()

    def test_forbids_privilege_escalation(self) -> None:
        assert "--security-opt=no-new-privileges" in self.command()

    def test_root_filesystem_is_read_only(self) -> None:
        assert "--read-only" in self.command()

    def test_tmp_is_noexec(self) -> None:
        tmpfs = next(a for a in self.command() if a.startswith("--tmpfs="))
        assert "noexec" in tmpfs
        assert "nosuid" in tmpfs

    def test_joins_the_egress_controlled_network(self) -> None:
        assert "--network=sandbox-egress" in self.command()
        assert "--network=custom" in self.command(network="custom")

    def test_memory_and_pid_limits_are_set(self) -> None:
        command = self.command()
        assert "--memory=512m" in command
        assert "--pids-limit=256" in command

    def test_no_bind_mounts(self) -> None:
        """A shared filesystem would be an escape route; results come back
        over stdout instead."""
        assert not any(a.startswith(("-v", "--volume", "--mount")) for a in self.command())

    def test_url_is_passed_as_an_argument_not_interpolated_into_a_shell(self) -> None:
        command = self.command()
        assert command[-3] == "https://x.test/"
        assert not any(part == "sh" or part.endswith("/sh") for part in command)

    def test_config_rejects_nonsense_limits(self) -> None:
        for kwargs in (
            {"timeout_seconds": 0},
            {"pids_limit": 0},
            {"navigation_timeout_ms": 0},
        ):
            with pytest.raises(ValueError):
                SandboxConfig(**kwargs)  # type: ignore[arg-type]


class TestContainerSafetyGate:
    def test_refuses_an_internal_url_before_launching_anything(self) -> None:
        sandbox = ContainerSandbox()
        with pytest.raises(UnsafeUrlError):
            run(sandbox.inspect("http://169.254.169.254/latest/meta-data/"))

    def test_refuses_a_file_url(self) -> None:
        with pytest.raises(UnsafeUrlError):
            run(ContainerSandbox().inspect("file:///etc/passwd"))

    def test_missing_docker_binary_is_reported_clearly(self) -> None:
        sandbox = ContainerSandbox(SandboxConfig(docker_binary="definitely-not-a-binary"))
        with pytest.raises(Exception, match="not found"):
            run(sandbox.inspect("https://example.com/"))


class TestReportParsing:
    PAYLOAD: ClassVar[dict[str, Any]] = {
        "final_url": "https://collector.test/final",
        "status": 200,
        "chain": [
            {"url": "https://a.test/", "status": 302},
            {"url": "https://collector.test/final", "status": 200},
        ],
        "console": ["error: boom"],
        "contacted": [
            "https://a.test/self.js",
            "https://tracker.test/px.gif",
            "https://tracker.test/again.gif",
        ],
        "dom": "<html><title>Sign in</title></html>",
        "title": "Sign in",
        "has_password_input": True,
        "errors": [],
    }

    def test_builds_a_report(self) -> None:
        report = report_from_payload(
            "https://a.test/", self.PAYLOAD, engine="container", load_ms=1234
        )
        assert report.final_url == "https://collector.test/final"
        assert report.engine == "container"
        assert report.load_ms == 1234
        assert report.has_password_input is True
        assert len(report.chain) == 2

    def test_contacted_domains_exclude_the_origin_and_deduplicate(self) -> None:
        report = report_from_payload("https://a.test/", self.PAYLOAD, engine="container", load_ms=0)
        assert report.contacted_domains == ["tracker.test"]

    def test_dom_is_truncated_and_hashed(self) -> None:
        huge = {**self.PAYLOAD, "dom": "x" * (DOM_EXCERPT_LIMIT * 3)}
        report = report_from_payload("https://a.test/", huge, engine="container", load_ms=0)
        assert len(report.dom_excerpt) == DOM_EXCERPT_LIMIT
        # The hash covers the whole DOM even though the excerpt is clipped.
        assert len(report.dom_sha256) == 64

    def test_screenshot_is_recorded_as_a_hash_not_inline_bytes(self) -> None:
        import base64

        payload = {
            **self.PAYLOAD,
            "screenshot_b64": base64.b64encode(b"PNGDATA").decode(),
        }
        report = report_from_payload("https://a.test/", payload, engine="container", load_ms=0)
        assert report.screenshot_bytes == 7
        assert len(report.screenshot_sha256) == 64

    def test_corrupt_screenshot_is_ignored(self) -> None:
        payload = {**self.PAYLOAD, "screenshot_b64": "!!!not base64!!!"}
        report = report_from_payload("https://a.test/", payload, engine="container", load_ms=0)
        assert report.screenshot_bytes == 0

    def test_console_output_is_capped(self) -> None:
        payload = {**self.PAYLOAD, "console": [f"msg {i}" for i in range(500)]}
        report = report_from_payload("https://a.test/", payload, engine="container", load_ms=0)
        assert len(report.console_messages) <= 50

    def test_redirect_chain_is_capped(self) -> None:
        payload = {
            **self.PAYLOAD,
            "chain": [{"url": f"https://a.test/{i}", "status": 302} for i in range(100)],
        }
        report = report_from_payload("https://a.test/", payload, engine="container", load_ms=0)
        assert len(report.chain) <= 15

    def test_malformed_entries_are_skipped(self) -> None:
        payload = {**self.PAYLOAD, "chain": ["not a dict", {"status": 200}]}
        report = report_from_payload("https://a.test/", payload, engine="container", load_ms=0)
        assert report.chain == []


class TestStaticInspector:
    def test_follows_a_redirect_chain(self) -> None:
        fetcher = FakeFetcher(
            {
                "https://a.test/": (302, {"location": "https://b.test/"}, ""),
                "https://b.test/": (200, {}, "<html><title>Done</title></html>"),
            }
        )
        report = run(StaticInspector(fetcher).inspect("https://a.test/"))

        assert report.engine == "static"
        assert report.final_url == "https://b.test/"
        assert [hop.url for hop in report.chain] == ["https://a.test/", "https://b.test/"]
        assert report.title == "Done"

    def test_relative_redirect_is_resolved(self) -> None:
        fetcher = FakeFetcher(
            {
                "https://a.test/x": (301, {"location": "/y"}, ""),
                "https://a.test/y": (200, {}, "ok"),
            }
        )
        report = run(StaticInspector(fetcher).inspect("https://a.test/x"))
        assert report.final_url == "https://a.test/y"

    def test_redirect_into_an_internal_address_is_blocked(self) -> None:
        """A redirect is attacker-controlled: it is the standard way to walk
        a fetcher into somewhere it must not go."""
        fetcher = FakeFetcher(
            {"https://a.test/": (302, {"location": "http://169.254.169.254/"}, "")}
        )
        report = run(StaticInspector(fetcher).inspect("https://a.test/"))

        assert any("blocked redirect" in e for e in report.errors)
        assert "http://169.254.169.254/" not in fetcher.requested

    def test_redirect_loop_terminates(self) -> None:
        fetcher = FakeFetcher(
            {
                "https://a.test/": (302, {"location": "https://b.test/"}, ""),
                "https://b.test/": (302, {"location": "https://a.test/"}, ""),
            }
        )
        report = run(StaticInspector(fetcher).inspect("https://a.test/"))
        assert any("loop" in e for e in report.errors)

    def test_detects_a_password_field(self) -> None:
        fetcher = FakeFetcher(
            {"https://a.test/": (200, {}, '<form><input type="password"></form>')}
        )
        report = run(StaticInspector(fetcher).inspect("https://a.test/"))
        assert report.has_password_input is True

    def test_transport_error_is_recorded_not_raised(self) -> None:
        report = run(StaticInspector(FakeFetcher({})).inspect("https://a.test/"))
        assert report.errors
        assert report.final_url == "https://a.test/"

    def test_refuses_an_unsafe_url_up_front(self) -> None:
        with pytest.raises(UnsafeUrlError):
            run(StaticInspector(FakeFetcher({})).inspect("http://127.0.0.1/"))

    def test_hop_limit_is_respected(self) -> None:
        responses = {
            f"https://a.test/{i}": (302, {"location": f"https://a.test/{i + 1}"}, "")
            for i in range(50)
        }
        report = run(
            StaticInspector(FakeFetcher(responses), max_hops=3).inspect("https://a.test/0")
        )
        assert len(report.chain) <= 3


class TestDefaultInspector:
    def test_fails_closed_when_no_container_runtime_exists(self) -> None:
        """Silently degrading would mean an operator who believes they are
        detonating a hostile page behind an isolation boundary is in fact
        fetching it from the host."""
        from security_assistant.threat.sandbox import SandboxUnavailableError

        with pytest.raises(SandboxUnavailableError, match="Refusing to fall back"):
            default_inspector(SandboxConfig(docker_binary="not-a-real-binary"))

    def test_static_fallback_requires_an_explicit_opt_in(self) -> None:
        inspector = default_inspector(
            SandboxConfig(docker_binary="not-a-real-binary"),
            allow_static_fallback=True,
        )
        assert isinstance(inspector, StaticInspector)

    def test_the_refusal_names_the_flag_that_overrides_it(self) -> None:
        from security_assistant.threat.sandbox import SandboxUnavailableError

        try:
            default_inspector(SandboxConfig(docker_binary="not-a-real-binary"))
        except SandboxUnavailableError as exc:
            assert "--allow-static-fallback" in str(exc)
        else:  # pragma: no cover - must raise
            raise AssertionError("expected a refusal")

    def test_docker_available_probes_path(self) -> None:
        assert docker_available("definitely-not-on-path") is False

    def test_engine_is_recorded_so_reduced_coverage_is_visible(self) -> None:
        report = SandboxReport(initial_url="https://a.test/", engine="static")
        assert report.to_dict()["engine"] == "static"


class TestBrowserScriptShape:
    """The in-container script is a string, so its contract is worth pinning."""

    def test_script_emits_json_on_stdout(self) -> None:
        from security_assistant.threat.sandbox import _BROWSER_SCRIPT

        assert "json.dumps" in _BROWSER_SCRIPT
        assert "print(" in _BROWSER_SCRIPT

    def test_script_uses_a_fresh_context_per_run(self) -> None:
        from security_assistant.threat.sandbox import _BROWSER_SCRIPT

        assert "new_context" in _BROWSER_SCRIPT

    def test_script_closes_the_browser_in_a_finally(self) -> None:
        from security_assistant.threat.sandbox import _BROWSER_SCRIPT

        assert "finally:" in _BROWSER_SCRIPT
        assert "browser.close()" in _BROWSER_SCRIPT

    def test_script_never_writes_to_disk(self) -> None:
        from security_assistant.threat.sandbox import _BROWSER_SCRIPT

        assert "open(" not in _BROWSER_SCRIPT
        assert "path=" not in _BROWSER_SCRIPT

    def test_parsed_output_round_trips(self) -> None:
        payload = {"final_url": "https://x.test/", "status": 200, "chain": [], "dom": ""}
        report = report_from_payload(
            "https://x.test/", json.loads(json.dumps(payload)), engine="container", load_ms=1
        )
        assert report.final_url == "https://x.test/"
