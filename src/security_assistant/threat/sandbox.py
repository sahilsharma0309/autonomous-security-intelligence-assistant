"""Headless page-load inspection behind a container boundary.

This is the only component in the system that deliberately executes
attacker-controlled content: it renders a page chosen by whoever is being
investigated, running that page's JavaScript. The isolation boundary is
therefore the design, not a detail of it.

**Container isolation (:class:`ContainerSandbox`).** Playwright runs inside a
throwaway Docker container, one per URL, launched with:

* ``--rm`` and a hard ``--stop-timeout`` -- nothing outlives the inspection.
* ``--user`` a non-root uid, ``--cap-drop=ALL``, ``--security-opt
  no-new-privileges`` -- a browser escape lands as an unprivileged user in a
  container that cannot regain privilege.
* ``--read-only`` with a small ``--tmpfs /tmp`` -- no writable image layer.
* ``--network`` a caller-named egress-controlled network, defaulting to one
  the operator is expected to define with no route back to the host or to
  internal ranges. This is what actually contains SSRF; the checks in
  :mod:`security_assistant.threat.safety` are the second layer.
* ``--memory``, ``--pids-limit`` -- a page cannot exhaust the host.
* No bind mounts. Results come back over stdout as JSON, so the container
  never writes to a shared filesystem.

**Timeout and cleanup.** The container is killed on timeout and again in a
``finally`` block, so a hung page or a crashed client cannot leave one
running. The process is awaited after the kill, so no zombie remains.

**Static fallback (:class:`StaticInspector`).** Where Docker is unavailable
the module degrades to an HTTP-only inspector that follows the redirect
chain and reads headers without executing anything. It is genuinely less
capable -- no script-driven redirects, no DOM, no console -- and it says so:
:attr:`SandboxReport.engine` records which inspector ran, so an absent
behavioural finding is never mistaken for a clean result.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import shutil
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable
from urllib.parse import urlsplit

from security_assistant.core.types import utcnow
from security_assistant.threat.models import RedirectHop, SandboxReport
from security_assistant.threat.safety import UnsafeUrlError, assert_fetchable

logger = logging.getLogger(__name__)

_httpx: Any
try:  # pragma: no cover - depends on which extras are installed
    import httpx

    _httpx = httpx
except ImportError:  # pragma: no cover
    _httpx = None

__all__ = [
    "ContainerSandbox",
    "SandboxConfig",
    "SandboxError",
    "SandboxInspector",
    "SandboxUnavailableError",
    "StaticInspector",
    "default_inspector",
    "docker_available",
]

#: Cap on DOM text kept in a report. The DOM is evidence, not a copy of the
#: site, and an unbounded field would put megabytes of attacker-chosen text
#: through logs, memory and the graph.
DOM_EXCERPT_LIMIT = 4096
CONSOLE_MESSAGE_LIMIT = 50
CONSOLE_LINE_LIMIT = 500
MAX_REDIRECT_HOPS = 15


class SandboxError(RuntimeError):
    """Page inspection failed."""


class SandboxUnavailableError(SandboxError):
    """No inspector backend is usable in this environment."""


@dataclass(frozen=True, slots=True)
class SandboxConfig:
    """Container and execution limits for one inspection."""

    image: str = "mcr.microsoft.com/playwright/python:v1.47.0-jammy"
    network: str = "sandbox-egress"
    """Docker network the container joins. The operator is expected to create
    this with egress restricted to the public internet and no route to the
    host or internal ranges."""

    user: str = "1000:1000"
    memory: str = "512m"
    pids_limit: int = 256
    tmpfs_size: str = "64m"
    timeout_seconds: float = 45.0
    """Wall-clock limit for the whole container run."""

    navigation_timeout_ms: int = 20000
    capture_screenshot: bool = True
    docker_binary: str = "docker"
    extra_args: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if self.pids_limit < 1:
            raise ValueError("pids_limit must be >= 1")
        if self.navigation_timeout_ms <= 0:
            raise ValueError("navigation_timeout_ms must be positive")


@runtime_checkable
class SandboxInspector(Protocol):
    """Loads a URL and reports what happened."""

    async def inspect(self, url: str) -> SandboxReport:  # pragma: no cover - protocol declaration
        ...


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:  # pragma: no cover - defensive
        return ""


# The script executed inside the container. It is deliberately small and
# self-contained: it takes a URL on argv, prints one JSON document on stdout,
# and never writes to disk.
_BROWSER_SCRIPT = r"""
import asyncio, base64, json, sys
from playwright.async_api import async_playwright

async def main(url, nav_timeout_ms, want_screenshot):
    report = {
        "final_url": "", "status": 0, "chain": [], "console": [],
        "contacted": [], "dom": "", "title": "", "has_password_input": False,
        "screenshot_b64": "", "errors": [],
    }
    async with async_playwright() as p:
        browser = await p.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
        try:
            # A fresh context per run: no cookies, storage or cache carry
            # between inspections.
            context = await browser.new_context(ignore_https_errors=True)
            page = await context.new_page()

            page.on("console", lambda m: report["console"].append(
                f"{m.type}: {m.text}"[:500]))
            page.on("request", lambda r: report["contacted"].append(r.url))
            page.on("response", lambda r: report["chain"].append(
                {"url": r.url, "status": r.status}))

            try:
                response = await page.goto(url, timeout=nav_timeout_ms,
                                           wait_until="domcontentloaded")
                if response is not None:
                    report["status"] = response.status
            except Exception as exc:
                report["errors"].append(f"navigation: {exc}")

            report["final_url"] = page.url
            try:
                report["title"] = await page.title()
                report["dom"] = await page.content()
                report["has_password_input"] = await page.evaluate(
                    "document.querySelectorAll('input[type=password]').length > 0")
                if want_screenshot:
                    shot = await page.screenshot(full_page=False)
                    report["screenshot_b64"] = base64.b64encode(shot).decode()
            except Exception as exc:
                report["errors"].append(f"capture: {exc}")
        finally:
            await browser.close()
    print(json.dumps(report))

asyncio.run(main(sys.argv[1], int(sys.argv[2]), sys.argv[3] == "1"))
"""


class ContainerSandbox:
    """Runs headless Chromium inside a locked-down throwaway container."""

    __slots__ = ("_config",)

    def __init__(self, config: SandboxConfig | None = None) -> None:
        self._config = config or SandboxConfig()

    @property
    def config(self) -> SandboxConfig:
        return self._config

    def _command(self, url: str) -> list[str]:
        config = self._config
        return [
            config.docker_binary,
            "run",
            "--rm",
            "--interactive",
            f"--network={config.network}",
            f"--user={config.user}",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--read-only",
            f"--tmpfs=/tmp:rw,noexec,nosuid,size={config.tmpfs_size}",
            f"--memory={config.memory}",
            f"--pids-limit={config.pids_limit}",
            # No bind mounts: results return over stdout.
            *config.extra_args,
            config.image,
            "python",
            "-c",
            _BROWSER_SCRIPT,
            url,
            str(config.navigation_timeout_ms),
            "1" if config.capture_screenshot else "0",
        ]

    async def inspect(self, url: str) -> SandboxReport:
        assert_fetchable(url)
        started = utcnow()
        process: asyncio.subprocess.Process | None = None

        try:
            process = await asyncio.create_subprocess_exec(
                *self._command(url),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError as exc:
            raise SandboxUnavailableError(
                f"{self._config.docker_binary} not found; cannot run the container sandbox"
            ) from exc
        except OSError as exc:
            raise SandboxError(f"Could not start sandbox container: {exc}") from exc

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=self._config.timeout_seconds
            )
        except TimeoutError as exc:
            await self._terminate(process)
            raise SandboxError(
                f"Sandbox inspection of {url!r} exceeded "
                f"{self._config.timeout_seconds}s and was killed"
            ) from exc
        finally:
            # Belt and braces: if anything above raised for another reason,
            # the container must still not survive this call.
            await self._terminate(process)

        if process.returncode != 0:
            detail = stderr.decode("utf-8", "replace").strip()[:300]
            raise SandboxError(f"Sandbox container exited {process.returncode}: {detail}")

        elapsed_ms = int((utcnow() - started).total_seconds() * 1000)
        return self._parse(url, stdout, elapsed_ms)

    @staticmethod
    async def _terminate(process: asyncio.subprocess.Process | None) -> None:
        """Kill a container process and reap it, ignoring races."""
        if process is None or process.returncode is not None:
            return
        try:
            process.kill()
        except ProcessLookupError:  # pragma: no cover - already gone
            return
        try:
            await asyncio.wait_for(process.wait(), timeout=5.0)
        except TimeoutError:  # pragma: no cover - defensive
            logger.warning("Sandbox process did not exit after kill")

    def _parse(self, url: str, stdout: bytes, elapsed_ms: int) -> SandboxReport:
        text = stdout.decode("utf-8", "replace").strip()
        if not text:
            raise SandboxError("Sandbox produced no output")
        # The script prints one JSON document last; ignore any leading noise.
        line = text.splitlines()[-1]
        try:
            payload = json.loads(line)
        except ValueError as exc:
            raise SandboxError("Sandbox produced malformed JSON") from exc
        if not isinstance(payload, dict):
            raise SandboxError("Sandbox output was not a JSON object")
        return report_from_payload(url, payload, engine="container", load_ms=elapsed_ms)


def report_from_payload(
    url: str, payload: Mapping[str, Any], *, engine: str, load_ms: int
) -> SandboxReport:
    """Build a :class:`SandboxReport` from the browser script's output.

    Kept separate from the subprocess handling so the mapping from raw
    capture to report is testable without Docker.
    """
    import base64

    dom = str(payload.get("dom", "") or "")
    screenshot_b64 = str(payload.get("screenshot_b64", "") or "")
    screenshot_bytes = b""
    if screenshot_b64:
        try:
            screenshot_bytes = base64.b64decode(screenshot_b64, validate=True)
        except (ValueError, TypeError):
            screenshot_bytes = b""

    chain: list[RedirectHop] = []
    for entry in payload.get("chain", []) or []:
        if not isinstance(entry, Mapping):
            continue
        hop_url = str(entry.get("url", "") or "")
        if not hop_url:
            continue
        status = entry.get("status")
        chain.append(
            RedirectHop(
                url=hop_url,
                status=int(status) if isinstance(status, (int, float)) else 0,
            )
        )
        if len(chain) >= MAX_REDIRECT_HOPS:
            break

    contacted: list[str] = []
    origin = _host_of(url)
    for request_url in payload.get("contacted", []) or []:
        host = _host_of(str(request_url))
        if host and host != origin and host not in contacted:
            contacted.append(host)

    console: list[str] = []
    for message in payload.get("console", []) or []:
        console.append(str(message)[:CONSOLE_LINE_LIMIT])
        if len(console) >= CONSOLE_MESSAGE_LIMIT:
            break

    errors = [str(e)[:300] for e in (payload.get("errors", []) or [])]

    return SandboxReport(
        initial_url=url,
        final_url=str(payload.get("final_url", "") or ""),
        engine=engine,
        chain=chain,
        status=int(payload.get("status", 0) or 0),
        contacted_domains=contacted,
        console_messages=console,
        dom_excerpt=dom[:DOM_EXCERPT_LIMIT],
        dom_sha256=_sha256(dom.encode("utf-8")) if dom else "",
        screenshot_sha256=_sha256(screenshot_bytes) if screenshot_bytes else "",
        screenshot_bytes=len(screenshot_bytes),
        title=str(payload.get("title", "") or "")[:300],
        has_password_input=bool(payload.get("has_password_input", False)),
        load_ms=load_ms,
        errors=errors,
    )


@runtime_checkable
class HttpFetcher(Protocol):
    """Minimal HTTP interface the static inspector needs."""

    async def get(
        self, url: str
    ) -> tuple[int, Mapping[str, str], str]:  # pragma: no cover - protocol
        """Return ``(status, headers, body)`` without following redirects."""
        ...


class HttpxFetcher:
    """Static-inspection fetcher backed by ``httpx``."""

    __slots__ = ("_max_bytes", "_timeout", "_user_agent")

    def __init__(
        self, timeout: float = 15.0, user_agent: str = "", max_bytes: int = 262144
    ) -> None:
        self._timeout = timeout
        self._user_agent = user_agent or "security-assistant-threat/1.0"
        self._max_bytes = max_bytes

    async def get(self, url: str) -> tuple[int, Mapping[str, str], str]:
        if _httpx is None:  # pragma: no cover - guarded by the default factory
            raise SandboxUnavailableError("httpx is not installed")
        async with _httpx.AsyncClient(
            timeout=self._timeout,
            follow_redirects=False,
            headers={"User-Agent": self._user_agent},
        ) as client:
            response = await client.get(url)
            body = response.text[: self._max_bytes]
            return int(response.status_code), dict(response.headers), body


class StaticInspector:
    """HTTP-only inspector: follows redirects, executes nothing.

    The fallback when no container runtime is available. It sees the redirect
    chain, status codes and raw HTML, which is enough for most structural
    findings, and it cannot see anything a script does. Reports are marked
    ``engine="static"`` so that difference is visible downstream.
    """

    __slots__ = ("_fetcher", "_max_hops")

    def __init__(
        self, fetcher: HttpFetcher | None = None, *, max_hops: int = MAX_REDIRECT_HOPS
    ) -> None:
        self._fetcher = fetcher or HttpxFetcher()
        self._max_hops = max_hops

    async def inspect(self, url: str) -> SandboxReport:
        from urllib.parse import urljoin

        started = utcnow()
        assert_fetchable(url)

        report = SandboxReport(initial_url=url, engine="static")
        current = url
        seen: set[str] = set()

        for _ in range(self._max_hops):
            if current in seen:
                report.errors.append(f"redirect loop at {current}")
                break
            seen.add(current)

            try:
                status, headers, body = await self._fetcher.get(current)
            except UnsafeUrlError:
                raise
            except Exception as exc:  # noqa: BLE001 - any transport error
                report.errors.append(f"fetch {current}: {exc}")
                break

            report.chain.append(RedirectHop(url=current, status=status))
            report.status = status
            report.final_url = current

            location = headers.get("location") or headers.get("Location")
            if 300 <= status < 400 and location:
                nxt = urljoin(current, location.strip())
                try:
                    # Each hop is re-checked: a redirect is attacker-controlled
                    # and is the classic way to walk a fetcher into an
                    # internal address.
                    assert_fetchable(nxt)
                except UnsafeUrlError as exc:
                    report.errors.append(f"blocked redirect to {nxt}: {exc}")
                    break
                current = nxt
                continue

            report.dom_excerpt = body[:DOM_EXCERPT_LIMIT]
            report.dom_sha256 = _sha256(body.encode("utf-8")) if body else ""
            report.title = _title_of(body)
            report.has_password_input = 'type="password"' in body.lower() or (
                "type='password'" in body.lower()
            )
            break

        report.load_ms = int((utcnow() - started).total_seconds() * 1000)
        if not report.final_url:
            report.final_url = url
        return report


def _title_of(html: str) -> str:
    """Extract a <title> without an HTML parser dependency."""
    lowered = html.lower()
    start = lowered.find("<title")
    if start == -1:
        return ""
    close = lowered.find(">", start)
    end = lowered.find("</title>", close)
    if close == -1 or end == -1:
        return ""
    return html[close + 1 : end].strip()[:300]


def docker_available(binary: str = "docker") -> bool:
    """Whether a Docker CLI is on PATH."""
    return shutil.which(binary) is not None


def default_inspector(
    config: SandboxConfig | None = None, *, allow_static_fallback: bool = False
) -> SandboxInspector:
    """Pick an inspector, **failing closed** when the container cannot run.

    If no container runtime is available the default is to raise, not to
    quietly degrade. Silently substituting the static inspector would mean an
    operator who believes they are detonating a hostile page behind an
    isolation boundary is in fact fetching it from the host, and the only
    signal would be a field in a report nobody reads. An accidental
    non-isolated execution is exactly what the boundary exists to prevent, so
    losing it has to be a deliberate act.

    Pass ``allow_static_fallback=True`` -- surfaced as ``--allow-static-fallback``
    on the CLI and ``threat.allow_static_fallback`` in config -- to accept the
    degraded, script-free inspection instead.
    """
    settings = config or SandboxConfig()
    if docker_available(settings.docker_binary):
        return ContainerSandbox(settings)

    if not allow_static_fallback:
        raise SandboxUnavailableError(
            f"No container runtime found ({settings.docker_binary!r} is not on "
            "PATH), so the sandbox cannot isolate the page load. Refusing to "
            "fall back silently. Install a container runtime, or pass "
            "--allow-static-fallback (config: threat.allow_static_fallback) to "
            "accept HTTP-only inspection, which executes no scripts and "
            "observes no script-driven behaviour."
        )

    logger.warning(
        "Container runtime unavailable and --allow-static-fallback was given; "
        "using static HTTP inspection. Script-driven behaviour will NOT be "
        "observed, and reports are marked engine='static'."
    )
    return StaticInspector()


def contacted_third_parties(report: SandboxReport) -> Sequence[str]:
    """Hosts the page reached that are not its own."""
    return tuple(report.contacted_domains)
