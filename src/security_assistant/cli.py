"""Unified command-line interface.

Wires all five modules into one entry point::

    security-assistant scan url https://suspicious.example/login
    security-assistant recon osint example.com
    security-assistant recon iot 'product:"IP Camera"' --target example.com
    security-assistant vpn status
    security-assistant vpn connect
    security-assistant run-daemon

Two conventions run through every command.

**Command logic is separate from presentation.** Each command's work lives in
an ``async def run_*`` function that returns a plain dictionary; the Typer
callback only renders it. That means the behaviour is testable without a
terminal, ``--json`` is free, and a rendering bug cannot change what the tool
actually did.

**Dangerous things are opt-in at the command line.** Nothing executes a system
command without ``--execute``; the sandbox will not silently degrade without
``--allow-static-fallback``; autonomous reconnection can be turned off with
``--no-auto-reconnect``. The defaults are the safe reading of each choice, and
the help text says what the flag actually costs.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Mapping, Sequence
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from security_assistant.core import (
    Agent,
    AgentConfig,
    AuthorizationScope,
    RiskLevel,
    ToolRegistry,
)
from security_assistant.daemon import (
    DaemonConfig,
    HealthMonitor,
    SecurityDaemon,
    TcpLatencyProbe,
    WorkerSupervisor,
)
from security_assistant.iot import ALL_IOT_TOOLS
from security_assistant.network import (
    DryRunRunner,
    SubprocessRunner,
    TunnelSupervisor,
    VpnConfig,
    VpnManager,
    plan_for,
)
from security_assistant.osint import ALL_COLLECTORS, Correlator, build_graph_from_payloads
from security_assistant.threat import ALL_THREAT_TOOLS

logger = logging.getLogger(__name__)

console = Console()
err_console = Console(stderr=True)

app = typer.Typer(
    name="security-assistant",
    help="Autonomous Security & Intelligence Assistant.",
    no_args_is_help=True,
    add_completion=False,
)
scan_app = typer.Typer(name="scan", help="Threat analysis of URLs.", no_args_is_help=True)
recon_app = typer.Typer(name="recon", help="OSINT and asset reconnaissance.", no_args_is_help=True)
vpn_app = typer.Typer(name="vpn", help="VPN tunnel lifecycle.", no_args_is_help=True)
app.add_typer(scan_app)
app.add_typer(recon_app)
app.add_typer(vpn_app)

__all__ = [
    "app",
    "build_scope",
    "dashboard",
    "main",
    "run_iot_recon",
    "run_osint_recon",
    "run_url_scan",
    "run_vpn_action",
]


# --------------------------------------------------------------------------- #
# Shared helpers
# --------------------------------------------------------------------------- #
def build_scope(
    targets: Sequence[str],
    max_risk: str = "active",
    authorization: str = "",
) -> AuthorizationScope:
    """Build an engagement scope from CLI arguments.

    An empty target list authorizes nothing, which is what makes forgetting
    ``--scope`` a refusal rather than an unbounded scan.
    """
    return AuthorizationScope(
        allow=list(targets),
        max_risk=RiskLevel.parse(max_risk),
        authorization_reference=authorization or "cli-session",
        engagement="cli",
    )


def _registry(*tool_groups: Sequence[Any]) -> ToolRegistry:
    registry = ToolRegistry("cli")
    for group in tool_groups:
        registry.register_all(group)
    return registry


def _emit(payload: Mapping[str, Any], as_json: bool) -> None:
    if as_json:
        console.print_json(json.dumps(payload, default=str))


def _fail(message: str, code: int = 1) -> None:
    err_console.print(f"[bold red]error:[/bold red] {message}")
    raise typer.Exit(code)


def _risk_style(band: str) -> str:
    return {
        "benign": "green",
        "low": "green",
        "suspicious": "yellow",
        "high": "red",
        "critical": "bold red",
    }.get(band, "white")


# --------------------------------------------------------------------------- #
# scan url
# --------------------------------------------------------------------------- #
async def run_url_scan(
    target: str,
    *,
    scope_targets: Sequence[str] = (),
    max_risk: str = "active",
    allow_static_fallback: bool = False,
    brands: Sequence[str] = (),
) -> dict[str, Any]:
    """Assess a URL with the threat module. Returns a plain payload."""
    from urllib.parse import urlsplit

    host = (urlsplit(target).hostname or "").strip()
    allowed = list(scope_targets) or ([host] if host else [])

    agent = Agent(
        _registry(ALL_THREAT_TOOLS),
        build_scope(allowed, max_risk),
        config=AgentConfig(name="cli-scan"),
    )
    result = await agent.run(
        "Assess this URL",
        target=target,
        context={
            "allow_static_fallback": allow_static_fallback,
            "protected_brands": list(brands),
        },
    )
    values = result.values_by_tool()
    scored = values.get("threat.url_score") or values.get("threat.url_analyze") or {}

    return {
        "target": target,
        "status": result.status.value,
        "risk_score": scored.get("risk_score", 0.0),
        "risk_band": scored.get("risk_band", "unknown"),
        "findings": scored.get("findings", []),
        "tools_run": sorted(values),
        "denied": [r.tool_name for r in result.denied],
        "failures": [r.tool_name for r in result.failures],
    }


@scan_app.command("url")
def scan_url(
    target: Annotated[str, typer.Argument(help="URL to assess.")],
    scope: Annotated[
        list[str] | None,
        typer.Option("--scope", help="Authorized hosts. Defaults to the URL's own host."),
    ] = None,
    max_risk: Annotated[
        str, typer.Option("--max-risk", help="passive | active | intrusive.")
    ] = "active",
    allow_static_fallback: Annotated[
        bool,
        typer.Option(
            "--allow-static-fallback",
            help=(
                "Permit HTTP-only inspection when no container runtime is "
                "available. Executes no scripts, so behavioural findings are "
                "NOT collected. Off by default: the sandbox fails closed "
                "rather than silently losing isolation."
            ),
        ),
    ] = False,
    brand: Annotated[
        list[str] | None,
        typer.Option("--brand", help="Extra brand domains to check for imitation."),
    ] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Emit JSON only.")] = False,
) -> None:
    """Analyze a URL for phishing, reputation and sandbox findings."""
    payload = asyncio.run(
        run_url_scan(
            target,
            scope_targets=scope or [],
            max_risk=max_risk,
            allow_static_fallback=allow_static_fallback,
            brands=brand or [],
        )
    )

    if as_json:
        _emit(payload, True)
        return

    band = str(payload["risk_band"])
    console.print(
        Panel(
            f"[{_risk_style(band)}]{payload['risk_score']}/100  ({band})[/]",
            title=f"Threat assessment: {target}",
            expand=False,
        )
    )

    findings = payload["findings"]
    if findings:
        table = Table("severity", "code", "detail", title="Findings")
        for finding in findings[:20]:
            table.add_row(
                str(finding.get("severity", "")),
                str(finding.get("code", "")),
                str(finding.get("detail", ""))[:80],
            )
        console.print(table)
    else:
        console.print("[green]No findings.[/green]")

    if payload["denied"]:
        console.print(f"[yellow]Denied by scope:[/yellow] {payload['denied']}")
    if payload["failures"]:
        console.print(f"[yellow]Failed:[/yellow] {payload['failures']}")


# --------------------------------------------------------------------------- #
# recon osint / iot
# --------------------------------------------------------------------------- #
async def run_osint_recon(
    target: str,
    *,
    max_risk: str = "active",
    correlate: bool = True,
) -> dict[str, Any]:
    """Collect OSINT for a domain and build the entity graph."""
    agent = Agent(
        _registry(ALL_COLLECTORS),
        build_scope([target], max_risk),
        config=AgentConfig(name="cli-osint"),
    )
    result = await agent.run("Map the external surface", target=target)
    values = result.values_by_tool()
    graph = build_graph_from_payloads(values.values())

    correlation: dict[str, Any] = {}
    if correlate and len(graph):
        correlation = Correlator().correlate(graph).to_dict()

    stats = graph.stats()
    return {
        "target": target,
        "status": result.status.value,
        "tools_run": sorted(values),
        "entities": stats.entities,
        "relationships": stats.relationships,
        "entities_by_type": stats.entities_by_type,
        "merged": len(correlation.get("merged", [])),
        "denied": [r.tool_name for r in result.denied],
        "graph": graph.to_dict(),
    }


@recon_app.command("osint")
def recon_osint(
    target: Annotated[str, typer.Argument(help="Domain to investigate.")],
    max_risk: Annotated[str, typer.Option("--max-risk")] = "active",
    no_correlate: Annotated[
        bool, typer.Option("--no-correlate", help="Skip entity resolution.")
    ] = False,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Collect OSINT and build an entity graph."""
    payload = asyncio.run(run_osint_recon(target, max_risk=max_risk, correlate=not no_correlate))
    if as_json:
        _emit(payload, True)
        return

    table = Table("metric", "value", title=f"OSINT: {target}")
    table.add_row("entities", str(payload["entities"]))
    table.add_row("relationships", str(payload["relationships"]))
    table.add_row("merged duplicates", str(payload["merged"]))
    table.add_row("tools run", ", ".join(payload["tools_run"]) or "-")
    console.print(table)

    by_type = payload["entities_by_type"]
    if by_type:
        breakdown = Table("type", "count", title="Entities by type")
        for name, count in sorted(by_type.items()):
            breakdown.add_row(name, str(count))
        console.print(breakdown)
    if payload["denied"]:
        console.print(f"[yellow]Denied by scope:[/yellow] {payload['denied']}")


async def run_iot_recon(
    query: str,
    *,
    target: str,
    max_risk: str = "passive",
) -> dict[str, Any]:
    """Search for exposed assets.

    ``target`` anchors the search to an authorized engagement: a search query
    is free text and cannot be scope-checked, so the scope applies to the
    asset the engagement is about.
    """
    agent = Agent(
        _registry(ALL_IOT_TOOLS),
        build_scope([target], max_risk),
        config=AgentConfig(name="cli-iot"),
    )
    result = await agent.run("Discover exposed assets", target=target, context={"query": query})
    values = result.values_by_tool()
    devices: list[Any] = []
    for payload in values.values():
        if isinstance(payload, Mapping):
            devices.extend(payload.get("devices", []) or [])

    return {
        "query": query,
        "target": target,
        "status": result.status.value,
        "tools_run": sorted(values),
        "device_count": len(devices),
        "devices": devices[:50],
        "denied": [r.tool_name for r in result.denied],
    }


@recon_app.command("iot")
def recon_iot(
    query: Annotated[str, typer.Argument(help="Search query, e.g. 'product:\"IP Camera\"'.")],
    target: Annotated[
        str, typer.Option("--target", help="Authorized asset this search belongs to.")
    ],
    max_risk: Annotated[str, typer.Option("--max-risk")] = "passive",
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Search for exposed IoT assets within an authorized engagement."""
    payload = asyncio.run(run_iot_recon(query, target=target, max_risk=max_risk))
    if as_json:
        _emit(payload, True)
        return

    console.print(
        Panel(
            f"{payload['device_count']} device(s)",
            title=f"IoT recon: {query}",
            expand=False,
        )
    )
    if payload["devices"]:
        table = Table("address", "class", "services", title="Discovered assets")
        for device in payload["devices"][:25]:
            if not isinstance(device, Mapping):
                continue
            services = device.get("services", []) or []
            table.add_row(
                str(device.get("address", "")),
                str(device.get("device_class", "")),
                str(len(services)),
            )
        console.print(table)
    if payload["denied"]:
        console.print(f"[yellow]Denied by scope:[/yellow] {payload['denied']}")


# --------------------------------------------------------------------------- #
# vpn
# --------------------------------------------------------------------------- #
def _vpn_manager(
    interface: str, backend: str, *, execute: bool, auto_reconnect: bool
) -> VpnManager:
    runner = SubprocessRunner() if execute else DryRunRunner()
    config = VpnConfig(interface=interface, backend=backend, auto_reconnect=auto_reconnect)
    return VpnManager(config=config, runner=runner)


async def run_vpn_action(
    action: str,
    *,
    interface: str = "wg0",
    backend: str = "wireguard",
    execute: bool = False,
    auto_reconnect: bool = True,
) -> dict[str, Any]:
    """Perform a VPN action and return its status payload."""
    manager = _vpn_manager(interface, backend, execute=execute, auto_reconnect=auto_reconnect)
    verb = action.strip().lower()

    if verb == "status":
        status = await manager.status()
    elif verb == "connect":
        status = await manager.connect()
    elif verb == "disconnect":
        status = await manager.disconnect()
    elif verb == "reconnect":
        status = await manager.reconnect()
    else:
        raise ValueError(f"Unknown VPN action {action!r}")

    payload = status.to_dict()
    payload["executed"] = execute
    payload["action"] = verb
    return payload


def _vpn_command(action: str, interface: str, backend: str, execute: bool, as_json: bool) -> None:
    try:
        payload = asyncio.run(
            run_vpn_action(action, interface=interface, backend=backend, execute=execute)
        )
    except Exception as exc:  # noqa: BLE001 - surfaced to the operator
        _fail(str(exc))
        return

    if as_json:
        _emit(payload, True)
        return

    state = str(payload["state"])
    colour = {
        "up": "green",
        "connecting": "yellow",
        "degraded": "yellow",
        "down": "red",
        "unknown": "white",
    }.get(state, "white")

    table = Table("field", "value", title=f"VPN {action}: {interface}")
    table.add_row("state", f"[{colour}]{state}[/]")
    table.add_row("backend", str(payload["backend"]))
    table.add_row("endpoint", str(payload["endpoint"]) or "-")
    table.add_row("handshake age", str(payload["handshake_age_seconds"] or "-"))
    table.add_row("detail", str(payload["detail"]))
    console.print(table)

    if not execute:
        console.print(
            "[yellow]dry run:[/yellow] nothing was executed. Pass --execute to "
            "apply changes (requires the sudoers grants from "
            "`security-assistant privileges`)."
        )


@vpn_app.command("status")
def vpn_status(
    interface: Annotated[str, typer.Option("--interface", "-i")] = "wg0",
    backend: Annotated[str, typer.Option("--backend")] = "wireguard",
    execute: Annotated[bool, typer.Option("--execute", help="Actually query the system.")] = False,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Show tunnel state, including whether the handshake is stale."""
    _vpn_command("status", interface, backend, execute, as_json)


@vpn_app.command("connect")
def vpn_connect(
    interface: Annotated[str, typer.Option("--interface", "-i")] = "wg0",
    backend: Annotated[str, typer.Option("--backend")] = "wireguard",
    execute: Annotated[bool, typer.Option("--execute")] = False,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Bring the tunnel up."""
    _vpn_command("connect", interface, backend, execute, as_json)


@vpn_app.command("disconnect")
def vpn_disconnect(
    interface: Annotated[str, typer.Option("--interface", "-i")] = "wg0",
    backend: Annotated[str, typer.Option("--backend")] = "wireguard",
    execute: Annotated[bool, typer.Option("--execute")] = False,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Bring the tunnel down."""
    _vpn_command("disconnect", interface, backend, execute, as_json)


# --------------------------------------------------------------------------- #
# privileges
# --------------------------------------------------------------------------- #
@app.command("privileges")
def privileges(
    user: Annotated[str, typer.Option("--user")] = "security-assistant",
    interface: Annotated[str, typer.Option("--interface", "-i")] = "wg0",
    backend: Annotated[str, typer.Option("--backend")] = "wireguard",
    killswitch: Annotated[
        bool,
        typer.Option(
            "--killswitch",
            help="Include firewall grants. These are broad; read the warning.",
        ),
    ] = False,
    systemd: Annotated[
        bool, typer.Option("--systemd", help="Emit a systemd unit instead of sudoers.")
    ] = False,
) -> None:
    """Print the sudoers grants or systemd unit needed to run privileged actions.

    Prints to stdout; it installs nothing. Review it, then install it yourself.
    """
    plan = plan_for(user=user, backend=backend, interface=interface, killswitch=killswitch)
    console.print(plan.systemd() if systemd else plan.sudoers(), highlight=False)


# --------------------------------------------------------------------------- #
# dashboard
# --------------------------------------------------------------------------- #
@app.command("dashboard")
def dashboard(
    host: Annotated[
        str, typer.Option("--host", help="Bind address. Loopback by default.")
    ] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port", help="Bind port.")] = 8443,
    scope: Annotated[
        list[str] | None,
        typer.Option("--scope", help="Authorized targets. Empty authorizes nothing."),
    ] = None,
    max_risk: Annotated[str, typer.Option("--max-risk")] = "active",
    execute: Annotated[
        bool,
        typer.Option(
            "--execute",
            help=(
                "Allow real VPN/firewall commands. Refused when combined with a non-loopback bind."
            ),
        ),
    ] = False,
    allow_static_fallback: Annotated[bool, typer.Option("--allow-static-fallback")] = False,
    interface: Annotated[str, typer.Option("--interface", "-i")] = "wg0",
    backend: Annotated[str, typer.Option("--backend")] = "wireguard",
    admin_cidr: Annotated[
        list[str] | None,
        typer.Option("--admin-cidr", help="Networks the kill-switch must preserve."),
    ] = None,
    open_browser: Annotated[
        bool, typer.Option("--open-browser", help="Open a browser once bound.")
    ] = False,
) -> None:
    """Serve the private web operations dashboard.

    Requires DASHBOARD_SECRET_KEY. The console dispatches agent runs and can
    change VPN and firewall state, so it refuses to start unauthenticated.
    """
    from security_assistant.web import build_config, describe_startup, serve
    from security_assistant.web.auth import AuthError, generate_secret
    from security_assistant.web.server import ServerError

    logging.basicConfig(level=logging.INFO, format="%(levelname)-8s %(name)s: %(message)s")

    try:
        settings = build_config(
            host=host,
            port=port,
            scope=tuple(scope or []),
            max_risk=max_risk,
            execute=execute,
            allow_static_fallback=allow_static_fallback,
            interface=interface,
            backend=backend,
            admin_cidrs=tuple(admin_cidr or []),
        )
    except AuthError as exc:
        err_console.print(f"[bold red]error:[/bold red] {exc}")
        err_console.print(
            f"\n[dim]For example:[/dim]\n  export DASHBOARD_SECRET_KEY={generate_secret()}"
        )
        raise typer.Exit(2) from exc
    except ServerError as exc:
        _fail(str(exc), 2)
        return

    console.print(
        Panel(
            "\n".join(describe_startup(settings)),
            title="security-assistant dashboard",
            expand=False,
        )
    )
    if not settings.loopback_only:
        console.print(
            "[yellow]warning:[/yellow] bound off-loopback. Put TLS and a reverse "
            "proxy in front of it and restrict the source range."
        )

    serve(settings, open_browser=open_browser)


# --------------------------------------------------------------------------- #
# run-daemon
# --------------------------------------------------------------------------- #
@app.command("run-daemon")
def run_daemon(
    interface: Annotated[str, typer.Option("--interface", "-i")] = "wg0",
    backend: Annotated[str, typer.Option("--backend")] = "wireguard",
    execute: Annotated[
        bool, typer.Option("--execute", help="Allow the daemon to run system commands.")
    ] = False,
    no_auto_reconnect: Annotated[
        bool,
        typer.Option(
            "--no-auto-reconnect",
            help=(
                "Monitor the tunnel but never repair it. Faults are reported "
                "and left for an operator."
            ),
        ),
    ] = False,
    health_interval: Annotated[float, typer.Option("--health-interval")] = 30.0,
    tunnel_interval: Annotated[float, typer.Option("--tunnel-interval")] = 15.0,
    iterations: Annotated[
        int | None,
        typer.Option("--iterations", help="Stop after N loops (for testing)."),
    ] = None,
    config: Annotated[str | None, typer.Option("--config", help="Path to a config file.")] = None,
) -> None:
    """Run the background daemon: health, tunnel supervision, worker recovery."""
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)-8s %(name)s: %(message)s"
    )
    if config:
        console.print(f"[dim]config: {config}[/dim]")

    manager = _vpn_manager(
        interface,
        backend,
        execute=execute,
        auto_reconnect=not no_auto_reconnect,
    )
    daemon = SecurityDaemon(
        config=DaemonConfig(
            health_interval_seconds=health_interval,
            tunnel_interval_seconds=tunnel_interval,
            max_iterations=iterations,
        ),
        health=HealthMonitor(latency_probe=TcpLatencyProbe()),
        tunnel=TunnelSupervisor(manager),
        workers=WorkerSupervisor(),
    )

    console.print(
        Panel(
            f"interface={interface} backend={backend}\n"
            f"auto-reconnect={'off' if no_auto_reconnect else 'on'}  "
            f"execute={'yes' if execute else 'no (dry run)'}",
            title="security-assistant daemon",
            expand=False,
        )
    )

    state = asyncio.run(daemon.run())
    console.print(
        f"[dim]stopped after {state.iterations} iteration(s): "
        f"{state.stop_reason or 'clean exit'}[/dim]"
    )


@app.command("version")
def version() -> None:
    """Print the version."""
    from security_assistant import __version__

    console.print(__version__)


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point. Returns a process exit code."""
    try:
        # With ``standalone_mode=False`` Click handles ``typer.Exit`` itself
        # and *returns* the code instead of raising it. Ignoring the return
        # value here would turn every deliberate failure -- a refused bind, a
        # missing secret -- into exit 0, which a systemd unit or a Makefile
        # would read as success. The ``except`` below stays for the paths that
        # raise before Click's own handler runs.
        result = app(args=list(argv) if argv is not None else None, standalone_mode=False)
    except typer.Exit as exc:
        return int(exc.exit_code)
    except KeyboardInterrupt:  # pragma: no cover - interactive
        err_console.print("[yellow]interrupted[/yellow]")
        return 130
    except Exception as exc:
        err_console.print(f"[bold red]error:[/bold red] {exc}")
        logger.debug("CLI failed", exc_info=True)
        return 1
    return result if isinstance(result, int) else 0
