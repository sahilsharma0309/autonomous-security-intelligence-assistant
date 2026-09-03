"""FastAPI application for the operations dashboard.

Routes are grouped by panel: graph, assets, threat, network, and the agent
console. A single WebSocket at ``/ws`` carries telemetry to the browser.

**Authentication guards everything, including the WebSocket.** A dependency
runs on every route, and the socket verifies before accepting. It is easy to
protect the HTML and forget the socket that streams the same data; that is
checked by an explicit test.

**The dashboard cannot widen an engagement's scope.** Every operation goes
through the same :class:`AuthorizationScope` the CLI uses, taken from server
configuration -- not from the request body. A browser form cannot authorize a
target the operator did not, which is the property that keeps a UI from
becoming a way around the safety model.

**System-changing routes stay opt-in.** VPN and kill-switch endpoints run
through the same dry-run-by-default runner as everything else, and return
``executed: false`` unless the server was started with execution enabled.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from fastapi import (
    Depends,
    FastAPI,
    HTTPException,
    Request,
    Response,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field

from security_assistant.core import (
    Agent,
    AgentConfig,
    AuthorizationScope,
    RiskLevel,
    ToolRegistry,
)
from security_assistant.iot import ALL_IOT_TOOLS
from security_assistant.network import (
    DryRunRunner,
    KillSwitch,
    LockoutGuard,
    SubprocessRunner,
    VpnConfig,
    VpnManager,
    build_iptables_plan,
)
from security_assistant.osint import ALL_COLLECTORS, Correlator
from security_assistant.threat import ALL_THREAT_TOOLS
from security_assistant.web.auth import (
    SESSION_COOKIE,
    AuthGate,
    is_loopback,
    token_from_headers,
)
from security_assistant.web.state import DashboardState, drain
from security_assistant.web.ui import render_index

logger = logging.getLogger(__name__)

__all__ = ["DashboardConfig", "create_app"]


@dataclass(slots=True)
class DashboardConfig:
    """How the dashboard server behaves."""

    secret: str
    host: str = "127.0.0.1"
    port: int = 8443

    scope_targets: tuple[str, ...] = ()
    """Authorized targets. Empty authorizes nothing, so a dashboard started
    without a scope can look at itself and run nothing."""

    max_risk: RiskLevel = RiskLevel.ACTIVE
    authorization_reference: str = "dashboard-session"

    execute: bool = False
    """Allow real system commands (VPN, firewall). Off by default."""

    allow_static_fallback: bool = False
    vpn_interface: str = "wg0"
    vpn_backend: str = "wireguard"
    admin_cidrs: tuple[str, ...] = ()
    telemetry_interval: float = 2.0

    def scope(self) -> AuthorizationScope:
        return AuthorizationScope(
            allow=list(self.scope_targets),
            max_risk=self.max_risk,
            authorization_reference=self.authorization_reference,
            engagement="dashboard",
        )

    @property
    def loopback_only(self) -> bool:
        return is_loopback(self.host)


# --------------------------------------------------------------------------- #
# Request models
# --------------------------------------------------------------------------- #
class LoginRequest(BaseModel):
    token: str = Field(min_length=1, max_length=512)


class ScanRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)


class ReconRequest(BaseModel):
    target: str = Field(min_length=1, max_length=253)


class IotRequest(BaseModel):
    target: str = Field(min_length=1, max_length=253)
    query: str = Field(default="", max_length=512)


class VpnRequest(BaseModel):
    action: str = Field(pattern="^(status|connect|disconnect|reconnect)$")


class KillSwitchRequest(BaseModel):
    engage: bool
    endpoint: str = Field(default="", max_length=128)


class AgentRequest(BaseModel):
    goal: str = Field(min_length=1, max_length=512)
    target: str = Field(min_length=1, max_length=253)


@dataclass(slots=True)
class _Runtime:
    """Server-side objects shared by the routes."""

    config: DashboardConfig
    gate: AuthGate
    state: DashboardState
    registry: ToolRegistry
    killswitch: KillSwitch
    context: dict[str, Any] = field(default_factory=dict)
    telemetry_task: asyncio.Task[None] | None = None


def create_app(
    config: DashboardConfig,
    *,
    state: DashboardState | None = None,
    context: Mapping[str, Any] | None = None,
    registry: ToolRegistry | None = None,
) -> FastAPI:
    """Build the dashboard application.

    ``context`` is the provider bag every module already uses, so a caller
    (and every test) can inject fakes for DNS, Shodan, VirusTotal, the
    sandbox and the command runner without the app knowing the difference.
    """
    gate = AuthGate(config.secret, loopback_only=config.loopback_only)

    if registry is None:
        registry = ToolRegistry("dashboard")
        registry.register_all(ALL_COLLECTORS)
        registry.register_all(ALL_IOT_TOOLS)
        registry.register_all(ALL_THREAT_TOOLS)

    runner = SubprocessRunner() if config.execute else DryRunRunner()
    runtime = _Runtime(
        config=config,
        gate=gate,
        state=state or DashboardState(),
        registry=registry,
        killswitch=KillSwitch(runner, LockoutGuard(required_admin_cidrs=tuple(config.admin_cidrs))),
        context={
            "allow_static_fallback": config.allow_static_fallback,
            **(dict(context) if context else {}),
        },
    )

    app = FastAPI(
        title="Security Assistant — Operations Dashboard",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.runtime = runtime

    # -- auth ------------------------------------------------------------- #
    def require_session(request: Request) -> None:
        """Reject anything without a valid session or bearer token."""
        if gate.verify_session(request.cookies.get(SESSION_COOKIE)):
            return
        if gate.verify_token(token_from_headers(dict(request.headers))):
            return
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    guarded = [Depends(require_session)]

    @app.middleware("http")
    async def security_headers(request: Request, call_next: Any) -> Response:
        """Headers that limit what a compromised panel could do.

        The page vendors nothing, so the policy can forbid every external
        origin outright rather than carving out a CDN exception. That matters
        more here than on a normal page: script running in this document can
        engage a kill-switch and dispatch agent runs.
        """
        response: Response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Cache-Control", "no-store")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'none'; "
            # The CSS and JS are inlined into the single served document.
            "script-src 'unsafe-inline'; "
            "style-src 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "form-action 'none'; "
            "base-uri 'none'; "
            "frame-ancestors 'none'",
        )
        return response

    # -- pages ------------------------------------------------------------ #
    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request) -> HTMLResponse:
        """The dashboard shell. Rendered unauthenticated; every data route
        behind it requires a session, so the page shows a login gate."""
        authed = gate.verify_session(request.cookies.get(SESSION_COOKIE)) is not None
        return HTMLResponse(render_index(authenticated=authed, config=config))

    @app.post("/api/login")
    async def login(body: LoginRequest, response: Response) -> dict[str, Any]:
        if not gate.verify_token(body.token):
            # Same message and shape for every failure: nothing here should
            # help an attacker distinguish "wrong token" from anything else.
            raise HTTPException(status_code=401, detail="invalid token")
        response.set_cookie(
            SESSION_COOKIE,
            gate.issue(),
            httponly=True,
            samesite="strict",
            secure=gate.cookie_secure,
            max_age=43200,
        )
        return {"authenticated": True}

    @app.post("/api/logout")
    async def logout(response: Response) -> dict[str, Any]:
        response.delete_cookie(SESSION_COOKIE)
        return {"authenticated": False}

    # -- overview --------------------------------------------------------- #
    @app.get("/api/state", dependencies=guarded)
    async def get_state() -> dict[str, Any]:
        payload = runtime.state.snapshot()
        payload["config"] = {
            "scope": list(config.scope_targets),
            "max_risk": str(config.max_risk),
            "execute": config.execute,
            "interface": config.vpn_interface,
            "loopback_only": config.loopback_only,
        }
        return payload

    @app.get("/api/health", dependencies=guarded)
    async def get_health() -> dict[str, Any]:
        return runtime.state.health

    # -- graph ------------------------------------------------------------ #
    @app.get("/api/graph", dependencies=guarded)
    async def get_graph(limit: int = 500) -> dict[str, Any]:
        return runtime.state.graph_payload(limit=max(1, min(limit, 2000)))

    @app.get("/api/graph/entity/{key:path}", dependencies=guarded)
    async def get_entity(key: str) -> dict[str, Any]:
        detail = runtime.state.entity_detail(key)
        if detail is None:
            raise HTTPException(status_code=404, detail="entity not found")
        return detail

    @app.get("/api/graph/export/json", dependencies=guarded)
    async def export_json() -> Response:
        return Response(
            content=runtime.state.graph.to_json(),
            media_type="application/json",
            headers={"Content-Disposition": 'attachment; filename="graph.json"'},
        )

    @app.get("/api/graph/export/cypher", dependencies=guarded)
    async def export_cypher() -> PlainTextResponse:
        statements = runtime.state.graph.to_cypher()
        lines = [
            f"// {i + 1}/{len(statements)}\n{s['query']};\n// params: {s['parameters']}"
            for i, s in enumerate(statements)
        ]
        return PlainTextResponse(
            "\n\n".join(lines),
            headers={"Content-Disposition": 'attachment; filename="graph.cypher"'},
        )

    @app.post("/api/recon/osint", dependencies=guarded)
    async def run_osint(body: ReconRequest) -> dict[str, Any]:
        agent = Agent(runtime.registry, config.scope(), config=AgentConfig(name="dash-osint"))
        runtime.state.log(f"$ recon osint {body.target}")
        result = await agent.run(
            "Map the external surface", target=body.target, context=runtime.context
        )
        values = result.values_by_tool()
        stats = runtime.state.ingest_graph_payloads(values.values())
        report = Correlator().correlate(runtime.state.graph)

        runtime.state.log(
            f"  {result.status.value}: {stats['entities']} entities, {len(report.merged)} merged"
        )
        runtime.state.record_event("recon.completed", {"target": body.target, **stats})
        return {
            "status": result.status.value,
            "stats": stats,
            "merged": len(report.merged),
            "denied": [r.tool_name for r in result.denied],
        }

    # -- assets ----------------------------------------------------------- #
    @app.get("/api/assets", dependencies=guarded)
    async def get_assets() -> dict[str, Any]:
        return {"assets": list(runtime.state.assets), "count": len(runtime.state.assets)}

    @app.post("/api/recon/iot", dependencies=guarded)
    async def run_iot(body: IotRequest) -> dict[str, Any]:
        agent = Agent(runtime.registry, config.scope(), config=AgentConfig(name="dash-iot"))
        runtime.state.log(f"$ recon iot {body.target}")
        context = dict(runtime.context)
        if body.query:
            context["query"] = body.query

        result = await agent.run("Discover assets", target=body.target, context=context)
        values = result.values_by_tool()

        devices: list[Mapping[str, Any]] = []
        for payload in values.values():
            if isinstance(payload, Mapping):
                devices.extend(payload.get("devices", []) or [])
        added = runtime.state.record_assets(devices)
        runtime.state.ingest_graph_payloads(values.values())

        runtime.state.log(f"  {result.status.value}: {added} asset(s)")
        return {
            "status": result.status.value,
            "assets": added,
            "denied": [r.tool_name for r in result.denied],
        }

    # -- threat ----------------------------------------------------------- #
    @app.get("/api/scans", dependencies=guarded)
    async def get_scans() -> dict[str, Any]:
        return {"scans": list(runtime.state.scans)}

    @app.post("/api/scan/url", dependencies=guarded)
    async def scan_url(body: ScanRequest) -> dict[str, Any]:
        agent = Agent(runtime.registry, config.scope(), config=AgentConfig(name="dash-scan"))
        runtime.state.log(f"$ scan url {body.url}")
        runtime.state.broadcaster.publish("scan.started", {"url": body.url})

        result = await agent.run("Assess this URL", target=body.url, context=runtime.context)
        values = result.values_by_tool()
        scored = values.get("threat.url_score") or values.get("threat.url_analyze") or {}
        runtime.state.ingest_graph_payloads(values.values())

        entry = runtime.state.record_scan(
            {
                "url": body.url,
                "status": result.status.value,
                "risk_score": scored.get("risk_score", 0.0),
                "risk_band": scored.get("risk_band", "unknown"),
                "findings": scored.get("findings", []),
                "sandbox": scored.get("sandbox"),
                "denied": [r.tool_name for r in result.denied],
            }
        )
        runtime.state.log(f"  {entry['risk_band']} ({entry['risk_score']}/100)")
        return entry

    # -- network ---------------------------------------------------------- #
    @app.get("/api/vpn", dependencies=guarded)
    async def vpn_status() -> dict[str, Any]:
        manager = _vpn(config, runner)
        payload = (await manager.status()).to_dict()
        payload["executed"] = config.execute
        runtime.state.update_tunnel(payload)
        return payload

    @app.post("/api/vpn", dependencies=guarded)
    async def vpn_action(body: VpnRequest) -> dict[str, Any]:
        manager = _vpn(config, runner)
        runtime.state.log(f"$ vpn {body.action}")

        if body.action == "connect":
            status_obj = await manager.connect()
        elif body.action == "disconnect":
            status_obj = await manager.disconnect()
        elif body.action == "reconnect":
            status_obj = await manager.reconnect()
        else:
            status_obj = await manager.status()

        payload = status_obj.to_dict()
        payload["executed"] = config.execute
        runtime.state.update_tunnel(payload)
        runtime.state.log(f"  {payload['state']} ({payload['detail']})")
        return payload

    @app.get("/api/killswitch", dependencies=guarded)
    async def killswitch_status() -> dict[str, Any]:
        return runtime.killswitch.state.to_dict()

    @app.post("/api/killswitch", dependencies=guarded)
    async def killswitch_toggle(body: KillSwitchRequest) -> dict[str, Any]:
        """Engage or release the kill-switch.

        The lockout guard still runs here exactly as it does on the CLI: a
        plan that would sever the operator's own access is refused, and the
        refusal is returned as a 400 with its reason rather than being
        applied and then regretted.
        """
        if not body.engage:
            state_payload = (await runtime.killswitch.release()).to_dict()
            runtime.state.update_killswitch(state_payload)
            runtime.state.log("$ killswitch release")
            return state_payload

        endpoint = body.endpoint or str(runtime.state.tunnel.get("endpoint", ""))
        try:
            plan = build_iptables_plan(
                config.vpn_interface,
                endpoints=[endpoint] if endpoint else [],
                admin_cidrs=list(config.admin_cidrs),
            )
            applied = await runtime.killswitch.apply(plan, confirm_within=None)
        except Exception as exc:
            runtime.state.log(f"  killswitch refused: {exc}")
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        payload = applied.to_dict()
        payload["executed"] = config.execute
        runtime.state.update_killswitch(payload)
        runtime.state.log(f"$ killswitch engage ({len(plan.rules)} rules)")
        return payload

    @app.get("/api/leaks", dependencies=guarded)
    async def leak_status() -> dict[str, Any]:
        return runtime.state.leaks

    # -- agent console ---------------------------------------------------- #
    @app.post("/api/agent/run", dependencies=guarded)
    async def agent_run(body: AgentRequest) -> dict[str, Any]:
        agent = Agent(runtime.registry, config.scope(), config=AgentConfig(name="dash-agent"))
        runtime.state.log(f"$ agent run '{body.goal}' --target {body.target}")

        result = await agent.run(body.goal, target=body.target, context=runtime.context)
        values = result.values_by_tool()
        runtime.state.ingest_graph_payloads(values.values())

        for tool_result in result.results:
            runtime.state.log(f"  [{tool_result.status.value:>8}] {tool_result.tool_name}")

        payload = {
            "status": result.status.value,
            "tools": sorted(values),
            "succeeded": [r.tool_name for r in result.succeeded],
            "failed": [r.tool_name for r in result.failures],
            "denied": [r.tool_name for r in result.denied],
        }
        runtime.state.record_event("agent.completed", payload)
        return payload

    @app.get("/api/console", dependencies=guarded)
    async def console_log() -> dict[str, Any]:
        return {"lines": list(runtime.state.console_log)[-500:]}

    # -- websocket -------------------------------------------------------- #
    @app.websocket("/ws")
    async def telemetry(websocket: WebSocket) -> None:
        """Stream telemetry frames.

        Authenticates *before* accepting: it is easy to protect the HTTP
        routes and leave the socket that streams the same data open.
        """
        cookie = websocket.cookies.get(SESSION_COOKIE)
        header_token = token_from_headers(dict(websocket.headers))
        if gate.verify_session(cookie) is None and not gate.verify_token(header_token):
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return

        await websocket.accept()
        queue = runtime.state.broadcaster.subscribe()
        try:
            await websocket.send_json({"kind": "snapshot", "payload": runtime.state.snapshot()})
            while True:
                frame = await drain(queue, timeout=config.telemetry_interval)
                if frame is None:
                    # Keepalive: proves the socket is alive and lets a proxy
                    # with an idle timeout leave it open.
                    await websocket.send_json({"kind": "ping", "payload": {}})
                    continue
                await websocket.send_json(frame)
        except WebSocketDisconnect:
            pass
        except Exception:  # noqa: BLE001 - a broken socket must not kill the app
            logger.debug("Telemetry socket closed with an error", exc_info=True)
        finally:
            runtime.state.broadcaster.unsubscribe(queue)

    @app.exception_handler(404)
    async def not_found(request: Request, exc: Any) -> JSONResponse:
        return JSONResponse({"detail": "not found"}, status_code=404)

    return app


def _vpn(config: DashboardConfig, runner: Any) -> VpnManager:
    return VpnManager(
        config=VpnConfig(interface=config.vpn_interface, backend=config.vpn_backend),
        runner=runner,
    )


async def telemetry_pump(
    state: DashboardState,
    *,
    health: Any = None,
    tunnel: Any = None,
    interval: float = 5.0,
    iterations: int | None = None,
) -> None:
    """Periodically sample health and tunnel state into the dashboard.

    Runs as a background task alongside the server so the UI updates without
    the browser polling. Bounded by ``iterations`` for tests.
    """
    count = 0
    while iterations is None or count < iterations:
        count += 1
        if health is not None:
            try:
                report = await health.check()
                state.update_health(report.to_dict())
            except Exception:  # noqa: BLE001 - a bad sample must not stop the pump
                logger.debug("Health sample failed", exc_info=True)
        if tunnel is not None:
            try:
                status_obj = await tunnel.tick()
                state.update_tunnel(status_obj.to_dict())
            except Exception:  # noqa: BLE001 - a bad sample must not stop the pump
                logger.debug("Tunnel sample failed", exc_info=True)
        if iterations is None or count < iterations:
            await asyncio.sleep(interval)


def registry_names(registry: ToolRegistry) -> Sequence[str]:
    """Tool names, for the console's autocomplete."""
    return registry.names
