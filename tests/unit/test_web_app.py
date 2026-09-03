"""Tests for the dashboard application.

Exercised over the real ASGI interface with ``httpx.ASGITransport`` rather
than Starlette's ``TestClient``, which in current versions pulls an extra
package the project does not depend on.

The two properties that matter most: every route including the WebSocket is
behind auth, and the dashboard cannot authorize a target the server was not
started with.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Mapping
from typing import Any, ClassVar

import httpx

from security_assistant.core.types import RiskLevel
from security_assistant.threat.models import SandboxReport
from security_assistant.web.app import DashboardConfig, create_app, telemetry_pump
from security_assistant.web.auth import SESSION_COOKIE, AuthGate
from security_assistant.web.state import DashboardState
from tests.unit.conftest import run

SECRET = "s" * 48


# --------------------------------------------------------------------------- #
# Injected doubles
# --------------------------------------------------------------------------- #
class Resolver:
    async def resolve(self, name: str, record_type: str) -> list[str]:
        return ["192.0.2.10"] if record_type == "A" else []


class Whois:
    async def lookup(self, domain: str) -> Mapping[str, Any]:
        return {"org": "Acme Widgets Ltd"}


class Tls:
    async def fetch(self, host: str, port: int, *, verify: bool) -> Mapping[str, Any]:
        return {
            "subject": ((("commonName", host),),),
            "subjectAltName": (("DNS", host),),
            "notAfter": "Sep  1 12:00:00 2035 GMT",
        }


class VirusTotal:
    async def report(self, indicator_type: str, indicator: str) -> Mapping[str, Any]:
        return {"data": {"attributes": {"last_analysis_stats": {"malicious": 6}}}}


class Urlscan:
    async def search(self, query: str, *, size: int = 20) -> Mapping[str, Any]:
        return {"results": []}

    async def submit(self, url: str, options: Any) -> Mapping[str, Any]:
        return {"uuid": "x"}

    async def result(self, scan_id: str) -> Mapping[str, Any]:
        return {}


class Inspector:
    async def inspect(self, url: str) -> SandboxReport:
        return SandboxReport(
            initial_url=url,
            final_url="https://collector.example/harvest",
            engine="container",
            status=200,
        )


def config(**overrides: Any) -> DashboardConfig:
    settings: dict[str, Any] = {
        "secret": SECRET,
        "scope_targets": ("example.com", "paypa1.com"),
        "max_risk": RiskLevel.ACTIVE,
    }
    settings.update(overrides)
    return DashboardConfig(**settings)


def context() -> dict[str, Any]:
    return {
        "dns_resolver": Resolver(),
        "whois_client": Whois(),
        "tls_fetcher": Tls(),
        "virustotal_client": VirusTotal(),
        "urlscan_client": Urlscan(),
        "sandbox_inspector": Inspector(),
    }


async def client_for(
    app: Any, *, cookies: dict[str, str] | None = None
) -> AsyncIterator[httpx.AsyncClient]:
    """An ASGI client. Cookies are set on the client, not per request --
    httpx deprecates the per-request form."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://dash", cookies=cookies
    ) as client:
        yield client


def authed_cookies() -> dict[str, str]:
    return {SESSION_COOKIE: AuthGate(SECRET).issue()}


async def authed(app: Any) -> AsyncIterator[httpx.AsyncClient]:
    """A client that has logged in the way a browser does.

    Going through ``/api/login`` rather than injecting a cookie means these
    tests exercise the real session flow, and sidesteps httpx cookie-jar
    domain rules for a synthetic base URL.
    """
    async for client in client_for(app):
        response = await client.post("/api/login", json={"token": SECRET})
        assert response.status_code == 200, "login failed in test setup"
        yield client


def call(coro: Any) -> Any:
    return run(coro)


# --------------------------------------------------------------------------- #
class TestAuthenticationGate:
    GUARDED: ClassVar[list[str]] = [
        "/api/state",
        "/api/graph",
        "/api/assets",
        "/api/scans",
        "/api/vpn",
        "/api/killswitch",
        "/api/console",
        "/api/health",
        "/api/leaks",
        "/api/graph/export/json",
        "/api/graph/export/cypher",
    ]

    def test_every_data_route_requires_auth(self) -> None:
        app = create_app(config(), context=context())

        async def scenario() -> list[tuple[str, int]]:
            out = []
            async for c in client_for(app):
                for path in self.GUARDED:
                    out.append((path, (await c.get(path)).status_code))
            return out

        for path, code in call(scenario()):
            assert code == 401, f"{path} was not guarded"

    def test_every_mutating_route_requires_auth(self) -> None:
        app = create_app(config(), context=context())
        posts = {
            "/api/scan/url": {"url": "https://paypa1.com/x"},
            "/api/recon/osint": {"target": "example.com"},
            "/api/recon/iot": {"target": "example.com"},
            "/api/vpn": {"action": "connect"},
            "/api/killswitch": {"engage": True},
            "/api/agent/run": {"goal": "g", "target": "example.com"},
        }

        async def scenario() -> list[tuple[str, int]]:
            out = []
            async for c in client_for(app):
                for path, body in posts.items():
                    out.append((path, (await c.post(path, json=body)).status_code))
            return out

        for path, code in call(scenario()):
            assert code == 401, f"{path} was not guarded"

    def test_index_is_served_but_reveals_no_data(self) -> None:
        app = create_app(config(), context=context())

        async def scenario() -> httpx.Response:
            async for c in client_for(app):
                return await c.get("/")
            raise AssertionError

        response = call(scenario())
        assert response.status_code == 200
        assert "RESTRICTED CONSOLE" in response.text
        # The shell must not embed the scope or any finding.
        assert "paypa1.com" not in response.text

    def test_login_with_the_right_token_sets_a_session(self) -> None:
        app = create_app(config(), context=context())

        async def scenario() -> httpx.Response:
            async for c in client_for(app):
                return await c.post("/api/login", json={"token": SECRET})
            raise AssertionError

        response = call(scenario())
        assert response.status_code == 200
        assert SESSION_COOKIE in response.cookies

    def test_login_with_a_wrong_token_is_rejected(self) -> None:
        app = create_app(config(), context=context())

        async def scenario() -> httpx.Response:
            async for c in client_for(app):
                return await c.post("/api/login", json={"token": "x" * 48})
            raise AssertionError

        assert call(scenario()).status_code == 401

    def test_bearer_token_works_without_a_cookie(self) -> None:
        app = create_app(config(), context=context())

        async def scenario() -> httpx.Response:
            async for c in client_for(app):
                return await c.get("/api/state", headers={"Authorization": f"Bearer {SECRET}"})
            raise AssertionError

        assert call(scenario()).status_code == 200

    def test_session_cookie_grants_access(self) -> None:
        app = create_app(config(), context=context())

        async def scenario() -> httpx.Response:
            async for c in authed(app):
                return await c.get("/api/state")
            raise AssertionError

        assert call(scenario()).status_code == 200

    def test_a_cookie_signed_by_another_secret_is_rejected(self) -> None:
        app = create_app(config(), context=context())
        forged = AuthGate("z" * 48).issue()

        async def scenario() -> httpx.Response:
            async for c in client_for(app):
                c.cookies.set(SESSION_COOKIE, forged, domain="dash")
                return await c.get("/api/state")
            raise AssertionError

        assert call(scenario()).status_code == 401


class TestSecurityHeaders:
    def test_csp_forbids_external_origins(self) -> None:
        """The page vendors nothing, so no CDN needs allowing."""
        app = create_app(config(), context=context())

        async def scenario() -> httpx.Response:
            async for c in client_for(app):
                return await c.get("/")
            raise AssertionError

        csp = call(scenario()).headers["content-security-policy"]
        assert "default-src 'none'" in csp
        assert "frame-ancestors 'none'" in csp
        assert "https://" not in csp

    def test_clickjacking_and_sniffing_headers(self) -> None:
        app = create_app(config(), context=context())

        async def scenario() -> httpx.Response:
            async for c in client_for(app):
                return await c.get("/")
            raise AssertionError

        headers = call(scenario()).headers
        assert headers["x-frame-options"] == "DENY"
        assert headers["x-content-type-options"] == "nosniff"
        assert headers["cache-control"] == "no-store"

    def test_api_docs_are_disabled(self) -> None:
        app = create_app(config(), context=context())

        async def scenario() -> list[int]:
            async for c in client_for(app):
                return [(await c.get(p)).status_code for p in ("/docs", "/openapi.json")]
            raise AssertionError

        assert all(code == 404 for code in call(scenario()))


class TestScopeIsNotWidenable:
    def test_a_target_outside_the_server_scope_is_denied(self) -> None:
        """The browser cannot authorize what the operator did not."""
        app = create_app(config(scope_targets=("example.com",)), context=context())

        async def scenario() -> dict[str, Any]:
            async for c in authed(app):
                response = await c.post(
                    "/api/scan/url",
                    json={"url": "https://not-authorized.test/x"},
                )
                return response.json()
            raise AssertionError

        payload = call(scenario())
        assert payload["denied"]
        assert payload["risk_score"] == 0.0

    def test_an_in_scope_target_runs(self) -> None:
        app = create_app(config(), context=context())

        async def scenario() -> dict[str, Any]:
            async for c in authed(app):
                response = await c.post(
                    "/api/scan/url",
                    json={"url": "https://paypa1.com/login"},
                )
                return response.json()
            raise AssertionError

        payload = call(scenario())
        assert payload["risk_score"] > 0
        assert not payload["denied"]

    def test_empty_scope_denies_everything(self) -> None:
        app = create_app(config(scope_targets=()), context=context())

        async def scenario() -> dict[str, Any]:
            async for c in authed(app):
                response = await c.post(
                    "/api/recon/osint",
                    json={"target": "example.com"},
                )
                return response.json()
            raise AssertionError

        assert call(scenario())["denied"]

    def test_passive_scope_excludes_active_tools(self) -> None:
        app = create_app(config(max_risk=RiskLevel.PASSIVE), context=context())

        async def scenario() -> dict[str, Any]:
            async for c in authed(app):
                response = await c.post(
                    "/api/scan/url",
                    json={"url": "https://paypa1.com/login"},
                )
                return response.json()
            raise AssertionError

        payload = call(scenario())
        assert payload["sandbox"] is None


class TestPanels:
    def test_osint_run_populates_the_graph(self) -> None:
        app = create_app(config(), context=context())

        async def scenario() -> tuple[dict[str, Any], dict[str, Any]]:
            async for c in authed(app):
                run_response = await c.post(
                    "/api/recon/osint",
                    json={"target": "example.com"},
                )
                graph = await c.get("/api/graph")
                return run_response.json(), graph.json()
            raise AssertionError

        result, graph = call(scenario())
        assert result["stats"]["entities"] > 0
        assert graph["nodes"]
        assert any(n["data"]["type"] == "domain" for n in graph["nodes"])

    def test_entity_inspection(self) -> None:
        app = create_app(config(), context=context())

        async def scenario() -> httpx.Response:
            async for c in authed(app):
                await c.post(
                    "/api/recon/osint",
                    json={"target": "example.com"},
                )
                return await c.get("/api/graph/entity/domain:example.com")
            raise AssertionError

        response = call(scenario())
        assert response.status_code == 200
        assert response.json()["entity"]["key"] == "domain:example.com"

    def test_unknown_entity_is_404(self) -> None:
        app = create_app(config(), context=context())

        async def scenario() -> int:
            async for c in authed(app):
                r = await c.get("/api/graph/entity/domain:nope.test")
                return r.status_code
            raise AssertionError

        assert call(scenario()) == 404

    def test_graph_exports(self) -> None:
        app = create_app(config(), context=context())

        async def scenario() -> tuple[httpx.Response, httpx.Response]:
            async for c in authed(app):
                await c.post(
                    "/api/recon/osint",
                    json={"target": "example.com"},
                )
                return (
                    await c.get("/api/graph/export/json"),
                    await c.get("/api/graph/export/cypher"),
                )
            raise AssertionError

        as_json, as_cypher = call(scenario())
        assert "attachment" in as_json.headers["content-disposition"]
        assert "MERGE" in as_cypher.text

    def test_vpn_status_is_a_dry_run_by_default(self) -> None:
        app = create_app(config(), context=context())

        async def scenario() -> dict[str, Any]:
            async for c in authed(app):
                return (await c.get("/api/vpn")).json()
            raise AssertionError

        payload = call(scenario())
        assert payload["executed"] is False
        assert payload["state"] == "unknown"

    def test_agent_console_dispatches_within_scope(self) -> None:
        app = create_app(config(), context=context())

        async def scenario() -> dict[str, Any]:
            async for c in authed(app):
                response = await c.post(
                    "/api/agent/run",
                    json={"goal": "Map surface", "target": "example.com"},
                )
                return response.json()
            raise AssertionError

        payload = call(scenario())
        assert payload["status"] in {"succeeded", "partial", "failed"}
        assert payload["succeeded"]


class TestKillSwitchRoute:
    def test_lockout_guard_refusal_becomes_a_400_not_an_applied_rule(self) -> None:
        """The guard runs on the web path exactly as on the CLI."""
        app = create_app(config(), context=context())

        async def scenario() -> httpx.Response:
            async for c in authed(app):
                # No endpoint known, so the plan lacks the VPN exemption.
                return await c.post("/api/killswitch", json={"engage": True})
            raise AssertionError

        response = call(scenario())
        assert response.status_code == 400
        assert "never reconnect" in response.json()["detail"]

    def test_engaging_with_an_endpoint_succeeds(self) -> None:
        app = create_app(config(), context=context())

        async def scenario() -> dict[str, Any]:
            async for c in authed(app):
                response = await c.post(
                    "/api/killswitch",
                    json={"engage": True, "endpoint": "203.0.113.5:51820"},
                )
                return response.json()
            raise AssertionError

        assert call(scenario())["engaged"] is True

    def test_release(self) -> None:
        app = create_app(config(), context=context())

        async def scenario() -> dict[str, Any]:
            async for c in authed(app):
                await c.post(
                    "/api/killswitch",
                    json={"engage": True, "endpoint": "203.0.113.5:51820"},
                )
                response = await c.post("/api/killswitch", json={"engage": False})
                return response.json()
            raise AssertionError

        assert call(scenario())["engaged"] is False


class TestTelemetryPump:
    def test_samples_health_and_tunnel_into_state(self) -> None:
        from security_assistant.daemon import HealthMonitor, ResourceSnapshot

        class Reader:
            name = "static"

            def read(self) -> ResourceSnapshot:
                return ResourceSnapshot(cpu_percent=12.0, memory_percent=30.0, disk_percent=40.0)

        state = DashboardState()
        call(telemetry_pump(state, health=HealthMonitor(Reader()), interval=0, iterations=1))

        assert state.health["overall"] == "ok"

    def test_a_failing_sampler_does_not_stop_the_pump(self) -> None:
        class Broken:
            async def check(self) -> Any:
                raise OSError("no /proc")

        state = DashboardState()
        call(telemetry_pump(state, health=Broken(), interval=0, iterations=2))
        assert state.health == {}


class TestValidation:
    def test_rejects_an_overlong_url(self) -> None:
        app = create_app(config(), context=context())

        async def scenario() -> int:
            async for c in authed(app):
                r = await c.post("/api/scan/url", json={"url": "x" * 5000})
                return r.status_code
            raise AssertionError

        assert call(scenario()) == 422

    def test_rejects_an_unknown_vpn_action(self) -> None:
        app = create_app(config(), context=context())

        async def scenario() -> int:
            async for c in authed(app):
                r = await c.post("/api/vpn", json={"action": "obliterate"})
                return r.status_code
            raise AssertionError

        assert call(scenario()) == 422
