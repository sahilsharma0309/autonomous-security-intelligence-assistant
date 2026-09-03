"""Private web operations dashboard.

A self-hosted FastAPI + WebSocket console over all five modules: OSINT graph
explorer, IoT asset grid, URL detonation HUD, VPN and daemon control, and an
agent command console.

Read this before exposing it anywhere:

* **It is a remote-control surface.** The dashboard dispatches agent runs and
  can change VPN and firewall state. It refuses to start without
  ``DASHBOARD_SECRET_KEY``, binds to loopback by default, and refuses
  outright to combine a non-loopback bind with ``--execute``.
* **It cannot widen a scope.** Every operation runs under the
  ``AuthorizationScope`` the server was started with, taken from server
  configuration and never from a request body. A browser form cannot
  authorize a target the operator did not.
* **It vendors nothing.** No CDN, no external script or style, so the
  Content-Security-Policy forbids every external origin and the console works
  on an isolated network.
* **It is a projection, not a source of truth.** State here is rebuilt from
  module output; a bug in the dashboard can show the wrong thing but cannot
  corrupt what the assistant knows.
"""

from __future__ import annotations

from security_assistant.web.app import DashboardConfig, create_app, telemetry_pump
from security_assistant.web.auth import (
    MIN_SECRET_LENGTH,
    SECRET_ENV_VAR,
    SESSION_COOKIE,
    AuthError,
    AuthGate,
    generate_secret,
    is_loopback,
    secret_from_env,
    warn_if_exposed,
)
from security_assistant.web.server import (
    ServerError,
    build_config,
    describe_startup,
    serve,
)
from security_assistant.web.state import Broadcaster, DashboardState, EventRecord
from security_assistant.web.ui import render_index

__all__ = [
    "MIN_SECRET_LENGTH",
    "SECRET_ENV_VAR",
    "SESSION_COOKIE",
    "AuthError",
    "AuthGate",
    "Broadcaster",
    "DashboardConfig",
    "DashboardState",
    "EventRecord",
    "ServerError",
    "build_config",
    "create_app",
    "describe_startup",
    "generate_secret",
    "is_loopback",
    "render_index",
    "secret_from_env",
    "serve",
    "telemetry_pump",
    "warn_if_exposed",
]
