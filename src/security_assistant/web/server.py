"""Uvicorn launcher for the dashboard.

Kept apart from :mod:`security_assistant.web.app` so the application can be
built and tested without a server, and so the launcher can do the things a
launcher should: validate the secret before binding, warn when binding
somewhere reachable, and refuse the combination that is actually dangerous.
"""

from __future__ import annotations

import logging
import threading
import webbrowser
from collections.abc import Mapping
from typing import Any

from security_assistant.web.app import DashboardConfig, create_app
from security_assistant.web.auth import (
    AuthError,
    generate_secret,
    is_loopback,
    secret_from_env,
    warn_if_exposed,
)

logger = logging.getLogger(__name__)

__all__ = ["ServerError", "build_config", "open_browser_later", "serve"]


class ServerError(RuntimeError):
    """The dashboard could not be started."""


def build_config(
    *,
    host: str = "127.0.0.1",
    port: int = 8443,
    scope: tuple[str, ...] = (),
    max_risk: str = "active",
    execute: bool = False,
    allow_static_fallback: bool = False,
    interface: str = "wg0",
    backend: str = "wireguard",
    admin_cidrs: tuple[str, ...] = (),
    env: Mapping[str, str] | None = None,
) -> DashboardConfig:
    """Validate inputs and build a :class:`DashboardConfig`.

    Refuses the one genuinely dangerous combination: a non-loopback bind with
    execution enabled. That is a remote-control surface for privileged system
    commands, and no amount of a shared secret makes it a reasonable default.
    Binding off-loopback for read-only use is allowed with a warning; adding
    ``--execute`` to it is not.
    """
    from security_assistant.core.types import RiskLevel

    secret = secret_from_env(env)

    if execute and not is_loopback(host):
        raise ServerError(
            f"Refusing to bind {host} with --execute. That combination exposes "
            "privileged VPN and firewall control to the network. Bind to "
            "127.0.0.1 and reach it over an SSH tunnel, or drop --execute."
        )

    warning = warn_if_exposed(host)
    if warning:
        logger.warning(warning)

    try:
        risk = RiskLevel.parse(max_risk)
    except ValueError as exc:
        raise ServerError(str(exc)) from exc

    if not scope:
        logger.warning(
            "Dashboard started with no --scope: every target will be denied. "
            "Pass --scope to authorize an engagement."
        )

    return DashboardConfig(
        secret=secret,
        host=host,
        port=port,
        scope_targets=tuple(scope),
        max_risk=risk,
        execute=execute,
        allow_static_fallback=allow_static_fallback,
        vpn_interface=interface,
        vpn_backend=backend,
        admin_cidrs=tuple(admin_cidrs),
    )


def open_browser_later(url: str, delay: float = 1.0) -> threading.Timer:
    """Open a browser once the server has had time to bind."""
    timer = threading.Timer(delay, lambda: webbrowser.open(url))
    timer.daemon = True
    timer.start()
    return timer


def serve(
    config: DashboardConfig,
    *,
    context: Mapping[str, Any] | None = None,
    open_browser: bool = False,
    log_level: str = "info",
) -> None:  # pragma: no cover - starts a blocking server
    """Run the dashboard until interrupted."""
    import uvicorn

    app = create_app(config, context=context)
    url = f"http://{config.host}:{config.port}/"

    if open_browser:
        open_browser_later(url)

    logger.info("Dashboard listening on %s", url)
    uvicorn.run(app, host=config.host, port=config.port, log_level=log_level)


def suggest_secret() -> str:
    """A ready-to-paste secret, for the CLI's error path."""
    return generate_secret()


def describe_startup(config: DashboardConfig) -> list[str]:
    """Lines the CLI prints before binding, so the posture is visible."""
    lines = [
        f"bind        {config.host}:{config.port}"
        + ("" if config.loopback_only else "   (reachable off-host)"),
        f"scope       {', '.join(config.scope_targets) or 'none — every target denied'}",
        f"max risk    {config.max_risk}",
        f"execution   {'ENABLED — real system commands' if config.execute else 'dry run'}",
        "sandbox     "
        + ("static fallback allowed" if config.allow_static_fallback else "fails closed"),
    ]
    if config.admin_cidrs:
        lines.append(f"admin nets  {', '.join(config.admin_cidrs)}")
    return lines


def ensure_secret(env: Mapping[str, str] | None = None) -> str:
    """Read the secret, converting the auth error into a server error."""
    try:
        return secret_from_env(env)
    except AuthError as exc:
        raise ServerError(str(exc)) from exc
