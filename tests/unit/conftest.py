"""Shared fixtures for the agent-core test suite.

Async tests are driven through the :func:`run` helper rather than
``pytest-asyncio``. Each test gets a fresh event loop via :func:`asyncio.run`,
which keeps the suite dependency-free and avoids cross-test loop state.
"""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine
from typing import Any, TypeVar

import pytest

from security_assistant.core import (
    AuthorizationScope,
    RiskLevel,
    ToolCategory,
    ToolContext,
    ToolParameter,
    ToolRegistry,
    tool,
)

T = TypeVar("T")


def run(coro: Coroutine[Any, Any, T]) -> T:
    """Execute ``coro`` on a fresh event loop and return its result."""
    return asyncio.run(coro)


# --------------------------------------------------------------------------- #
# Representative tools spanning every category, risk level and dependency shape
# --------------------------------------------------------------------------- #
@tool(
    name="net.vpn_up",
    description="Ensure the authorized egress tunnel is established.",
    category=ToolCategory.NETWORK,
    risk=RiskLevel.PASSIVE,
    requires_scope=False,
    produces=["egress"],
)
async def vpn_up(ctx: ToolContext) -> dict[str, str]:
    return {"tunnel": "up"}


@tool(
    name="osint.whois",
    description="Passive WHOIS registration lookup.",
    category=ToolCategory.OSINT,
    risk=RiskLevel.PASSIVE,
    parameters=[ToolParameter("target", str, description="Domain to look up")],
    produces=["registration"],
)
async def whois_lookup(ctx: ToolContext, target: str) -> dict[str, str]:
    return {"registrar": "Example Registrar", "target": target}


@tool(
    name="recon.dns",
    description="Resolve DNS records for a hostname.",
    category=ToolCategory.RECON,
    risk=RiskLevel.ACTIVE,
    parameters=[ToolParameter("target", str, description="Hostname to resolve")],
    produces=["hosts"],
)
async def dns_resolve(ctx: ToolContext, target: str) -> list[str]:
    return [f"93.184.216.34 ({target})"]


@tool(
    name="analysis.correlate",
    description="Correlate collected reconnaissance data.",
    category=ToolCategory.ANALYSIS,
    risk=RiskLevel.PASSIVE,
    parameters=[ToolParameter("target", str, description="Target under assessment")],
    consumes=["hosts", "registration"],
)
async def correlate(ctx: ToolContext, target: str) -> dict[str, Any]:
    return {"correlated": True, "target": target}


@tool(
    name="scan.intrusive",
    description="An intrusive action requiring explicit authorization.",
    category=ToolCategory.SCANNING,
    risk=RiskLevel.INTRUSIVE,
    parameters=[ToolParameter("target", str, description="Target")],
)
async def intrusive_scan(ctx: ToolContext, target: str) -> str:
    return "performed intrusive scan"


@pytest.fixture
def registry() -> ToolRegistry:
    """A registry wired with the four cooperating pipeline tools."""
    reg = ToolRegistry("test")
    reg.register_all([vpn_up, whois_lookup, dns_resolve, correlate])
    return reg


@pytest.fixture
def scope() -> AuthorizationScope:
    """An engagement authorizing active work against example.com."""
    return AuthorizationScope(
        allow=["example.com"],
        max_risk=RiskLevel.ACTIVE,
        authorization_reference="ENG-TEST-1",
        engagement="unit-test",
    )
