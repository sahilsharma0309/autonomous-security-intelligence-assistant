"""Shared plumbing for OSINT collectors.

Every collector performs I/O against something outside the process -- a
resolver, a WHOIS registry, a TLS endpoint. That dependency is always reached
through a small injectable provider rather than being called directly, for
three reasons:

* tests run with no network and no optional packages installed,
* an operator can route collection through a specific resolver or proxy, and
* the expensive/fragile part of each collector is isolated from its parsing
  logic, which is where the bugs actually live.

Providers are looked up in :attr:`ToolContext.config` by a well-known key, so
injecting one is just ``agent.run(..., context={"dns_resolver": fake})``.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from typing import Any, TypeVar

from security_assistant.core.types import ToolContext

logger = logging.getLogger(__name__)

__all__ = [
    "CollectorError",
    "provider_from",
    "run_blocking",
]

T = TypeVar("T")


class CollectorError(RuntimeError):
    """Raised when a collector cannot complete its lookup.

    The dispatcher converts this into a failed ``ToolResult``; it does not
    abort the surrounding plan.
    """


def provider_from(ctx: ToolContext, key: str, default_factory: Callable[[], T]) -> T:
    """Return the provider registered under ``key``, or build the default.

    Looking the provider up per call (rather than binding it at import time)
    keeps collectors stateless and makes them trivially mockable.
    """
    provider = ctx.config.get(key)
    if provider is not None:
        return provider  # type: ignore[no-any-return]
    return default_factory()


async def run_blocking(func: Callable[..., T], /, *args: Any, **kwargs: Any) -> T:
    """Run a blocking call in the default executor.

    Several OSINT libraries (``whois``, parts of ``dnspython``) are synchronous
    and would stall the event loop, which matters because the agent runs
    collectors concurrently.
    """
    loop = asyncio.get_running_loop()
    if kwargs:
        return await loop.run_in_executor(None, lambda: func(*args, **kwargs))
    return await loop.run_in_executor(None, func, *args)
