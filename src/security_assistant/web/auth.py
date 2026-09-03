"""Authentication for the dashboard.

The dashboard is a remote-control surface for a security tool: it dispatches
agent runs, toggles a kill-switch, and reads an engagement's findings. An
unauthenticated instance on a shared network is worse than no dashboard,
because it hands all of that to whoever finds the port.

Four decisions follow.

**No default secret.** :func:`secret_from_env` raises when
``DASHBOARD_SECRET_KEY`` is unset. A generated-on-boot default would be
printed to a log nobody reads; a hardcoded default would be in this file, and
therefore in every deployment. The server refuses to start instead.

**A minimum length, enforced.** A four-character key is not a key. The floor
is deliberately larger than anything a human would type by hand, which is the
point -- the guidance is to generate one.

**Constant-time comparison.** Token checks use :func:`hmac.compare_digest`, so
a timing side channel cannot be used to recover the secret one byte at a time.

**Cookies are signed, not encrypted, and carry no privilege.** The session
cookie proves only that the holder presented the token; every request
re-verifies the signature. It is ``HttpOnly``, ``SameSite=Strict``, and
``Secure`` unless the server is bound to loopback -- where a secure-only
cookie would simply never be sent over plain http and lock the operator out
of their own dashboard.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os
import secrets
import time
from collections.abc import Mapping
from dataclasses import dataclass

logger = logging.getLogger(__name__)

__all__ = [
    "MIN_SECRET_LENGTH",
    "SECRET_ENV_VAR",
    "SESSION_COOKIE",
    "AuthError",
    "AuthGate",
    "generate_secret",
    "secret_from_env",
]

SECRET_ENV_VAR = "DASHBOARD_SECRET_KEY"
SESSION_COOKIE = "sa_session"

#: Minimum acceptable secret length. Larger than anyone will type by hand,
#: which is intentional: the documented path is `generate_secret()`.
MIN_SECRET_LENGTH = 32

#: How long a session stays valid without re-presenting the token.
DEFAULT_SESSION_TTL_SECONDS = 12 * 3600


class AuthError(RuntimeError):
    """Authentication is misconfigured or a credential was rejected."""


def generate_secret(length: int = 48) -> str:
    """Generate a secret suitable for ``DASHBOARD_SECRET_KEY``."""
    return secrets.token_urlsafe(length)


def secret_from_env(env: Mapping[str, str] | None = None) -> str:
    """Read and validate the dashboard secret.

    Raises rather than inventing one: a dashboard that silently generates its
    own key is a dashboard whose access control nobody has thought about.
    """
    source = env if env is not None else os.environ
    secret = (source.get(SECRET_ENV_VAR) or "").strip()

    if not secret:
        raise AuthError(
            f"{SECRET_ENV_VAR} is not set. The dashboard controls agent runs, "
            "VPN state and the kill-switch, so it will not start without "
            "authentication. Generate one with:\n"
            '    python -c "import secrets; print(secrets.token_urlsafe(48))"'
        )

    if len(secret) < MIN_SECRET_LENGTH:
        raise AuthError(
            f"{SECRET_ENV_VAR} is {len(secret)} characters; the minimum is "
            f"{MIN_SECRET_LENGTH}. Generate one rather than choosing it."
        )

    return secret


@dataclass(slots=True)
class Session:
    """A verified session."""

    issued_at: float
    expires_at: float

    @property
    def expired(self) -> bool:
        return time.time() >= self.expires_at


class AuthGate:
    """Verifies tokens and issues signed session cookies."""

    __slots__ = ("_loopback_only", "_secret", "_ttl")

    def __init__(
        self,
        secret: str,
        *,
        session_ttl_seconds: float = DEFAULT_SESSION_TTL_SECONDS,
        loopback_only: bool = True,
    ) -> None:
        if len(secret) < MIN_SECRET_LENGTH:
            raise AuthError(f"Secret is too short ({len(secret)} < {MIN_SECRET_LENGTH})")
        self._secret = secret.encode("utf-8")
        self._ttl = session_ttl_seconds
        self._loopback_only = loopback_only

    @property
    def cookie_secure(self) -> bool:
        """Whether the session cookie should carry ``Secure``.

        False when bound to loopback: a ``Secure`` cookie is never sent over
        plain http, so setting it there would lock the operator out of their
        own dashboard rather than protecting anything.
        """
        return not self._loopback_only

    def verify_token(self, presented: str) -> bool:
        """Constant-time check of a presented token against the secret."""
        if not presented:
            return False
        return hmac.compare_digest(presented.encode("utf-8"), self._secret)

    def issue(self) -> str:
        """Mint a signed session cookie value.

        Format: ``<issued>.<expires>.<signature>``. The payload is readable --
        it carries no secret -- and the signature makes it unforgeable.
        """
        issued = time.time()
        expires = issued + self._ttl
        payload = f"{issued:.0f}.{expires:.0f}"
        return f"{payload}.{self._sign(payload)}"

    def verify_session(self, cookie: str | None) -> Session | None:
        """Validate a session cookie, or return ``None``.

        Every failure path returns ``None`` rather than raising, so a
        malformed cookie is simply unauthenticated rather than a 500.
        """
        if not cookie:
            return None

        parts = cookie.split(".")
        if len(parts) != 3:
            return None
        issued_text, expires_text, signature = parts

        payload = f"{issued_text}.{expires_text}"
        if not hmac.compare_digest(signature, self._sign(payload)):
            return None

        try:
            session = Session(issued_at=float(issued_text), expires_at=float(expires_text))
        except ValueError:
            return None

        if session.expired:
            return None
        return session

    def _sign(self, payload: str) -> str:
        digest = hmac.new(self._secret, payload.encode("utf-8"), hashlib.sha256).digest()
        return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<AuthGate ttl={self._ttl:.0f}s secure_cookie={self.cookie_secure}>"


def token_from_headers(headers: Mapping[str, str]) -> str:
    """Extract a bearer token from an ``Authorization`` header.

    Also accepts ``X-Dashboard-Token`` so a WebSocket client, which cannot set
    arbitrary ``Authorization`` headers in a browser, has a path that does not
    involve putting the secret in a query string where it would land in logs.
    """
    authorization = headers.get("authorization") or headers.get("Authorization") or ""
    if authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return (headers.get("x-dashboard-token") or headers.get("X-Dashboard-Token") or "").strip()


def is_loopback(host: str) -> bool:
    """Whether a bind address is loopback-only."""
    import ipaddress

    text = host.strip().strip("[]").lower()
    if text in {"localhost", ""}:
        return True
    try:
        return ipaddress.ip_address(text).is_loopback
    except ValueError:
        return False


def warn_if_exposed(host: str) -> str | None:
    """Return a warning when binding somewhere reachable off-host.

    Not a refusal -- a deliberate LAN bind behind a reverse proxy is a real
    deployment -- but it must be a visible choice rather than a default that
    quietly exposes an agent-control surface.
    """
    if is_loopback(host):
        return None
    return (
        f"Dashboard is binding to {host}, which is reachable from outside this "
        "machine. It can dispatch agent runs and change VPN state. Put it "
        "behind TLS and a reverse proxy, restrict the source range, and "
        "confirm DASHBOARD_SECRET_KEY is a generated value."
    )
