"""Fetch-safety checks for URLs the scanner is asked to visit.

Every other module in this system points outward at a target the operator
named. This one is different: it takes a URL supplied by whoever is being
investigated -- from a phishing mail, a suspicious link, an alert -- and
fetches it. That makes the scanner itself an attack surface, and the specific
attack is SSRF: a URL like ``http://169.254.169.254/latest/meta-data/`` does
not attack the target at all, it attacks the machine doing the scanning and
walks off with its cloud credentials.

So a URL is checked before anything fetches it:

* **Scheme allowlist.** Only ``http`` and ``https``. ``file://`` reads local
  disk, ``gopher://`` and friends are classic SSRF pivots.
* **Address-space denylist.** Loopback, private, link-local (which is where
  cloud metadata lives), multicast, reserved and unspecified addresses are
  refused.
* **Port allowlist.** Web ports only by default, so a URL cannot be used to
  poke an internal Redis or SMTP service.

**Known limitation, stated rather than hidden:** a hostname is only checked
against these rules when it is an IP literal, or when a resolver is supplied
to :func:`assert_fetchable`. A name that resolves to a private address is
caught only if resolution happens here, and even then a DNS-rebinding attack
can change the answer between this check and the actual fetch. The durable
mitigation for that is the network boundary the sandbox container runs
behind, not this function -- this is defence in depth, not the only defence.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable, Iterable
from urllib.parse import urlsplit

__all__ = [
    "ALLOWED_PORTS",
    "ALLOWED_SCHEMES",
    "UnsafeUrlError",
    "assert_fetchable",
    "is_blocked_address",
    "is_fetchable",
]

ALLOWED_SCHEMES = frozenset({"http", "https"})

#: Ports a page may legitimately be served from. Anything else is far more
#: likely to be an attempt to reach an internal service than a real website.
ALLOWED_PORTS = frozenset({80, 443, 8000, 8008, 8080, 8443, 8888, 3000, 5000})


class UnsafeUrlError(ValueError):
    """Raised when a URL must not be fetched."""


def is_blocked_address(value: str) -> bool:
    """Whether an IP address is in a range the scanner refuses to contact.

    >>> is_blocked_address("169.254.169.254")   # cloud metadata
    True
    >>> is_blocked_address("127.0.0.1")
    True
    >>> is_blocked_address("10.0.0.5")
    True
    >>> is_blocked_address("93.184.216.34")
    False
    """
    try:
        address = ipaddress.ip_address(value.strip().strip("[]"))
    except ValueError:
        return False

    if (
        address.is_loopback
        or address.is_private
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    ):
        return True

    # An IPv4-mapped IPv6 address (::ffff:127.0.0.1) inherits the v4 range's
    # meaning, and the flags above do not see through the mapping.
    mapped = getattr(address, "ipv4_mapped", None)
    if mapped is not None:
        return is_blocked_address(str(mapped))

    return False


def assert_fetchable(
    url: str,
    *,
    resolver: Callable[[str], Iterable[str]] | None = None,
    allowed_ports: frozenset[int] | None = None,
    allow_private: bool = False,
) -> str:
    """Validate that ``url`` may be fetched; return it unchanged.

    Pass ``resolver`` to also check the addresses a hostname resolves to.
    ``allow_private=True`` exists for assessments of an operator's own
    internal infrastructure and must be a deliberate act -- it disables the
    single control that stops this scanner being pointed at its own host.

    Raises :class:`UnsafeUrlError` with a specific reason.
    """
    text = url.strip()
    if not text:
        raise UnsafeUrlError("URL must not be empty")

    try:
        parts = urlsplit(text)
    except ValueError as exc:
        raise UnsafeUrlError(f"Malformed URL {url!r}: {exc}") from exc

    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise UnsafeUrlError(
            f"Refusing to fetch scheme {scheme or '(none)'!r}; "
            f"only {sorted(ALLOWED_SCHEMES)} are allowed"
        )

    host = parts.hostname
    if not host:
        raise UnsafeUrlError(f"URL {url!r} has no host")

    try:
        port = parts.port
    except ValueError as exc:
        raise UnsafeUrlError(f"URL {url!r} has an invalid port: {exc}") from exc

    if port is not None:
        permitted = allowed_ports if allowed_ports is not None else ALLOWED_PORTS
        if port not in permitted:
            raise UnsafeUrlError(
                f"Refusing to fetch port {port}; only {sorted(permitted)} are allowed"
            )

    if not allow_private:
        if is_blocked_address(host):
            raise UnsafeUrlError(
                f"Refusing to fetch {host}: address is loopback, private, "
                "link-local, or otherwise not a public internet host"
            )

        if resolver is not None:
            try:
                addresses = list(resolver(host))
            except Exception as exc:
                raise UnsafeUrlError(
                    f"Could not resolve {host!r} to verify it is public: {exc}"
                ) from exc
            if not addresses:
                raise UnsafeUrlError(f"Host {host!r} did not resolve to any address")
            for address in addresses:
                if is_blocked_address(address):
                    raise UnsafeUrlError(
                        f"Refusing to fetch {host}: it resolves to {address}, "
                        "which is not a public internet address"
                    )

    return text


def is_fetchable(
    url: str,
    *,
    resolver: Callable[[str], Iterable[str]] | None = None,
    allow_private: bool = False,
) -> bool:
    """Boolean form of :func:`assert_fetchable`."""
    try:
        assert_fetchable(url, resolver=resolver, allow_private=allow_private)
    except UnsafeUrlError:
        return False
    return True
