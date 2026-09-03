"""Tests for the fetch-safety (SSRF) guard.

This is the control that stops a scanner which fetches adversary-chosen URLs
from being aimed at its own host or cloud metadata, so the tests are written
as an attacker would probe it.
"""

from __future__ import annotations

import pytest

from security_assistant.threat.safety import (
    ALLOWED_SCHEMES,
    UnsafeUrlError,
    assert_fetchable,
    is_blocked_address,
    is_fetchable,
)


class TestBlockedAddresses:
    @pytest.mark.parametrize(
        "address",
        [
            "127.0.0.1",
            "127.1.2.3",
            "0.0.0.0",
            "10.0.0.5",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",  # AWS/GCP/Azure metadata
            "::1",
            "fe80::1",
            "fc00::1",
            "224.0.0.1",
        ],
    )
    def test_blocks_non_public_addresses(self, address: str) -> None:
        assert is_blocked_address(address) is True

    @pytest.mark.parametrize("address", ["93.184.216.34", "8.8.8.8", "2606:4700::1111"])
    def test_allows_public_addresses(self, address: str) -> None:
        assert is_blocked_address(address) is False

    def test_sees_through_ipv4_mapped_ipv6(self) -> None:
        # ::ffff:127.0.0.1 is loopback wearing a v6 costume; the plain
        # is_loopback flag does not catch it.
        assert is_blocked_address("::ffff:127.0.0.1") is True
        assert is_blocked_address("::ffff:169.254.169.254") is True

    def test_non_addresses_are_not_blocked_here(self) -> None:
        # Hostnames are handled by the resolver path, not this function.
        assert is_blocked_address("example.com") is False


class TestSchemes:
    @pytest.mark.parametrize("scheme", ["file", "gopher", "ftp", "data", "javascript"])
    def test_refuses_non_web_schemes(self, scheme: str) -> None:
        with pytest.raises(UnsafeUrlError, match="Refusing to fetch scheme"):
            assert_fetchable(f"{scheme}://example.com/x")

    def test_allows_http_and_https(self) -> None:
        assert assert_fetchable("http://example.com/")
        assert assert_fetchable("https://example.com/")

    def test_allowed_set_is_only_web(self) -> None:
        assert frozenset({"http", "https"}) == ALLOWED_SCHEMES

    def test_requires_a_scheme(self) -> None:
        with pytest.raises(UnsafeUrlError):
            assert_fetchable("example.com/path")


class TestMetadataAndInternal:
    def test_refuses_cloud_metadata(self) -> None:
        with pytest.raises(UnsafeUrlError, match=r"not a public internet host"):
            assert_fetchable("http://169.254.169.254/latest/meta-data/")

    def test_refuses_loopback(self) -> None:
        with pytest.raises(UnsafeUrlError):
            assert_fetchable("http://127.0.0.1:8080/admin")

    def test_refuses_private_range(self) -> None:
        with pytest.raises(UnsafeUrlError):
            assert_fetchable("http://10.1.2.3/")

    def test_allows_private_only_when_explicitly_permitted(self) -> None:
        assert assert_fetchable("http://10.1.2.3/", allow_private=True)


class TestPorts:
    def test_refuses_non_web_ports(self) -> None:
        # A URL is not a way to reach an internal Redis.
        with pytest.raises(UnsafeUrlError, match="Refusing to fetch port"):
            assert_fetchable("http://example.com:6379/")

    @pytest.mark.parametrize("port", [80, 443, 8080, 8443])
    def test_allows_web_ports(self, port: int) -> None:
        assert assert_fetchable(f"http://example.com:{port}/")

    def test_custom_allowlist(self) -> None:
        assert assert_fetchable(
            "http://example.com:9999/", allowed_ports=frozenset({9999})
        )


class TestResolverPath:
    def test_blocks_a_name_resolving_to_a_private_address(self) -> None:
        # The DNS-rebinding style attack: an innocuous name pointing inward.
        def resolver(host: str) -> list[str]:
            return ["169.254.169.254"]

        with pytest.raises(UnsafeUrlError, match=r"resolves to 169\.254\.169\.254"):
            assert_fetchable("http://metadata.example/", resolver=resolver)

    def test_allows_a_name_resolving_publicly(self) -> None:
        assert assert_fetchable(
            "http://example.com/", resolver=lambda host: ["93.184.216.34"]
        )

    def test_resolution_failure_is_fatal_not_ignored(self) -> None:
        def resolver(host: str) -> list[str]:
            raise OSError("nxdomain")

        with pytest.raises(UnsafeUrlError, match="Could not resolve"):
            assert_fetchable("http://example.com/", resolver=resolver)

    def test_empty_resolution_is_refused(self) -> None:
        with pytest.raises(UnsafeUrlError, match="did not resolve"):
            assert_fetchable("http://example.com/", resolver=lambda host: [])

    def test_one_bad_address_among_several_blocks(self) -> None:
        with pytest.raises(UnsafeUrlError):
            assert_fetchable(
                "http://example.com/",
                resolver=lambda host: ["93.184.216.34", "127.0.0.1"],
            )


class TestMalformed:
    @pytest.mark.parametrize("url", ["", "   ", "http://", "https://:80/"])
    def test_refuses_malformed(self, url: str) -> None:
        with pytest.raises(UnsafeUrlError):
            assert_fetchable(url)

    def test_invalid_port_is_refused(self) -> None:
        with pytest.raises(UnsafeUrlError):
            assert_fetchable("http://example.com:notaport/")


class TestIsFetchable:
    def test_boolean_form(self) -> None:
        assert is_fetchable("https://example.com/") is True
        assert is_fetchable("http://127.0.0.1/") is False
        assert is_fetchable("file:///etc/passwd") is False
