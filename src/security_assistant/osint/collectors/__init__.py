"""OSINT collectors, exposed as registrable agent tools.

Each collector is a ``@tool``-decorated coroutine that performs one kind of
lookup and returns both its normalized findings and the graph elements those
findings imply. They declare their own ``risk``, rate limits and
``produces``/``consumes`` artifacts so the planner can order them correctly:

===================  ========  =========================  ==========================
Tool                 Risk      Produces                   Notes
===================  ========  =========================  ==========================
``osint.whois``      PASSIVE   registration, contacts     Queries the registry only
``osint.dns``        ACTIVE    hosts, dns_records         May reach the target's NS
``osint.tls``        ACTIVE    certificates, sans         Completes a TLS handshake
``osint.social``     ACTIVE    handles                    No platforms by default
===================  ========  =========================  ==========================

Every collector reaches its I/O through an injectable provider looked up in
``ToolContext.config``, so the whole set is testable with no network access:

===================  =========================
Context key          Provider protocol
===================  =========================
``dns_resolver``     ``DnsResolver``
``whois_client``     ``WhoisClient``
``tls_fetcher``      ``TlsCertificateFetcher``
``profile_probe``    ``ProfileProbe``
===================  =========================
"""

from __future__ import annotations

from security_assistant.osint.collectors.base import (
    CollectorError,
    provider_from,
    run_blocking,
)
from security_assistant.osint.collectors.dns_collector import (
    DEFAULT_RECORD_TYPES,
    DnspythonResolver,
    DnsRecordSet,
    DnsResolver,
    StdlibDnsResolver,
    default_resolver,
    dns_collect,
    records_to_graph_elements,
)
from security_assistant.osint.collectors.social_collector import (
    FootprintResult,
    HandleFinding,
    HttpxProfileProbe,
    PlatformHook,
    ProbeOutcome,
    ProfileProbe,
    UnavailableProfileProbe,
    default_profile_probe,
    findings_to_graph_elements,
    platforms_from_config,
    social_footprint,
)
from security_assistant.osint.collectors.tls_collector import (
    CertificateInfo,
    StdlibTlsFetcher,
    TlsCertificateFetcher,
    certificate_to_graph_elements,
    default_tls_fetcher,
    parse_certificate,
    tls_collect,
)
from security_assistant.osint.collectors.whois_collector import (
    PythonWhoisClient,
    UnavailableWhoisClient,
    WhoisClient,
    WhoisRecord,
    default_whois_client,
    parse_whois_record,
    record_to_graph_elements,
    whois_collect,
)

#: Every collector tool, ready to hand to ``ToolRegistry.register_all``.
ALL_COLLECTORS = (dns_collect, whois_collect, tls_collect, social_footprint)

__all__ = [
    "ALL_COLLECTORS",
    "DEFAULT_RECORD_TYPES",
    "CertificateInfo",
    "CollectorError",
    "DnsRecordSet",
    "DnsResolver",
    "DnspythonResolver",
    "FootprintResult",
    "HandleFinding",
    "HttpxProfileProbe",
    "PlatformHook",
    "ProbeOutcome",
    "ProfileProbe",
    "PythonWhoisClient",
    "StdlibDnsResolver",
    "StdlibTlsFetcher",
    "TlsCertificateFetcher",
    "UnavailableProfileProbe",
    "UnavailableWhoisClient",
    "WhoisClient",
    "WhoisRecord",
    "certificate_to_graph_elements",
    "default_profile_probe",
    "default_resolver",
    "default_tls_fetcher",
    "default_whois_client",
    "dns_collect",
    "findings_to_graph_elements",
    "parse_certificate",
    "parse_whois_record",
    "platforms_from_config",
    "provider_from",
    "record_to_graph_elements",
    "records_to_graph_elements",
    "run_blocking",
    "social_footprint",
    "tls_collect",
    "whois_collect",
]
