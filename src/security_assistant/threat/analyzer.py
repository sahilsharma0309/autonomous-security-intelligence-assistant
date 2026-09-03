"""Heuristic URL analysis: deception, structure, hosting and behaviour.

Everything here works on evidence already gathered -- the URL string, an
optional certificate, an optional sandbox report -- and contacts nothing. The
scanner that fetches lives in :mod:`security_assistant.threat.sandbox`.

Two ideas shape the heuristics:

**Say what was observed, not what it means.** A finding records "the
registrable domain is one edit away from ``paypal.com``", not "this is a
phishing site". The verdict is the score's job, and keeping the two separate
is what makes a false positive legible rather than mysterious.

**Weight by how forgeable the signal is.** A homoglyph in a domain is nearly
always deliberate, so it scores high. A hyphen in a hostname is normal, so
alone it scores almost nothing. Getting this ordering wrong is how scanners
end up flagging half the internet and being switched off.

The brand list is deliberately small and caller-extensible. A built-in list
of a thousand brands would produce confident nonsense on the many legitimate
domains that happen to resemble one; the operator is expected to supply the
brands that matter to the engagement.
"""

from __future__ import annotations

import logging
import re
import unicodedata
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlsplit

from security_assistant.threat.models import (
    Finding,
    FindingCategory,
    SandboxReport,
    Severity,
    UrlAssessment,
    registrable_domain,
)

logger = logging.getLogger(__name__)

__all__ = [
    "AnalyzerConfig",
    "UrlAnalyzer",
    "confusable_skeleton",
    "edit_distance",
    "looks_like_homoglyph",
]

#: Brands worth checking for imitation by default. Short on purpose -- see
#: the module docstring.
DEFAULT_PROTECTED_BRANDS: tuple[str, ...] = (
    "google.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "paypal.com",
    "facebook.com",
    "instagram.com",
    "netflix.com",
    "linkedin.com",
    "dropbox.com",
    "github.com",
    "office365.com",
    "outlook.com",
)

#: TLDs disproportionately represented in abuse reporting. Presence is a weak
#: signal only: plenty of legitimate sites use them.
SUSPICIOUS_TLDS = frozenset(
    {
        "zip",
        "mov",
        "top",
        "xyz",
        "tk",
        "ml",
        "ga",
        "cf",
        "gq",
        "buzz",
        "click",
        "link",
        "work",
        "country",
        "kim",
        "loan",
        "download",
        "racing",
        "win",
        "review",
        "stream",
        "bid",
        "date",
        "faith",
    }
)

#: Hosts that let anyone publish arbitrary content on a trusted-looking name.
DYNAMIC_DNS_SUFFIXES = frozenset(
    {
        "duckdns.org",
        "no-ip.com",
        "no-ip.org",
        "ddns.net",
        "hopto.org",
        "zapto.org",
        "serveo.net",
        "ngrok.io",
        "ngrok-free.app",
        "trycloudflare.com",
        "loca.lt",
        "localtunnel.me",
        "pagekite.me",
        "serveusers.com",
    }
)

#: Words that suggest a credential-collection page when they appear in a
#: hostname rather than a path.
PHISHING_KEYWORDS = frozenset(
    {
        "login",
        "signin",
        "sign-in",
        "verify",
        "verification",
        "account",
        "secure",
        "security",
        "update",
        "confirm",
        "billing",
        "payment",
        "invoice",
        "wallet",
        "recover",
        "unlock",
        "suspended",
        "authenticate",
        "webscr",
        "banking",
    }
)

#: Characters commonly substituted to imitate ASCII letters. Mapping to the
#: letter they imitate gives a "skeleton" two names can be compared on.
_CONFUSABLES: dict[str, str] = {
    "а": "a",
    "α": "a",
    "ⅰ": "i",
    "і": "i",
    "ӏ": "l",
    "ⅼ": "l",
    "е": "e",
    "ё": "e",
    "о": "o",
    "ο": "o",
    "օ": "o",
    "р": "p",
    "ρ": "p",
    "с": "c",
    "ϲ": "c",
    "ѕ": "s",
    "ԁ": "d",
    "һ": "h",
    "ν": "v",
    "ԝ": "w",
    "х": "x",
    "у": "y",
    "ƅ": "b",
    "ɡ": "g",
    "ᴜ": "u",
    "ｍ": "m",
    "ո": "n",
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "8": "b",
    "rn": "m",
    "vv": "w",
    "cl": "d",
}

_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_HEX_RE = re.compile(r"^[0-9a-f]{16,}$")


def edit_distance(left: str, right: str, *, cap: int = 4) -> int:
    """Levenshtein distance, abandoned once it exceeds ``cap``.

    The cap keeps this cheap: the caller only cares whether two names are
    *close*, and an exact distance of 37 costs the same to compute as 3.

    >>> edit_distance("paypal", "paypa1")
    1
    >>> edit_distance("paypal", "example")
    4
    """
    if left == right:
        return 0
    if abs(len(left) - len(right)) > cap:
        return cap
    previous = list(range(len(right) + 1))
    for i, lc in enumerate(left, start=1):
        current = [i]
        for j, rc in enumerate(right, start=1):
            current.append(
                min(
                    previous[j] + 1,
                    current[j - 1] + 1,
                    previous[j - 1] + (lc != rc),
                )
            )
        if min(current) > cap:
            return cap
        previous = current
    return min(previous[-1], cap)


def confusable_skeleton(value: str) -> str:
    """Reduce a name to a comparison skeleton.

    Strips accents, folds known confusable characters onto the ASCII letter
    they imitate, and applies multi-character substitutions like ``rn`` for
    ``m``. Two names with the same skeleton look alike to a human even when
    their bytes differ entirely.

    >>> confusable_skeleton("pаypal")   # Cyrillic а
    'paypal'
    >>> confusable_skeleton("rnicrosoft")
    'microsoft'
    """
    decomposed = unicodedata.normalize("NFKD", value.casefold())
    stripped = "".join(c for c in decomposed if not unicodedata.combining(c))

    for source, target in (("rn", "m"), ("vv", "w"), ("cl", "d")):
        stripped = stripped.replace(source, target)

    return "".join(_CONFUSABLES.get(c, c) for c in stripped)


def looks_like_homoglyph(value: str) -> bool:
    """Whether a name mixes scripts or uses confusable non-ASCII characters.

    >>> looks_like_homoglyph("pаypal.com")   # Cyrillic а
    True
    >>> looks_like_homoglyph("paypal.com")
    False
    """
    if value.isascii():
        return False
    # Punycode-decoded names that mix Latin with another script are the
    # classic IDN homograph attack.
    scripts: set[str] = set()
    for char in value:
        if not char.isalpha():
            continue
        try:
            name = unicodedata.name(char)
        except ValueError:  # pragma: no cover - unnamed codepoint
            continue
        scripts.add(name.split(" ")[0])
    return len(scripts) > 1 or any(c in _CONFUSABLES for c in value)


@dataclass(slots=True)
class AnalyzerConfig:
    """What the analyzer treats as suspicious."""

    protected_brands: tuple[str, ...] = DEFAULT_PROTECTED_BRANDS
    max_url_length: int = 120
    max_subdomain_depth: int = 4
    max_typo_distance: int = 2
    suspicious_tlds: frozenset[str] = SUSPICIOUS_TLDS
    dynamic_dns_suffixes: frozenset[str] = DYNAMIC_DNS_SUFFIXES
    phishing_keywords: frozenset[str] = PHISHING_KEYWORDS
    certificate_min_age_days: int = 7

    def with_brands(self, brands: Iterable[str]) -> AnalyzerConfig:
        """Return a copy protecting an additional set of brands."""
        merged = list(self.protected_brands)
        for brand in brands:
            text = str(brand).strip().lower()
            if text and text not in merged:
                merged.append(text)
        return AnalyzerConfig(
            protected_brands=tuple(merged),
            max_url_length=self.max_url_length,
            max_subdomain_depth=self.max_subdomain_depth,
            max_typo_distance=self.max_typo_distance,
            suspicious_tlds=self.suspicious_tlds,
            dynamic_dns_suffixes=self.dynamic_dns_suffixes,
            phishing_keywords=self.phishing_keywords,
            certificate_min_age_days=self.certificate_min_age_days,
        )


@dataclass(slots=True)
class _UrlParts:
    url: str
    scheme: str = ""
    host: str = ""
    path: str = ""
    query: str = ""
    port: int | None = None
    username: str = ""
    registrable: str = ""
    labels: list[str] = field(default_factory=list)


class UrlAnalyzer:
    """Produces findings about a URL without contacting it."""

    def __init__(self, config: AnalyzerConfig | None = None) -> None:
        self._config = config or AnalyzerConfig()

    @property
    def config(self) -> AnalyzerConfig:
        return self._config

    # -- public API -------------------------------------------------------- #
    def analyze(
        self,
        url: str,
        *,
        certificate: Mapping[str, object] | None = None,
        sandbox: SandboxReport | None = None,
    ) -> UrlAssessment:
        """Assess a URL from its text plus any evidence already gathered."""
        findings = list(self.analyze_url(url))
        if certificate is not None:
            findings.extend(self.analyze_certificate(url, certificate))
        if sandbox is not None:
            findings.extend(self.analyze_sandbox(sandbox))
        return UrlAssessment(url=url, findings=findings, sandbox=sandbox)

    def analyze_url(self, url: str) -> list[Finding]:
        """Findings derivable from the URL string alone."""
        parts = self._split(url)
        if parts is None:
            return [
                Finding(
                    code="malformed_url",
                    title="URL could not be parsed",
                    severity=Severity.MEDIUM,
                    category=FindingCategory.STRUCTURE,
                    detail=f"{url!r} is not a well-formed URL",
                    source="threat.url_analyze",
                )
            ]

        findings: list[Finding] = []
        findings.extend(self._structure_findings(parts))
        findings.extend(self._deception_findings(parts))
        findings.extend(self._hosting_findings(parts))
        return findings

    def analyze_certificate(self, url: str, certificate: Mapping[str, object]) -> list[Finding]:
        """Findings from a TLS certificate observed for this URL.

        Accepts the shape produced by ``osint.tls`` so Module 2's collector
        feeds this directly.
        """
        findings: list[Finding] = []
        parts = self._split(url)
        host = parts.host if parts is not None else ""

        if certificate.get("is_expired"):
            findings.append(
                Finding(
                    code="cert_expired",
                    title="TLS certificate is expired",
                    severity=Severity.MEDIUM,
                    category=FindingCategory.CERTIFICATE,
                    detail=f"not_after={certificate.get('not_after')}",
                    source="threat.url_analyze",
                )
            )

        verified = certificate.get("verified")
        if verified is False:
            error = str(certificate.get("verification_error") or "chain not trusted")
            findings.append(
                Finding(
                    code="cert_untrusted",
                    title="TLS certificate did not verify",
                    severity=Severity.MEDIUM,
                    category=FindingCategory.CERTIFICATE,
                    detail=error,
                    source="threat.url_analyze",
                )
            )

        sans = certificate.get("sans")
        if host and isinstance(sans, (list, tuple)) and sans:
            covered = {str(s).lower().lstrip("*.") for s in sans}
            if host not in covered and registrable_domain(host) not in covered:
                findings.append(
                    Finding(
                        code="cert_host_mismatch",
                        title="Certificate does not cover the URL's host",
                        severity=Severity.HIGH,
                        category=FindingCategory.CERTIFICATE,
                        detail=f"{host} not in SANs {sorted(covered)[:5]}",
                        source="threat.url_analyze",
                    )
                )

        return findings

    def analyze_sandbox(self, report: SandboxReport) -> list[Finding]:
        """Findings from what happened when the page was loaded."""
        findings: list[Finding] = []

        initial_domain = registrable_domain(_host_of(report.initial_url))
        final_domain = registrable_domain(_host_of(report.final_url))

        if final_domain and initial_domain and final_domain != initial_domain:
            findings.append(
                Finding(
                    code="cross_domain_redirect",
                    title="URL redirects to a different registrable domain",
                    severity=Severity.MEDIUM,
                    category=FindingCategory.BEHAVIOR,
                    detail=f"{initial_domain} -> {final_domain}",
                    source="threat.url_inspect",
                )
            )

        if len(report.chain) > 3:
            findings.append(
                Finding(
                    code="long_redirect_chain",
                    title="Long redirect chain",
                    severity=Severity.LOW,
                    category=FindingCategory.BEHAVIOR,
                    detail=f"{len(report.chain)} hops",
                    source="threat.url_inspect",
                )
            )

        if report.has_password_input:
            # A password field is only notable in combination with something
            # else -- most login pages are legitimate -- so it is MEDIUM on
            # a deceptive domain and LOW otherwise.
            deceptive = any(f.category is FindingCategory.DECEPTION for f in findings)
            findings.append(
                Finding(
                    code="credential_form",
                    title="Page collects a password",
                    severity=Severity.MEDIUM if deceptive else Severity.LOW,
                    category=FindingCategory.CONTENT,
                    detail=f"password input present on {report.final_url}",
                    source="threat.url_inspect",
                )
            )

        if report.engine == "static":
            findings.append(
                Finding(
                    code="static_inspection_only",
                    title="Inspected without a browser",
                    severity=Severity.INFO,
                    category=FindingCategory.BEHAVIOR,
                    detail=(
                        "No container runtime was available, so script-driven "
                        "behaviour was not observed. Absence of behavioural "
                        "findings is not evidence of safety."
                    ),
                    source="threat.url_inspect",
                )
            )

        return findings

    # -- rule groups ------------------------------------------------------- #
    def _structure_findings(self, parts: _UrlParts) -> list[Finding]:
        findings: list[Finding] = []

        if parts.username:
            findings.append(
                Finding(
                    code="embedded_credentials",
                    title="URL embeds credentials before the host",
                    severity=Severity.HIGH,
                    category=FindingCategory.STRUCTURE,
                    detail=(
                        f"userinfo {parts.username!r} precedes the host, which "
                        "hides the real destination from a reader"
                    ),
                    source="threat.url_analyze",
                )
            )

        if len(parts.url) > self._config.max_url_length:
            findings.append(
                Finding(
                    code="excessive_length",
                    title="Unusually long URL",
                    severity=Severity.LOW,
                    category=FindingCategory.STRUCTURE,
                    detail=f"{len(parts.url)} characters",
                    source="threat.url_analyze",
                )
            )

        if len(parts.labels) > self._config.max_subdomain_depth:
            findings.append(
                Finding(
                    code="deep_subdomain",
                    title="Deeply nested subdomains",
                    severity=Severity.LOW,
                    category=FindingCategory.STRUCTURE,
                    detail=f"{len(parts.labels)} labels in {parts.host}",
                    source="threat.url_analyze",
                )
            )

        # A URL that carries another URL in its query is often an open
        # redirect being abused to borrow a trusted domain's reputation.
        for values in parse_qs(parts.query).values():
            for value in values:
                if value.lower().startswith(("http://", "https://", "//")):
                    findings.append(
                        Finding(
                            code="embedded_url_parameter",
                            title="A parameter contains another URL",
                            severity=Severity.MEDIUM,
                            category=FindingCategory.STRUCTURE,
                            detail=f"parameter value {value[:80]!r}",
                            source="threat.url_analyze",
                        )
                    )
                    break

        if parts.scheme == "http":
            findings.append(
                Finding(
                    code="plaintext_scheme",
                    title="URL uses http rather than https",
                    severity=Severity.LOW,
                    category=FindingCategory.STRUCTURE,
                    detail="credentials or session data would travel in clear text",
                    source="threat.url_analyze",
                )
            )

        return findings

    def _deception_findings(self, parts: _UrlParts) -> list[Finding]:
        findings: list[Finding] = []
        host = parts.host
        if not host:
            return findings

        if host.startswith("xn--") or ".xn--" in host:
            findings.append(
                Finding(
                    code="punycode_host",
                    title="Host uses punycode",
                    severity=Severity.MEDIUM,
                    category=FindingCategory.DECEPTION,
                    detail=(
                        f"{host} is an internationalized name; it may render as "
                        "something visually different"
                    ),
                    source="threat.url_analyze",
                )
            )

        if looks_like_homoglyph(host):
            findings.append(
                Finding(
                    code="homoglyph_host",
                    title="Host mixes scripts or uses confusable characters",
                    severity=Severity.HIGH,
                    category=FindingCategory.DECEPTION,
                    detail=f"{host!r} folds to {confusable_skeleton(host)!r}",
                    source="threat.url_analyze",
                )
            )

        registrable = parts.registrable
        if registrable:
            name = registrable.split(".")[0]
            skeleton = confusable_skeleton(name)

            for brand in self._config.protected_brands:
                brand_name = brand.split(".")[0]
                if registrable == brand:
                    return findings  # It *is* the brand; nothing to report.

                distance = edit_distance(name, brand_name, cap=self._config.max_typo_distance + 1)
                if 0 < distance <= self._config.max_typo_distance:
                    findings.append(
                        Finding(
                            code="typosquat",
                            title=f"Domain closely resembles {brand}",
                            severity=Severity.HIGH,
                            category=FindingCategory.DECEPTION,
                            detail=(f"{registrable!r} is {distance} edit(s) from {brand!r}"),
                            source="threat.url_analyze",
                        )
                    )
                    break

                if skeleton == confusable_skeleton(brand_name) and name != brand_name:
                    findings.append(
                        Finding(
                            code="lookalike_domain",
                            title=f"Domain is visually confusable with {brand}",
                            severity=Severity.HIGH,
                            category=FindingCategory.DECEPTION,
                            detail=f"{name!r} and {brand_name!r} share skeleton {skeleton!r}",
                            source="threat.url_analyze",
                        )
                    )
                    break

            # A brand name in a subdomain of someone else's domain, e.g.
            # paypal.com.security-check.example -- the reader sees the brand,
            # the browser sees the last two labels.
            subdomain_part = host[: -len(registrable)].rstrip(".")
            for brand in self._config.protected_brands:
                brand_name = brand.split(".")[0]
                if brand_name in subdomain_part.split(".") or brand in subdomain_part:
                    findings.append(
                        Finding(
                            code="brand_in_subdomain",
                            title=f"{brand} appears in a subdomain of another domain",
                            severity=Severity.HIGH,
                            category=FindingCategory.DECEPTION,
                            detail=(f"{host} is served by {registrable}, not {brand}"),
                            source="threat.url_analyze",
                        )
                    )
                    break

        keywords = sorted(
            {
                word
                for word in self._config.phishing_keywords
                if word in host.replace("-", ".").split(".")
            }
        )
        if keywords:
            findings.append(
                Finding(
                    code="phishing_keyword_host",
                    title="Security-themed words in the hostname",
                    severity=Severity.MEDIUM,
                    category=FindingCategory.DECEPTION,
                    detail=f"found {keywords} in {host}",
                    source="threat.url_analyze",
                )
            )

        return findings

    def _hosting_findings(self, parts: _UrlParts) -> list[Finding]:
        findings: list[Finding] = []
        host = parts.host
        if not host:
            return findings

        if _IPV4_RE.match(host) or ":" in host:
            findings.append(
                Finding(
                    code="ip_literal_host",
                    title="URL points at a bare IP address",
                    severity=Severity.MEDIUM,
                    category=FindingCategory.HOSTING,
                    detail=f"host is the literal address {host}",
                    source="threat.url_analyze",
                )
            )
            return findings

        tld = host.rsplit(".", 1)[-1] if "." in host else ""
        if tld in self._config.suspicious_tlds:
            findings.append(
                Finding(
                    code="suspicious_tld",
                    title=f"Top-level domain .{tld} is over-represented in abuse",
                    severity=Severity.LOW,
                    category=FindingCategory.HOSTING,
                    detail=f"{host} uses .{tld}",
                    source="threat.url_analyze",
                )
            )

        for suffix in self._config.dynamic_dns_suffixes:
            if host == suffix or host.endswith(f".{suffix}"):
                findings.append(
                    Finding(
                        code="dynamic_dns_host",
                        title="Hosted on a dynamic-DNS or tunnelling provider",
                        severity=Severity.MEDIUM,
                        category=FindingCategory.HOSTING,
                        detail=f"{host} is under {suffix}",
                        source="threat.url_analyze",
                    )
                )
                break

        first_label = parts.labels[0] if parts.labels else ""
        if _HEX_RE.match(first_label):
            findings.append(
                Finding(
                    code="random_subdomain",
                    title="Machine-generated looking subdomain",
                    severity=Severity.LOW,
                    category=FindingCategory.HOSTING,
                    detail=f"leading label {first_label!r} looks generated",
                    source="threat.url_analyze",
                )
            )

        if parts.port is not None and parts.port not in (80, 443):
            findings.append(
                Finding(
                    code="uncommon_port",
                    title=f"Served from uncommon port {parts.port}",
                    severity=Severity.LOW,
                    category=FindingCategory.HOSTING,
                    detail=f"{host}:{parts.port}",
                    source="threat.url_analyze",
                )
            )

        return findings

    # -- helpers ----------------------------------------------------------- #
    @staticmethod
    def _split(url: str) -> _UrlParts | None:
        try:
            parsed = urlsplit(url.strip())
        except ValueError:
            return None
        if not parsed.scheme or not parsed.hostname:
            return None
        try:
            port = parsed.port
        except ValueError:
            return None

        host = parsed.hostname.lower()
        return _UrlParts(
            url=url,
            scheme=parsed.scheme.lower(),
            host=host,
            path=parsed.path,
            query=parsed.query,
            port=port,
            username=parsed.username or "",
            registrable=registrable_domain(host),
            labels=host.split("."),
        )


def _host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:  # pragma: no cover - defensive
        return ""


def combine_assessments(assessments: Sequence[UrlAssessment]) -> UrlAssessment | None:
    """Return the highest-scoring assessment, for run-level reporting."""
    if not assessments:
        return None
    return max(assessments, key=lambda a: a.risk_score)
