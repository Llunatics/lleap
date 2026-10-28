"""Scan engine: substitute payloads into a target URL and classify replies.

Verdicts, in order of evaluation:

- ``ERROR`` — the request to the target itself failed (connection error,
  timeout, malformed target URL).
- ``BLOCKED`` — the target refused the value: a 400/403/422 response whose
  body mentions blocking, or a lab JSON reply whose fetch failed with a
  ``blocked``/``denied`` reason.
- ``OPEN-REDIRECT`` — the target redirected the client to a host taken
  from the payload (only meaningful for ``redirect`` payloads).
- ``FETCHED`` — evidence the target fetched the payload URL server-side:
  a lab JSON reply reporting a successful fetch, or a response body that
  contains the payload's host/IP or a known metadata marker.
- ``UNCLEAR`` — none of the above fired. The raw status, final URL and
  body length are still reported so a human can judge.

``FETCHED``/``UNCLEAR`` are evidence grades, not proof of exploitability:
a 200 from a fetcher that returns a generic error page is ``UNCLEAR`` for a
reason. The bundled lab server (``lleap demo``) gives ground truth through
its canary log instead of heuristics.
"""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

from .payloads import Payload

BLOCK_KEYWORDS = (
    "blocked", "denied", "forbidden", "not allowed",
    "invalid url", "invalid host", "disallowed", "ssrf",
)
METADATA_MARKERS = (
    "ami-id", "instance-id", "security-credentials",
    "computeMetadata", "instance/", "meta-data",
)
ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def term_safe(text: str) -> str:
    """Strip ANSI escape sequences and control characters so
    server-supplied text cannot inject terminal escapes or fake log lines.
    Removing the ESC byte alone would leave printable ``[31m`` fragments;
    the whole sequence must go."""
    return CONTROL_CHARS.sub("", ANSI_ESCAPE.sub("", text))


def snippet(text: str, limit: int = 120) -> str:
    """Single-line, control-char-free preview of a response body."""
    return term_safe(" ".join(text.split()))[:limit]


@dataclass
class Finding:
    payload: Payload
    target_status: int | None  # HTTP status of the target's own response
    final_url: str | None      # URL after following target redirects
    body_length: int
    body_preview: str
    verdict: str
    evidence: str

    def as_dict(self) -> dict:
        return {
            "payload": self.payload.value,
            "group": self.payload.group,
            "note": self.payload.note,
            "target_status": self.target_status,
            "final_url": self.final_url,
            "body_length": self.body_length,
            "body_preview": self.body_preview,
            "verdict": self.verdict,
            "evidence": self.evidence,
        }


def _payload_host(payload_value: str) -> str | None:
    """Host part of a payload URL, if it parses as one."""
    parsed = urllib.parse.urlparse(payload_value)
    return parsed.hostname


class _RedirectCaptured(Exception):
    """Raised by the no-follow handler with the redirect target."""

    def __init__(self, location: str, status: int) -> None:
        super().__init__(location)
        self.location = location
        self.status = status


class _NoFollowRedirect(urllib.request.HTTPRedirectHandler):
    """Capture redirects instead of following them.

    Following a redirect would destroy the very evidence an open-redirect
    test looks for (and would send requests to the payload host, e.g.
    evil.example.com, which a test must never do).
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise _RedirectCaptured(newurl, code)


def _loose_host(value: str) -> str | None:
    """Best-effort host extraction for messy redirect values.

    Handles ``https:evil.example.com`` (scheme without slashes) and
    percent-encoded forms that ``urlparse`` reports as hostless.
    """
    text = urllib.parse.unquote(value.strip())
    text = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", "", text)
    text = text.lstrip("/")
    host = text.split("/")[0].split("@")[-1].split(":")[0]
    return host or None


def _looks_blocked(status: int | None, body: str) -> bool:
    if status in (400, 403, 422) and any(
        kw in body.lower() for kw in BLOCK_KEYWORDS
    ):
        return True
    return False


def classify(
    payload: Payload,
    target_status: int | None,
    final_url: str | None,
    body: str,
) -> tuple[str, str]:
    """Pure verdict function, kept separate so tests can drive it directly."""
    if target_status is None:
        return "ERROR", "request to target failed"

    # Lab JSON replies carry ground truth about the server-side fetch.
    try:
        lab = json.loads(body)
    except (ValueError, TypeError):
        lab = None
    if isinstance(lab, dict) and "fetched_status" in lab:
        fetched = lab["fetched_status"]
        if fetched is not None and 200 <= fetched < 300:
            return "FETCHED", f"lab reports server-side fetch -> HTTP {fetched}"
        if fetched is None and not lab.get("fetch_error") \
                and lab.get("length", 0) > 0:
            return "FETCHED", "lab reports server-side read (no HTTP status)"
        reason = str(lab.get("fetch_error") or "fetch failed")
        if any(kw in reason.lower() for kw in BLOCK_KEYWORDS):
            return "BLOCKED", f"lab refused fetch: {term_safe(reason)[:80]}"
        return "UNCLEAR", f"lab fetch failed: {term_safe(reason)[:80]}"

    if _looks_blocked(target_status, body):
        return "BLOCKED", f"target refused with HTTP {target_status}"

    if payload.group == "redirect" and final_url:
        payload_scheme = urllib.parse.urlparse(payload.value).scheme.lower()
        if payload_scheme in ("javascript", "data", "vbscript") and \
                final_url.lower().startswith(payload_scheme + ":"):
            return "OPEN-REDIRECT", (
                f"Location header reflects a {payload_scheme}: URI"
            )
        final_host = _loose_host(final_url)
        payload_host = _loose_host(payload.value)
        if final_host and payload_host and final_host == payload_host:
            return "OPEN-REDIRECT", f"client redirected to {final_host}"
    host = _payload_host(payload.value)
    if host and host in body:
        return "FETCHED", "payload host echoed in target response body"
    if any(marker in body for marker in METADATA_MARKERS):
        return "FETCHED", "cloud metadata marker present in response body"

    return "UNCLEAR", (
        f"HTTP {target_status}, {len(body)} bytes, "
        "no fetch/block/redirect evidence"
    )


def check_target_safety(target_template: str, allow_public: bool) -> None:
    """Refuse public targets unless the operator explicitly opts in.

    Loopback and RFC 1918 targets are always allowed: that is where labs
    and local dev servers live. Anything else requires
    ``--allow-public-target`` so a typo cannot turn a scan into traffic
    against someone else's infrastructure.
    """
    if "{payload}" not in target_template:
        raise ValueError("target URL must contain the {payload} placeholder")
    sample = target_template.replace("{payload}", "http://example.com/")
    host = urllib.parse.urlparse(sample).hostname
    if not host:
        raise ValueError("could not parse a host from the target URL")
    try:
        resolved = socket.gethostbyname(host)
        addr = ipaddress.ip_address(resolved)
    except (socket.gaierror, ValueError) as exc:
        raise ValueError(f"cannot resolve target host {host!r}: {exc}") from exc
    if addr.is_loopback or addr.is_private or addr.is_link_local:
        return
    if not allow_public:
        raise ValueError(
            f"target host {host!r} resolves to public IP {resolved}; "
            "re-run with --allow-public-target if this is your own application"
        )


def _request_url(template: str, payload: Payload) -> str:
    return template.replace(
        "{payload}", urllib.parse.quote(payload.value, safe="")
    )


def scan_one(
    template: str,
    payload: Payload,
    timeout: float = 5.0,
) -> Finding:
    """Send one payload to the target and classify the reply."""
    url = _request_url(template, payload)
    request = urllib.request.Request(url, headers={"User-Agent": "lleap/1.0"})
    opener = urllib.request.build_opener(_NoFollowRedirect)
    body = ""
    status: int | None = None
    final_url: str | None = None
    try:
        with opener.open(request, timeout=timeout) as response:
            status = response.status
            final_url = response.geturl()
            body = response.read(65536).decode("utf-8", errors="replace")
    except _RedirectCaptured as exc:
        status = exc.status
        final_url = urllib.parse.urljoin(url, exc.location)
        body = ""
    except urllib.error.HTTPError as exc:
        status = exc.code
        final_url = exc.geturl() if hasattr(exc, "geturl") else url
        try:
            body = exc.read(65536).decode("utf-8", errors="replace")
        except Exception:
            body = ""
    except Exception as exc:  # connection error, timeout, DNS failure
        return Finding(
            payload=payload,
            target_status=None,
            final_url=None,
            body_length=0,
            body_preview="",
            verdict="ERROR",
            evidence=f"{type(exc).__name__}: {term_safe(str(exc))[:100]}",
        )
    verdict, evidence = classify(payload, status, final_url, body)
    return Finding(
        payload=payload,
        target_status=status,
        final_url=final_url,
        body_length=len(body),
        body_preview=snippet(body),
        verdict=verdict,
        evidence=evidence,
    )


def scan(
    template: str,
    payloads: list[Payload],
    timeout: float = 5.0,
    delay: float = 0.0,
    allow_public: bool = False,
) -> list[Finding]:
    """Run a full payload set against the target template."""
    import time

    check_target_safety(template, allow_public)
    findings: list[Finding] = []
    for payload in payloads:
        findings.append(scan_one(template, payload, timeout=timeout))
        if delay:
            time.sleep(delay)
    return findings


def summarize(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.verdict] = counts.get(finding.verdict, 0) + 1
    return counts
