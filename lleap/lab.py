"""Vulnerable-by-design lab server for local SSRF / open-redirect testing.

Binds 127.0.0.1 only and exists for exactly one purpose: giving lleap a
target whose behaviour is known, so ``lleap demo`` can prove the scanner
works without touching any real application.

Endpoints:

- ``GET /fetch?url=<value>`` — fetches ``value`` server-side (following
  redirects) and returns JSON: ``fetched_status``, ``fetched_url``,
  ``length`` and a ``preview`` of the body. Fetch failures return
  ``fetched_status: null`` plus ``fetch_error``. This endpoint is
  intentionally vulnerable: never expose it beyond loopback.
- ``GET /redirect?next=<value>`` — responds 302 to ``value``.
- ``GET /canary/<token>`` — records a hit in the in-memory log and
  answers 200. A hit proves the lab server itself requested that URL,
  which is the ground truth behind ``lleap demo``.
- ``GET /canary-hits`` — returns the hit log as JSON (loopback only).

The lab deliberately performs no allow-listing: a "secure" fetcher would
make the demo meaningless. The safety boundary is the bind address.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class CanaryLog:
    """Thread-safe record of canary hits."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._hits: list[dict] = []

    def record(self, token: str, path: str) -> None:
        with self._lock:
            self._hits.append(
                {"token": token, "path": path, "time": round(time.time(), 3)}
            )

    def snapshot(self) -> list[dict]:
        with self._lock:
            return list(self._hits)


def make_handler(log: CanaryLog) -> type[BaseHTTPRequestHandler]:
    class LabHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "lleap-lab/1.0"

        def log_message(self, *args):  # keep demo output clean
            pass

        def _send_json(self, status: int, obj: dict) -> None:
            data = json.dumps(obj).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _query(self) -> dict[str, list[str]]:
            return urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)

        def do_GET(self) -> None:  # noqa: N802 - stdlib handler name
            parsed = urllib.parse.urlparse(self.path)
            query = self._query()
            if parsed.path == "/fetch":
                self._handle_fetch(query)
            elif parsed.path == "/redirect":
                self._handle_redirect(query)
            elif parsed.path.startswith("/canary/"):
                token = parsed.path[len("/canary/"):]
                log.record(token, parsed.path)
                self._send_json(200, {"canary": token, "hit": True})
            elif parsed.path == "/canary-hits":
                self._send_json(200, {"hits": log.snapshot()})
            else:
                self._send_json(404, {"error": "unknown lab endpoint"})

        def _handle_fetch(self, query: dict[str, list[str]]) -> None:
            values = query.get("url")
            if not values:
                self._send_json(400, {"error": "missing url parameter"})
                return
            target = values[0]
            try:
                request = urllib.request.Request(
                    target, headers={"User-Agent": "lleap-lab/1.0"}
                )
                with urllib.request.urlopen(request, timeout=3) as response:
                    body = response.read(65536).decode("utf-8", errors="replace")
                    # Non-HTTP handlers (file://) return no status; a body
                    # that was actually read is a successful fetch.
                    status = response.status if response.status is not None else 200
                    self._send_json(200, {
                        "fetched_status": status,
                        "fetched_url": response.geturl(),
                        "length": len(body),
                        "preview": " ".join(body.split())[:200],
                    })
            except urllib.error.HTTPError as exc:
                # An HTTP error status still proves the fetch happened.
                body = ""
                try:
                    body = exc.read(65536).decode("utf-8", errors="replace")
                except Exception:
                    pass
                self._send_json(200, {
                    "fetched_status": exc.code,
                    "fetched_url": target,
                    "length": len(body),
                    "preview": " ".join(body.split())[:200],
                })
            except Exception as exc:
                self._send_json(200, {
                    "fetched_status": None,
                    "fetched_url": target,
                    "length": 0,
                    "preview": "",
                    "fetch_error": f"{type(exc).__name__}: {exc}",
                })

        def _handle_redirect(self, query: dict[str, list[str]]) -> None:
            values = query.get("next")
            if not values:
                self._send_json(400, {"error": "missing next parameter"})
                return
            self.send_response(302)
            self.send_header("Location", values[0])
            self.send_header("Content-Length", "0")
            self.end_headers()

    return LabHandler


def start_lab(port: int = 0) -> tuple[ThreadingHTTPServer, CanaryLog, int]:
    """Start the lab on 127.0.0.1; ``port=0`` picks a free port."""
    log = CanaryLog()
    server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(log))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, log, server.server_address[1]
