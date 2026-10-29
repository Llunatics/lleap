"""Command line interface for lleap."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .lab import start_lab
from .payloads import GROUPS, Payload, payloads_for
from .report import render_json, render_table
from .scanner import scan, scan_one

WARNING = (
    "WARNING: only test applications you own or have written permission "
    "to test. lleap sends SSRF and open-redirect payloads at the target "
    "you point it at."
)


def _target_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--target", required=True,
        help="target URL template containing {payload}, e.g. "
             "'http://127.0.0.1:8901/fetch?url={payload}'",
    )


def _common_scan_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--sets", default=",".join(GROUPS),
        help="comma-separated payload groups "
             f"({', '.join(GROUPS)}); default: all",
    )
    parser.add_argument("--timeout", type=float, default=5.0,
                        help="per-request timeout in seconds (default: 5)")
    parser.add_argument("--delay", type=float, default=0.0,
                        help="pause between requests in seconds (default: 0)")
    parser.add_argument("--json", dest="json_out", default=None, metavar="FILE",
                        help="also write the full report as JSON to FILE")
    parser.add_argument("--allow-public-target", action="store_true",
                        help="permit targets resolving to a public IP")
    parser.add_argument("--quiet", action="store_true",
                        help="skip the warning banner")


def _parse_sets(value: str) -> list[Payload]:
    if not value.strip():
        # An explicit empty --sets used to fall through to "all groups"
        # silently; an empty selection is a typo, not a default.
        print("lleap: error: --sets must name at least one payload group",
              file=sys.stderr)
        raise SystemExit(2)
    groups = tuple(part.strip() for part in value.split(",") if part.strip())
    try:
        return payloads_for(groups or None)
    except ValueError as exc:
        print(f"lleap: error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc


def _print_findings(findings, target, json_out, quiet) -> int:
    if not quiet:
        print(WARNING, file=sys.stderr)
    print(render_table(findings))
    if json_out:
        try:
            with open(json_out, "w", encoding="utf-8") as handle:
                handle.write(render_json(findings, target))
        except OSError as exc:
            print(f"lleap: error: cannot write JSON report to {json_out}: "
                  f"{exc}", file=sys.stderr)
            return 2
        print(f"\nJSON report written to {json_out}")
    worst = any(
        f.verdict in ("FETCHED", "OPEN-REDIRECT") for f in findings
    )
    return 1 if worst else 0


def cmd_scan(args: argparse.Namespace) -> int:
    # Validate up front: a negative timeout used to surface as an
    # all-ERROR scan with exit code 0 (indistinguishable from a clean
    # target), and a negative delay only failed with a cryptic sleep
    # error after the first request.
    if args.timeout <= 0:
        print("lleap: error: --timeout must be positive", file=sys.stderr)
        return 2
    if args.delay < 0:
        print("lleap: error: --delay must not be negative", file=sys.stderr)
        return 2
    payloads = _parse_sets(args.sets)
    try:
        findings = scan(
            args.target, payloads, timeout=args.timeout, delay=args.delay,
            allow_public=args.allow_public_target,
        )
    except ValueError as exc:
        print(f"lleap: error: {exc}", file=sys.stderr)
        return 2
    return _print_findings(findings, args.target, args.json_out, args.quiet)


def cmd_lab(args: argparse.Namespace) -> int:
    if not 0 <= args.port <= 65535:
        print(f"lleap: error: --port must be 0-65535, got {args.port}",
              file=sys.stderr)
        return 2
    try:
        server, _log, port = start_lab(args.port)
    except OSError as exc:
        print(f"lleap: error: cannot listen on port {args.port}: {exc}",
              file=sys.stderr)
        return 2
    print(f"lleap lab listening on http://127.0.0.1:{port} (loopback only)")
    print("Endpoints: /fetch?url=  /redirect?next=  /canary/<token>")
    print("Press Ctrl-C to stop. WARNING: the lab fetcher is intentionally")
    print("vulnerable — never expose this port beyond loopback.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping lab.")
    finally:
        server.shutdown()
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    """Lab in a thread + full scan against it, with canary ground truth."""
    server, log, port = start_lab(0)
    try:
        fetch_target = f"http://127.0.0.1:{port}/fetch?url={{payload}}"
        redirect_target = f"http://127.0.0.1:{port}/redirect?next={{payload}}"
        canary = Payload(
            value=f"http://127.0.0.1:{port}/canary/demo",
            group="localhost", note="canary proving a server-side fetch",
        )
        canary_finding = scan_one(fetch_target, canary, timeout=5.0)
        findings = [canary_finding]
        findings.extend(scan(
            fetch_target,
            [p for p in payloads_for() if p.group != "redirect"],
            timeout=5.0,
        ))
        findings.extend(scan(
            redirect_target,
            [p for p in payloads_for() if p.group == "redirect"],
            timeout=5.0,
        ))
        code = _print_findings(findings, fetch_target, args.json_out, quiet=True)
        hits = log.snapshot()
        print(f"\nCanary hits recorded by the lab server: {len(hits)}")
        for hit in hits:
            print(f"  - {hit['path']}")
        if not hits:
            print("  (none — the lab did not fetch the canary URL)")
        return code
    finally:
        server.shutdown()


def cmd_list(args: argparse.Namespace) -> int:
    payloads = _parse_sets(args.sets) if args.sets is not None \
        else payloads_for()
    for payload in payloads:
        print(f"{payload.group:<9} {payload.value:<55} # {payload.note}")
    print(f"\n{len(payloads)} payload(s) in {len(set(p.group for p in payloads))} group(s).")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lleap",
        description="SSRF and open-redirect tester for your own apps and labs.",
    )
    parser.add_argument("--version", action="version",
                        version=f"lleap {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="scan a target URL template")
    _target_arg(scan_p)
    _common_scan_args(scan_p)
    scan_p.set_defaults(func=cmd_scan)

    lab_p = sub.add_parser("lab", help="run the vulnerable-by-design lab server")
    lab_p.add_argument("--port", type=int, default=8901,
                       help="port to listen on (default: 8901)")
    lab_p.set_defaults(func=cmd_lab)

    demo_p = sub.add_parser("demo", help="lab + full scan with canary proof")
    demo_p.add_argument("--json", dest="json_out", default=None, metavar="FILE",
                        help="also write the full report as JSON to FILE")
    demo_p.set_defaults(func=cmd_demo)

    list_p = sub.add_parser("list-payloads", help="print the payload catalog")
    list_p.add_argument("--sets", default=None,
                        help="comma-separated groups to show (default: all)")
    list_p.set_defaults(func=cmd_list)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
