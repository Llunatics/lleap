"""Rendering of scan findings: terminal table and JSON report."""

from __future__ import annotations

import json

from .scanner import Finding, summarize

VERDICT_MARK = {
    "FETCHED": "!!",
    "OPEN-REDIRECT": "!!",
    "BLOCKED": "ok",
    "UNCLEAR": "??",
    "ERROR": "xx",
}


def render_table(findings: list[Finding]) -> str:
    """Plain-text table (no third-party dependency, pipe-friendly)."""
    rows = []
    header = f"{'GROUP':<9} {'VERDICT':<13} {'STATUS':>6}  PAYLOAD"
    rows.append(header)
    rows.append("-" * len(header))
    for finding in findings:
        mark = VERDICT_MARK.get(finding.verdict, "  ")
        status = (
            str(finding.target_status) if finding.target_status is not None
            else "-"
        )
        rows.append(
            f"{finding.payload.group:<9} {mark} {finding.verdict:<10} "
            f"{status:>6}  {finding.payload.value}"
        )
        rows.append(f"{'':<9} {'':<13} {'':>6}  -> {finding.evidence}")
    counts = summarize(findings)
    rows.append("")
    rows.append("Summary: " + ", ".join(
        f"{verdict}={counts[verdict]}" for verdict in sorted(counts)
    ))
    return "\n".join(rows)


def render_json(findings: list[Finding], target: str) -> str:
    return json.dumps(
        {
            "target": target,
            "summary": summarize(findings),
            "findings": [finding.as_dict() for finding in findings],
        },
        indent=2,
    )
