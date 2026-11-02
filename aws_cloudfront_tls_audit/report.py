"""table / json / csv renderers. No rendering dependency on purpose."""

from __future__ import annotations

import csv
import io
import json
from typing import Sequence

from .model import Finding, severity_rank

HEADERS = ("SEVERITY", "DISTRIBUTION", "NAME", "RULE")


def sort_findings(findings: Sequence[Finding]) -> list[Finding]:
    """Worst first, then stable by distribution id and rule name."""
    return sorted(
        findings,
        key=lambda f: (-severity_rank(f.severity), f.distribution_id, f.rule),
    )


def render(findings: Sequence[Finding], fmt: str, scanned: int) -> str:
    if fmt == "json":
        return _render_json(findings, scanned)
    if fmt == "csv":
        return _render_csv(findings)
    return _render_table(findings, scanned)


def _render_table(findings: Sequence[Finding], scanned: int) -> str:
    if not findings:
        return f"No TLS findings across {scanned} distribution(s)."

    rows = [
        (f.severity, f.distribution_id, f.name, f.rule) for f in findings
    ]
    widths = [
        max(len(HEADERS[i]), *(len(row[i]) for row in rows)) for i in range(len(HEADERS))
    ]
    lines = ["  ".join(h.ljust(widths[i]) for i, h in enumerate(HEADERS)).rstrip()]
    lines.append("  ".join("-" * widths[i] for i in range(len(HEADERS))))
    for finding, row in zip(findings, rows):
        lines.append("  ".join(row[i].ljust(widths[i]) for i in range(len(HEADERS))).rstrip())
        lines.append(f"    {finding.detail}")
        lines.append(f"    fix: {finding.remediation}")
        lines.append("")

    counts = _counts(findings)
    summary = ", ".join(f"{sev} {counts[sev]}" for sev in ("high", "medium", "low") if counts[sev])
    lines.append(f"{len(findings)} finding(s) across {scanned} distribution(s): {summary}")
    return "\n".join(lines)


def _render_json(findings: Sequence[Finding], scanned: int) -> str:
    counts = _counts(findings)
    payload = {
        "distributions_scanned": scanned,
        "findings": [f.to_dict() for f in findings],
        "summary": {"total": len(findings), **counts},
    }
    return json.dumps(payload, indent=2, sort_keys=False)


def _render_csv(findings: Sequence[Finding]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(
        ["rule", "severity", "distribution_id", "name", "targets", "detail", "remediation"]
    )
    for f in findings:
        writer.writerow(
            [f.rule, f.severity, f.distribution_id, f.name, " ".join(f.targets), f.detail, f.remediation]
        )
    return buf.getvalue().rstrip("\n")


def _counts(findings: Sequence[Finding]) -> dict[str, int]:
    counts = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        counts[f.severity] += 1
    return counts
