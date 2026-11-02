"""Severities and the finding record shared by the rules and the reporters."""

from __future__ import annotations

from dataclasses import dataclass, field

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}
SEVERITIES = ("high", "medium", "low")


def severity_rank(severity: str) -> int:
    try:
        return SEVERITY_ORDER[severity]
    except KeyError:  # pragma: no cover - guarded by argparse choices
        raise ValueError(f"unknown severity: {severity}") from None


@dataclass(frozen=True)
class Finding:
    """One rule hit against one distribution.

    ``targets`` collects the offending path patterns or origin ids so a
    distribution with eight ``allow-all`` behaviors stays a single finding
    instead of eight near-identical lines.
    """

    rule: str
    severity: str
    distribution_id: str
    name: str
    detail: str
    remediation: str
    targets: tuple[str, ...] = field(default=())

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "distribution_id": self.distribution_id,
            "name": self.name,
            "targets": list(self.targets),
            "detail": self.detail,
            "remediation": self.remediation,
        }


class AwsError(RuntimeError):
    """An AWS API or credential failure; the CLI turns this into exit 2."""
