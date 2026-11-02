"""Command line entrypoint.

Exit codes: 0 clean, 1 a finding at or above ``--fail-on``, 2 an AWS API or
credential error.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Sequence

from . import __version__
from .collect import list_distributions, make_client
from .model import AwsError, severity_rank
from .report import render, sort_findings
from .rules import RULES, audit

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_AWS_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aws-cloudfront-tls-audit",
        description=(
            "Audit every CloudFront distribution's viewer and origin TLS posture: "
            "default certificates on aliased distributions, legacy minimum protocol "
            "versions, allow-all viewer policies and http-only origins."
        ),
        epilog="rules: " + ", ".join(f"{name} ({sev})" for name, sev in RULES.items()),
    )
    parser.add_argument("--profile", help="AWS profile name (CloudFront is global; no --region)")
    parser.add_argument(
        "--distribution",
        action="append",
        default=[],
        metavar="ID",
        help="limit the audit to this distribution id (repeatable)",
    )
    parser.add_argument(
        "--format", choices=("table", "json", "csv"), default="table", help="output format"
    )
    parser.add_argument(
        "--fail-on",
        choices=("high", "medium", "low", "never"),
        default="high",
        help="lowest severity that makes the command exit 1 (default: high)",
    )
    parser.add_argument(
        "--ignore",
        default="",
        metavar="RULE,RULE",
        help="comma-separated rules to drop from the output and the exit code",
    )
    parser.add_argument(
        "--from-file",
        metavar="PATH",
        help=(
            "audit a recorded ListDistributions response instead of calling AWS "
            "(the examples/ fixtures use this; no credentials needed)"
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def load_from_file(path: str) -> list[dict]:
    """Accept either a raw ListDistributions response or a bare list of items."""
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return data.get("DistributionList", {}).get("Items") or []
    raise AwsError(f"{path}: expected a ListDistributions response or a list of distributions")


def exit_code(findings, fail_on: str) -> int:
    if fail_on == "never" or not findings:
        return EXIT_OK
    threshold = severity_rank(fail_on)
    worst = max(severity_rank(f.severity) for f in findings)
    return EXIT_FINDINGS if worst >= threshold else EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    ignore = args.ignore.split(",") if args.ignore else []

    unknown = [r.strip().upper() for r in ignore if r.strip() and r.strip().upper() not in RULES]
    if unknown:
        print(
            f"unknown rule(s) in --ignore: {', '.join(unknown)}; known rules: "
            + ", ".join(RULES),
            file=sys.stderr,
        )
        return EXIT_AWS_ERROR

    try:
        if args.from_file:
            distributions = load_from_file(args.from_file)
            if args.distribution:
                wanted = set(args.distribution)
                distributions = [d for d in distributions if d.get("Id") in wanted]
        else:
            client = make_client(args.profile)
            distributions = list_distributions(client, args.distribution)
    except AwsError as exc:
        print(f"aws-cloudfront-tls-audit: {exc}", file=sys.stderr)
        return EXIT_AWS_ERROR
    except OSError as exc:
        print(f"aws-cloudfront-tls-audit: {exc}", file=sys.stderr)
        return EXIT_AWS_ERROR

    findings = sort_findings(audit(distributions, ignore))
    print(render(findings, args.format, len(distributions)))
    return exit_code(findings, args.fail_on)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
