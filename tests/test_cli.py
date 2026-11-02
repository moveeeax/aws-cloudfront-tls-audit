from __future__ import annotations

import csv
import io
import json

import pytest

from aws_cloudfront_tls_audit.cli import main


def run(capsys, *argv):
    code = main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_clean_account_exits_zero(capsys, examples_dir):
    code, out, _ = run(capsys, "--from-file", str(examples_dir / "hardened-account.json"))
    assert code == 0
    assert "No TLS findings across 2 distribution(s)." in out


def test_messy_account_exits_one_on_high(capsys, examples_dir):
    code, out, _ = run(capsys, "--from-file", str(examples_dir / "messy-account.json"))
    assert code == 1
    assert "7 finding(s) across 4 distribution(s): high 5, medium 2" in out
    assert "DEFAULT_CERT_WITH_ALIAS" in out
    assert "fix:" in out


def test_fail_on_threshold_respects_severity(capsys, examples_dir):
    fixture = str(examples_dir / "viewer-http-only.json")
    assert run(capsys, "--from-file", fixture, "--fail-on", "high")[0] == 0
    assert run(capsys, "--from-file", fixture, "--fail-on", "medium")[0] == 1
    assert run(capsys, "--from-file", fixture, "--fail-on", "low")[0] == 1
    assert run(capsys, "--from-file", fixture, "--fail-on", "never")[0] == 0


def test_ignore_changes_output_and_exit_code(capsys, examples_dir):
    fixture = str(examples_dir / "viewer-http-only.json")
    code, out, _ = run(capsys, "--from-file", fixture, "--fail-on", "medium", "--ignore", "VIEWER_ALLOWS_HTTP")
    assert code == 0
    assert "VIEWER_ALLOWS_HTTP" not in out


def test_distribution_flag_narrows_the_scan(capsys, examples_dir):
    code, out, _ = run(
        capsys,
        "--from-file",
        str(examples_dir / "messy-account.json"),
        "--distribution",
        "E3ORIGINCCCCCCC",
    )
    assert code == 1
    assert "across 1 distribution(s)" in out
    assert "E1DEFAULTCERTAAA" not in out


def test_json_format_is_machine_readable(capsys, examples_dir):
    code, out, _ = run(
        capsys, "--from-file", str(examples_dir / "messy-account.json"), "--format", "json"
    )
    payload = json.loads(out)
    assert code == 1
    assert payload["distributions_scanned"] == 4
    assert payload["summary"] == {"total": 7, "high": 5, "medium": 2, "low": 0}
    assert payload["findings"][0]["severity"] == "high"
    assert set(payload["findings"][0]) == {
        "rule",
        "severity",
        "distribution_id",
        "name",
        "targets",
        "detail",
        "remediation",
    }


def test_csv_format_has_one_row_per_finding(capsys, examples_dir):
    _, out, _ = run(
        capsys, "--from-file", str(examples_dir / "messy-account.json"), "--format", "csv"
    )
    rows = list(csv.reader(io.StringIO(out)))
    assert rows[0][:4] == ["rule", "severity", "distribution_id", "name"]
    assert len(rows) == 8


def test_findings_are_sorted_worst_first(capsys, examples_dir):
    _, out, _ = run(
        capsys, "--from-file", str(examples_dir / "messy-account.json"), "--format", "csv"
    )
    severities = [row[1] for row in list(csv.reader(io.StringIO(out)))[1:]]
    assert severities == sorted(severities, key=lambda s: 0 if s == "high" else 1)


def test_unknown_ignore_rule_exits_two(capsys, examples_dir):
    code, _, err = run(
        capsys,
        "--from-file",
        str(examples_dir / "messy-account.json"),
        "--ignore",
        "NO_SUCH_RULE",
    )
    assert code == 2
    assert "unknown rule(s)" in err


def test_missing_file_exits_two_without_traceback(capsys, tmp_path):
    code, _, err = run(capsys, "--from-file", str(tmp_path / "nope.json"))
    assert code == 2
    assert "nope.json" in err


def test_aws_error_exits_two(capsys, monkeypatch):
    import aws_cloudfront_tls_audit.cli as cli
    from aws_cloudfront_tls_audit.model import AwsError

    def boom(_profile=None):
        raise AwsError("AccessDenied: cloudfront:ListDistributions")

    monkeypatch.setattr(cli, "make_client", boom)
    code, _, err = run(capsys)
    assert code == 2
    assert "AccessDenied" in err
    assert "Traceback" not in err


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
