# aws-cloudfront-tls-audit

[![ci](https://github.com/moveeeax/aws-cloudfront-tls-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/moveeeax/aws-cloudfront-tls-audit/actions/workflows/ci.yml)
[![python](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue)](https://www.python.org/)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

A CloudFront distribution has four independent TLS settings and the console never
shows them on one screen. This reads every distribution config in one paginated
`ListDistributions` call and reports the viewer side and the origin side together.

What usually hides in there:

- a `MinimumProtocolVersion` of `TLSv1`, because that was the default when someone
  clicked through the wizard;
- a `ViewerProtocolPolicy` of `allow-all`, so `http://` keeps working forever;
- the `*.cloudfront.net` default certificate on a distribution that has a real
  `CNAME` pointed at it — every browser hitting the alias gets a name mismatch;
- TLS 1.3 to the browser and `http-only` to the origin.

## Rules

| rule | severity | trips when |
| --- | --- | --- |
| `DEFAULT_CERT_WITH_ALIAS` | high | `ViewerCertificate.CloudFrontDefaultCertificate` is true while `Aliases` is non-empty |
| `WEAK_MIN_PROTOCOL` | high | `MinimumProtocolVersion` is `SSLv3`, `TLSv1`, `TLSv1_2016` or `TLSv1.1_2016` |
| `VIEWER_ALLOWS_HTTP` | medium | the default or any ordered behavior uses `ViewerProtocolPolicy: allow-all` |
| `ORIGIN_INSECURE` | high | `OriginProtocolPolicy` is `http-only`, or `match-viewer` while some viewer behavior allows HTTP |
| `ORIGIN_WEAK_SSL_PROTOCOL` | medium | `OriginSslProtocols` still contains `SSLv3` or `TLSv1` |
| `BELOW_POLICY_FLOOR` | low | only with `--min-policy`: `MinimumProtocolVersion` is a TLS 1.2+ policy older than the floor |

One finding per distribution per rule. A distribution with eight `allow-all`
behaviors is a single `VIEWER_ALLOWS_HTTP` finding that lists all eight path
patterns, not eight lines of the same sentence. Every finding carries the exact
field to change and the `update-distribution` call shape.

### Minimum security policy

`WEAK_MIN_PROTOCOL` only catches policies that still negotiate below TLS 1.2, so
`TLSv1.2_2018` and `TLSv1.2_2019` pass it. A compliance scanner can be stricter:
Security Hub [CloudFront.15](https://docs.aws.amazon.com/securityhub/latest/userguide/cloudfront-controls.html#cloudfront-15)
passes only `TLSv1.2_2025` and `TLSv1.3_2025` (as documented on 2026-11-12).
`--min-policy` sets the floor:

```bash
aws-cloudfront-tls-audit --min-policy TLSv1.2_2025 --fail-on low
```

Policies are compared in this order, weakest first: `SSLv3`, `TLSv1`,
`TLSv1_2016`, `TLSv1.1_2016`, `TLSv1.2_2018`, `TLSv1.2_2019`, `TLSv1.2_2021`,
`TLSv1.2_2025`, `TLSv1.3_2025`. A distribution below the floor gets one
`BELOW_POLICY_FLOOR` finding; one that is already a `WEAK_MIN_PROTOCOL` finding
does not get a second one. A value the tool does not know (a policy newer than
this list) is not judged. Without `--min-policy` the rule does not run.

## How it works

`ListDistributions` returns full configs — `ViewerCertificate`, `Aliases`,
`Origins`, `DefaultCacheBehavior` and `CacheBehaviors` — so there is no
per-distribution `GetDistributionConfig` call and no rate-limit dance. The
service paginator walks the account; the rules are pure functions over the
returned dicts, which is why the whole test suite runs offline.

CloudFront is a global service: the client is pinned to `us-east-1` and there is
no `--region` flag.

## Install

```bash
pip install git+https://github.com/moveeeax/aws-cloudfront-tls-audit.git
```

Needs `cloudfront:ListDistributions`.

## Usage

```bash
aws-cloudfront-tls-audit
aws-cloudfront-tls-audit --format json --fail-on high
aws-cloudfront-tls-audit --distribution E1AAAAAAAAAAAA --ignore VIEWER_ALLOWS_HTTP
```

Against the recorded example account, no credentials needed:

```console
$ aws-cloudfront-tls-audit --from-file examples/messy-account.json
SEVERITY  DISTRIBUTION      NAME              RULE
--------  ----------------  ----------------  ------------------------
high      E1DEFAULTCERTAAA  cdn.example.com   DEFAULT_CERT_WITH_ALIAS
    serves the default *.cloudfront.net certificate while 2 alias(es) point at it: cdn.example.com, www.example.com — browsers hitting those names get a certificate name mismatch
    fix: request or import an ACM certificate covering cdn.example.com, www.example.com in us-east-1 ...

high      E3ORIGINCCCCCCC   docs.example.com  ORIGIN_INSECURE
    origin traffic can leave CloudFront unencrypted — origin-docs: http-only
    fix: set OriginProtocolPolicy=https-only on origin-docs ...

medium    E2WEAKTLSBBBBBB   api.example.com   VIEWER_ALLOWS_HTTP
    3 cache behavior(s) use ViewerProtocolPolicy=allow-all, so plain HTTP keeps serving content: (default), /api/*, /static/*
    fix: set ViewerProtocolPolicy to redirect-to-https (or https-only for an API) on (default), /api/*, /static/* ...

7 finding(s) across 4 distribution(s): high 5, medium 2
```

### Flags

| flag | effect |
| --- | --- |
| `--profile NAME` | AWS profile to use |
| `--distribution ID` | limit to this distribution id, repeatable |
| `--format table\|json\|csv` | output format, default `table` |
| `--fail-on high\|medium\|low\|never` | lowest severity that exits 1, default `high` |
| `--min-policy POLICY` | report `BELOW_POLICY_FLOOR` for policies older than `POLICY`, default off |
| `--ignore RULE,RULE` | drop rules from the output *and* the exit code |
| `--from-file PATH` | audit a recorded `ListDistributions` response instead of calling AWS |

### Exit codes

| code | meaning |
| --- | --- |
| 0 | clean, or nothing at or above `--fail-on` |
| 1 | a finding at or above `--fail-on` |
| 2 | an AWS API, credential or argument error |

## In CI

```yaml
- name: CloudFront TLS audit
  run: aws-cloudfront-tls-audit --fail-on high --format json
```

`--fail-on medium` once the high findings are cleared; `--ignore` for the
behaviors you have decided to keep on `allow-all`.

## Examples

`examples/` holds recorded `ListDistributions` responses: `messy-account.json`
(one distribution per failure mode plus a clean one), `hardened-account.json`,
`viewer-http-only.json` and `empty-account.json`. They are generated by
`examples/_build_fixtures.py` and are the same fixtures the test suite stubs into
botocore, so a response-shape drift fails CI rather than passing silently.

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest
```

No live AWS in the tests.

## License

MIT
