# examples

Recorded `ListDistributions` responses, usable with `--from-file` and stubbed
into botocore by the test suite.

| file | what it holds |
| --- | --- |
| `messy-account.json` | four distributions: default cert + alias, legacy `TLSv1.1_2016` with `allow-all` behaviors and a `match-viewer` origin, an `http-only` origin offering `SSLv3`, and a clean S3-backed one |
| `hardened-account.json` | two clean distributions, zero findings |
| `viewer-http-only.json` | one distribution tripping only `VIEWER_ALLOWS_HTTP`, for the `--fail-on` boundary |
| `empty-account.json` | a `DistributionList` with no `Items` key at all, which is what an empty account returns |

```bash
aws-cloudfront-tls-audit --from-file examples/hardened-account.json   # exit 0
aws-cloudfront-tls-audit --from-file examples/messy-account.json      # exit 1
aws-cloudfront-tls-audit --from-file examples/messy-account.json --format json
```

Regenerate after changing a scenario, then commit the diff:

```bash
python3 examples/_build_fixtures.py
```

CI re-runs the generator and fails on any diff, so the checked-in JSON always
matches the builder.
