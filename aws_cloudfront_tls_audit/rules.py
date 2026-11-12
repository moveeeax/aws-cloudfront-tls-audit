"""The TLS rules, evaluated against a raw DistributionSummary dict."""

from __future__ import annotations

from typing import Callable, Iterable

from .collect import distribution_name
from .model import Finding

#: Minimum protocol versions that still negotiate protocols every modern
#: baseline rejects. ``TLSv1.2_2018``/``TLSv1.2_2019``/``TLSv1.2_2021`` are fine.
WEAK_MIN_PROTOCOLS = ("SSLv3", "TLSv1", "TLSv1_2016", "TLSv1.1_2016")
RECOMMENDED_MIN_PROTOCOL = "TLSv1.2_2021"

#: Every ViewerCertificate.MinimumProtocolVersion CloudFront accepts, weakest
#: first (the botocore ``MinimumProtocolVersion`` enum, reordered). ``--min-policy``
#: picks a floor from this list.
SECURITY_POLICY_ORDER = (
    "SSLv3",
    "TLSv1",
    "TLSv1_2016",
    "TLSv1.1_2016",
    "TLSv1.2_2018",
    "TLSv1.2_2019",
    "TLSv1.2_2021",
    "TLSv1.2_2025",
    "TLSv1.3_2025",
)

#: Origin SSL protocols that should never appear in an origin handshake.
WEAK_ORIGIN_SSL_PROTOCOLS = ("SSLv3", "TLSv1")

RULES: dict[str, str] = {
    "DEFAULT_CERT_WITH_ALIAS": "high",
    "WEAK_MIN_PROTOCOL": "high",
    "VIEWER_ALLOWS_HTTP": "medium",
    "ORIGIN_INSECURE": "high",
    "ORIGIN_WEAK_SSL_PROTOCOL": "medium",
    "BELOW_POLICY_FLOOR": "low",
}

UPDATE_CALL = (
    "aws cloudfront get-distribution-config --id {dist_id} > cfg.json, edit "
    "DistributionConfig, then aws cloudfront update-distribution --id {dist_id} "
    "--distribution-config file://cfg.json --if-match <ETag>"
)


def _behaviors(dist: dict) -> list[tuple[str, dict]]:
    """Default behavior plus every ordered behavior, labelled by path pattern."""
    out: list[tuple[str, dict]] = []
    default = dist.get("DefaultCacheBehavior")
    if default:
        out.append(("(default)", default))
    for behavior in (dist.get("CacheBehaviors") or {}).get("Items") or []:
        out.append((behavior.get("PathPattern", "(unnamed)"), behavior))
    return out


def _http_allowing_patterns(dist: dict) -> list[str]:
    return [
        pattern
        for pattern, behavior in _behaviors(dist)
        if behavior.get("ViewerProtocolPolicy") == "allow-all"
    ]


def check_default_cert_with_alias(dist: dict) -> Finding | None:
    cert = dist.get("ViewerCertificate") or {}
    aliases = (dist.get("Aliases") or {}).get("Items") or []
    if not cert.get("CloudFrontDefaultCertificate") or not aliases:
        return None
    shown = ", ".join(aliases)
    return _finding(
        "DEFAULT_CERT_WITH_ALIAS",
        dist,
        detail=(
            f"serves the default *.cloudfront.net certificate while {len(aliases)} "
            f"alias(es) point at it: {shown} — browsers hitting those names get a "
            "certificate name mismatch"
        ),
        remediation=(
            "request or import an ACM certificate covering "
            f"{shown} in us-east-1 (CloudFront only reads certificates from "
            "us-east-1, regardless of where the origin lives), then set "
            "ViewerCertificate.ACMCertificateArn with SSLSupportMethod=sni-only "
            f"and MinimumProtocolVersion={RECOMMENDED_MIN_PROTOCOL}; "
            + UPDATE_CALL.format(dist_id=dist.get("Id", "<id>"))
        ),
        targets=tuple(aliases),
    )


def check_weak_min_protocol(dist: dict) -> Finding | None:
    cert = dist.get("ViewerCertificate") or {}
    current = cert.get("MinimumProtocolVersion")
    if current not in WEAK_MIN_PROTOCOLS:
        return None
    return _finding(
        "WEAK_MIN_PROTOCOL",
        dist,
        detail=(
            f"ViewerCertificate.MinimumProtocolVersion is {current}, which still "
            "negotiates protocols below TLS 1.2"
        ),
        remediation=(
            f"set ViewerCertificate.MinimumProtocolVersion to "
            f"{RECOMMENDED_MIN_PROTOCOL} (current: {current}); "
            "the default certificate is pinned to TLSv1 and cannot be raised, so "
            "an ACM certificate in us-east-1 is a prerequisite if "
            "CloudFrontDefaultCertificate is still true; "
            + UPDATE_CALL.format(dist_id=dist.get("Id", "<id>"))
        ),
        targets=(current,),
    )


def check_viewer_allows_http(dist: dict) -> Finding | None:
    patterns = _http_allowing_patterns(dist)
    if not patterns:
        return None
    return _finding(
        "VIEWER_ALLOWS_HTTP",
        dist,
        detail=(
            f"{len(patterns)} cache behavior(s) use ViewerProtocolPolicy=allow-all, "
            f"so plain HTTP keeps serving content: {', '.join(patterns)}"
        ),
        remediation=(
            "set ViewerProtocolPolicy to redirect-to-https (or https-only for an "
            "API) on "
            + ", ".join(patterns)
            + "; "
            + UPDATE_CALL.format(dist_id=dist.get("Id", "<id>"))
        ),
        targets=tuple(patterns),
    )


def check_origin_insecure(dist: dict) -> Finding | None:
    """http-only origins, plus match-viewer origins behind an allow-all viewer.

    match-viewer is only as good as the viewer policy in front of it: with one
    allow-all behavior, an http:// request is proxied to the origin over http://.
    """
    viewer_allows_http = bool(_http_allowing_patterns(dist))
    offenders: list[str] = []
    reasons: list[str] = []
    for origin in (dist.get("Origins") or {}).get("Items") or []:
        custom = origin.get("CustomOriginConfig")
        if not custom:
            continue  # S3 origin access, no viewer-settable origin protocol
        policy = custom.get("OriginProtocolPolicy")
        origin_id = origin.get("Id", "(unnamed)")
        if policy == "http-only":
            offenders.append(origin_id)
            reasons.append(f"{origin_id}: http-only")
        elif policy == "match-viewer" and viewer_allows_http:
            offenders.append(origin_id)
            reasons.append(f"{origin_id}: match-viewer behind an allow-all behavior")
    if not offenders:
        return None
    return _finding(
        "ORIGIN_INSECURE",
        dist,
        detail="origin traffic can leave CloudFront unencrypted — " + "; ".join(reasons),
        remediation=(
            "set OriginProtocolPolicy=https-only on "
            + ", ".join(offenders)
            + " (and confirm the origin presents a certificate matching its "
            "Origins[].DomainName, otherwise CloudFront returns 502); "
            + UPDATE_CALL.format(dist_id=dist.get("Id", "<id>"))
        ),
        targets=tuple(offenders),
    )


def check_origin_weak_ssl_protocol(dist: dict) -> Finding | None:
    offenders: list[str] = []
    reasons: list[str] = []
    for origin in (dist.get("Origins") or {}).get("Items") or []:
        custom = origin.get("CustomOriginConfig") or {}
        protocols = (custom.get("OriginSslProtocols") or {}).get("Items") or []
        weak = [p for p in protocols if p in WEAK_ORIGIN_SSL_PROTOCOLS]
        if not weak:
            continue
        origin_id = origin.get("Id", "(unnamed)")
        offenders.append(origin_id)
        reasons.append(f"{origin_id}: {', '.join(weak)}")
    if not offenders:
        return None
    return _finding(
        "ORIGIN_WEAK_SSL_PROTOCOL",
        dist,
        detail="OriginSslProtocols still offers obsolete protocols — " + "; ".join(reasons),
        remediation=(
            "reduce CustomOriginConfig.OriginSslProtocols to [TLSv1.2] on "
            + ", ".join(offenders)
            + "; "
            + UPDATE_CALL.format(dist_id=dist.get("Id", "<id>"))
        ),
        targets=tuple(offenders),
    )


def check_below_policy_floor(dist: dict, floor: str) -> Finding | None:
    """A TLS 1.2+ policy that is still older than the ``--min-policy`` floor.

    Policies in WEAK_MIN_PROTOCOLS are left to WEAK_MIN_PROTOCOL so one setting
    does not produce two findings. Values missing from SECURITY_POLICY_ORDER
    (a policy newer than this tool) are not judged.
    """
    cert = dist.get("ViewerCertificate") or {}
    current = cert.get("MinimumProtocolVersion")
    if current in WEAK_MIN_PROTOCOLS or current not in SECURITY_POLICY_ORDER:
        return None
    if SECURITY_POLICY_ORDER.index(current) >= SECURITY_POLICY_ORDER.index(floor):
        return None
    return _finding(
        "BELOW_POLICY_FLOOR",
        dist,
        detail=(
            f"ViewerCertificate.MinimumProtocolVersion is {current}, older than "
            f"the required floor {floor}"
        ),
        remediation=(
            f"set ViewerCertificate.MinimumProtocolVersion to {floor} or newer "
            f"(current: {current}); "
            + UPDATE_CALL.format(dist_id=dist.get("Id", "<id>"))
        ),
        targets=(current,),
    )


CHECKS: tuple[Callable[[dict], Finding | None], ...] = (
    check_default_cert_with_alias,
    check_weak_min_protocol,
    check_viewer_allows_http,
    check_origin_insecure,
    check_origin_weak_ssl_protocol,
)


def _finding(rule: str, dist: dict, *, detail: str, remediation: str, targets=()) -> Finding:
    return Finding(
        rule=rule,
        severity=RULES[rule],
        distribution_id=dist.get("Id", "<unknown>"),
        name=distribution_name(dist),
        detail=detail,
        remediation=remediation,
        targets=tuple(targets),
    )


def audit(
    distributions: Iterable[dict],
    ignore: Iterable[str] = (),
    min_policy: str | None = None,
) -> list[Finding]:
    """Run every rule over every distribution, dropping ignored rules.

    Ignored rules disappear from the output *and* from the exit code; that is
    the whole point of ``--ignore``. BELOW_POLICY_FLOOR only runs when
    ``min_policy`` is set.
    """
    if min_policy is not None and min_policy not in SECURITY_POLICY_ORDER:
        raise ValueError(f"unknown security policy: {min_policy}")
    skip = {r.strip().upper() for r in ignore if r.strip()}
    findings: list[Finding] = []
    for dist in distributions:
        for check in CHECKS:
            finding = check(dist)
            if finding is not None and finding.rule not in skip:
                findings.append(finding)
        if min_policy is not None:
            finding = check_below_policy_floor(dist, min_policy)
            if finding is not None and finding.rule not in skip:
                findings.append(finding)
    return findings
