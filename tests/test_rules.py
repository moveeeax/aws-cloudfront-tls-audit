from __future__ import annotations

import pytest

from aws_cloudfront_tls_audit.rules import (
    RECOMMENDED_MIN_PROTOCOL,
    RULES,
    SECURITY_POLICY_ORDER,
    audit,
)


def by_rule(findings):
    out = {}
    for f in findings:
        out.setdefault(f.rule, []).append(f)
    return out


def test_hardened_account_is_clean(hardened):
    assert audit(hardened) == []


def test_messy_account_rule_counts(messy):
    grouped = by_rule(audit(messy))
    assert sorted(grouped) == [
        "DEFAULT_CERT_WITH_ALIAS",
        "ORIGIN_INSECURE",
        "ORIGIN_WEAK_SSL_PROTOCOL",
        "VIEWER_ALLOWS_HTTP",
        "WEAK_MIN_PROTOCOL",
    ]
    assert len(grouped["WEAK_MIN_PROTOCOL"]) == 2
    assert len(grouped["ORIGIN_INSECURE"]) == 2
    # the clean S3-backed distribution contributes nothing
    assert all(f.distribution_id != "E4HARDENEDDDDDD" for f in audit(messy))


def test_default_cert_with_alias_names_alias_and_us_east_1(messy):
    (finding,) = by_rule(audit(messy))["DEFAULT_CERT_WITH_ALIAS"]
    assert finding.severity == "high"
    assert finding.distribution_id == "E1DEFAULTCERTAAA"
    assert finding.name == "cdn.example.com"
    assert "cdn.example.com" in finding.detail
    assert finding.targets == ("cdn.example.com", "www.example.com")
    assert "us-east-1" in finding.remediation


def test_weak_min_protocol_names_current_and_recommended(messy):
    findings = {f.distribution_id: f for f in by_rule(audit(messy))["WEAK_MIN_PROTOCOL"]}
    legacy = findings["E1DEFAULTCERTAAA"]
    assert legacy.severity == "high"
    assert "TLSv1" in legacy.detail
    assert RECOMMENDED_MIN_PROTOCOL in legacy.remediation
    assert findings["E2WEAKTLSBBBBBB"].targets == ("TLSv1.1_2016",)


def test_viewer_allows_http_lists_path_patterns(messy):
    (finding,) = by_rule(audit(messy))["VIEWER_ALLOWS_HTTP"]
    assert finding.severity == "medium"
    # the default behavior plus two ordered ones; /api/v2/* is already redirecting
    assert finding.targets == ("(default)", "/api/*", "/static/*")
    assert "/api/v2/*" not in finding.detail


def test_origin_insecure_covers_http_only_and_match_viewer(messy):
    findings = {f.distribution_id: f for f in by_rule(audit(messy))["ORIGIN_INSECURE"]}
    assert "http-only" in findings["E3ORIGINCCCCCCC"].detail
    assert "match-viewer" in findings["E2WEAKTLSBBBBBB"].detail
    assert all(f.severity == "high" for f in findings.values())


def test_match_viewer_is_clean_when_no_behavior_allows_http(messy):
    dist = next(d for d in messy if d["Id"] == "E2WEAKTLSBBBBBB")
    dist["DefaultCacheBehavior"]["ViewerProtocolPolicy"] = "redirect-to-https"
    for behavior in dist["CacheBehaviors"]["Items"]:
        behavior["ViewerProtocolPolicy"] = "redirect-to-https"
    grouped = by_rule(audit([dist]))
    assert "ORIGIN_INSECURE" not in grouped
    assert "VIEWER_ALLOWS_HTTP" not in grouped


def test_origin_weak_ssl_protocol_names_the_protocols(messy):
    (finding,) = by_rule(audit(messy))["ORIGIN_WEAK_SSL_PROTOCOL"]
    assert finding.severity == "medium"
    assert "SSLv3" in finding.detail and "TLSv1" in finding.detail
    assert finding.targets == ("origin-docs",)


def test_s3_origin_is_not_audited_for_origin_protocol(hardened):
    web = next(d for d in hardened if d["Id"] == "E6CLEANFFFFFFFF")
    assert "S3OriginConfig" in web["Origins"]["Items"][0]
    assert audit([web]) == []


def test_default_cert_without_alias_is_not_a_finding(messy):
    dist = next(d for d in messy if d["Id"] == "E1DEFAULTCERTAAA")
    dist["Aliases"] = {"Quantity": 0, "Items": []}
    assert "DEFAULT_CERT_WITH_ALIAS" not in by_rule(audit([dist]))


def test_ignore_drops_a_rule(messy):
    grouped = by_rule(audit(messy, ignore=["VIEWER_ALLOWS_HTTP", "weak_min_protocol"]))
    assert "VIEWER_ALLOWS_HTTP" not in grouped
    assert "WEAK_MIN_PROTOCOL" not in grouped
    assert "ORIGIN_INSECURE" in grouped


def test_viewer_http_only_fixture_trips_exactly_one_rule(viewer_http_only):
    findings = audit(viewer_http_only)
    assert [f.rule for f in findings] == ["VIEWER_ALLOWS_HTTP"]


@pytest.mark.parametrize("rule,severity", sorted(RULES.items()))
def test_every_rule_has_a_known_severity(rule, severity):
    assert severity in ("high", "medium", "low")


def test_below_policy_floor_is_off_by_default(hardened):
    assert "BELOW_POLICY_FLOOR" not in by_rule(audit(hardened))


def test_below_policy_floor_flags_tls12_policies_under_the_floor(hardened):
    (finding,) = by_rule(audit(hardened, min_policy="TLSv1.2_2021"))["BELOW_POLICY_FLOOR"]
    assert finding.severity == "low"
    assert finding.targets == ("TLSv1.2_2019",)
    assert "TLSv1.2_2021" in finding.detail
    assert "TLSv1.2_2021" in finding.remediation


def test_below_policy_floor_2025_catches_2021(hardened):
    findings = by_rule(audit(hardened, min_policy="TLSv1.2_2025"))["BELOW_POLICY_FLOOR"]
    assert sorted(f.targets for f in findings) == [("TLSv1.2_2019",), ("TLSv1.2_2021",)]


@pytest.mark.parametrize("current", ["TLSv1.2_2025", "TLSv1.3_2025"])
def test_policy_at_or_above_floor_passes(hardened, current):
    dist = hardened[0]
    dist["ViewerCertificate"]["MinimumProtocolVersion"] = current
    assert audit([dist], min_policy="TLSv1.2_2025") == []


def test_tls13_floor_rejects_tls12_2025(hardened):
    dist = hardened[0]
    dist["ViewerCertificate"]["MinimumProtocolVersion"] = "TLSv1.2_2025"
    assert [f.rule for f in audit([dist], min_policy="TLSv1.3_2025")] == ["BELOW_POLICY_FLOOR"]


def test_weak_protocol_is_not_reported_twice(messy):
    grouped = by_rule(audit(messy, min_policy="TLSv1.2_2021"))
    assert "BELOW_POLICY_FLOOR" not in grouped
    assert len(grouped["WEAK_MIN_PROTOCOL"]) == 2


def test_unknown_policy_value_is_not_judged(hardened):
    dist = hardened[0]
    dist["ViewerCertificate"]["MinimumProtocolVersion"] = "TLSv1.3_2030"
    assert audit([dist], min_policy="TLSv1.3_2025") == []


def test_below_policy_floor_can_be_ignored(hardened):
    findings = audit(hardened, ignore=["BELOW_POLICY_FLOOR"], min_policy="TLSv1.3_2025")
    assert findings == []


def test_unknown_min_policy_is_rejected(hardened):
    with pytest.raises(ValueError):
        audit(hardened, min_policy="TLSv9")


def test_security_policy_order_matches_botocore_enum():
    import botocore.session

    model = botocore.session.get_session().get_service_model("cloudfront")
    enum = model.shape_for("MinimumProtocolVersion").enum
    assert sorted(SECURITY_POLICY_ORDER) == sorted(enum)
