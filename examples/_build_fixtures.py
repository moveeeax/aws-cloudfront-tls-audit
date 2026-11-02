#!/usr/bin/env python3
"""Regenerate the recorded ListDistributions fixtures in this directory.

The fixtures are shaped exactly like a real ``ListDistributions`` response so
the same files feed both ``--from-file`` and the botocore ``Stubber`` in
``tests/``. Run: ``python3 examples/_build_fixtures.py``.
"""

from __future__ import annotations

import json
import pathlib

HERE = pathlib.Path(__file__).parent


def custom_origin(origin_id, domain, policy, ssl_protocols=("TLSv1.2",)):
    return {
        "Id": origin_id,
        "DomainName": domain,
        "OriginPath": "",
        "CustomHeaders": {"Quantity": 0},
        "CustomOriginConfig": {
            "HTTPPort": 80,
            "HTTPSPort": 443,
            "OriginProtocolPolicy": policy,
            "OriginSslProtocols": {
                "Quantity": len(ssl_protocols),
                "Items": list(ssl_protocols),
            },
            "OriginReadTimeout": 30,
            "OriginKeepaliveTimeout": 5,
        },
    }


def s3_origin(origin_id, domain):
    return {
        "Id": origin_id,
        "DomainName": domain,
        "OriginPath": "",
        "CustomHeaders": {"Quantity": 0},
        "S3OriginConfig": {"OriginAccessIdentity": ""},
    }


def behavior(target, policy, path_pattern=None):
    out = {
        "TargetOriginId": target,
        "ViewerProtocolPolicy": policy,
        "TrustedSigners": {"Enabled": False, "Quantity": 0},
        "ForwardedValues": {
            "QueryString": False,
            "Cookies": {"Forward": "none"},
            "Headers": {"Quantity": 0},
            "QueryStringCacheKeys": {"Quantity": 0},
        },
        "MinTTL": 0,
        "Compress": True,
    }
    if path_pattern is not None:
        out["PathPattern"] = path_pattern
    return out


def distribution(
    dist_id,
    comment,
    aliases,
    origins,
    default_behavior,
    ordered_behaviors,
    viewer_certificate,
):
    return {
        "Id": dist_id,
        "ARN": f"arn:aws:cloudfront::123456789012:distribution/{dist_id}",
        "Status": "Deployed",
        "LastModifiedTime": "2026-10-28T09:14:02+00:00",
        "DomainName": f"{dist_id.lower()}.cloudfront.net",
        "Aliases": {"Quantity": len(aliases), "Items": list(aliases)},
        "Origins": {"Quantity": len(origins), "Items": list(origins)},
        "DefaultCacheBehavior": default_behavior,
        "CacheBehaviors": {
            "Quantity": len(ordered_behaviors),
            "Items": list(ordered_behaviors),
        },
        "CustomErrorResponses": {"Quantity": 0},
        "Comment": comment,
        "PriceClass": "PriceClass_All",
        "Enabled": True,
        "ViewerCertificate": viewer_certificate,
        "Restrictions": {"GeoRestriction": {"RestrictionType": "none", "Quantity": 0}},
        "WebACLId": "",
        "HttpVersion": "http2",
        "IsIPV6Enabled": True,
        "Staging": False,
    }


ACM_ARN = "arn:aws:acm:us-east-1:123456789012:certificate/9f1c0e2a-7b44-4d19-93a1-2f0c9e8a1b33"


def acm_cert(min_protocol="TLSv1.2_2021"):
    return {
        "ACMCertificateArn": ACM_ARN,
        "SSLSupportMethod": "sni-only",
        "MinimumProtocolVersion": min_protocol,
        "Certificate": ACM_ARN,
        "CertificateSource": "acm",
    }


DEFAULT_CERT = {
    "CloudFrontDefaultCertificate": True,
    "MinimumProtocolVersion": "TLSv1",
    "CertificateSource": "cloudfront",
}


def response(items):
    return {
        "DistributionList": {
            "Marker": "",
            "MaxItems": 100,
            "IsTruncated": False,
            "Quantity": len(items),
            "Items": items,
        }
    }


MESSY = response(
    [
        distribution(
            "E1DEFAULTCERTAAA",
            "marketing site, migrated from the wizard in 2017",
            ["cdn.example.com", "www.example.com"],
            [custom_origin("origin-www", "www-alb.example.com", "https-only")],
            behavior("origin-www", "redirect-to-https"),
            [],
            DEFAULT_CERT,
        ),
        distribution(
            "E2WEAKTLSBBBBBB",
            "legacy api edge",
            ["api.example.com"],
            [custom_origin("origin-api", "api-alb.example.com", "match-viewer")],
            behavior("origin-api", "allow-all"),
            [
                behavior("origin-api", "allow-all", "/api/*"),
                behavior("origin-api", "redirect-to-https", "/api/v2/*"),
                behavior("origin-api", "allow-all", "/static/*"),
            ],
            acm_cert("TLSv1.1_2016"),
        ),
        distribution(
            "E3ORIGINCCCCCCC",
            "docs edge, origin is an old nginx box",
            ["docs.example.com"],
            [
                custom_origin(
                    "origin-docs",
                    "docs-legacy.internal.example.com",
                    "http-only",
                    ("SSLv3", "TLSv1", "TLSv1.2"),
                )
            ],
            behavior("origin-docs", "redirect-to-https"),
            [],
            acm_cert(),
        ),
        distribution(
            "E4HARDENEDDDDDD",
            "static assets, built this year",
            ["assets.example.com"],
            [s3_origin("origin-assets", "assets-bucket.s3.us-east-1.amazonaws.com")],
            behavior("origin-assets", "https-only"),
            [behavior("origin-assets", "https-only", "/img/*")],
            acm_cert(),
        ),
    ]
)

HARDENED = response(
    [
        distribution(
            "E5CLEANEEEEEEEE",
            "api edge",
            ["api.example.com"],
            [custom_origin("origin-api", "api-alb.example.com", "https-only")],
            behavior("origin-api", "https-only"),
            [],
            acm_cert(),
        ),
        distribution(
            "E6CLEANFFFFFFFF",
            "web edge",
            ["www.example.com"],
            [s3_origin("origin-web", "web-bucket.s3.us-east-1.amazonaws.com")],
            behavior("origin-web", "redirect-to-https"),
            [],
            acm_cert("TLSv1.2_2019"),
        ),
    ]
)

VIEWER_HTTP_ONLY = response(
    [
        distribution(
            "E7HTTPGGGGGGGGG",
            "redirect shim nobody tightened",
            ["go.example.com"],
            [custom_origin("origin-shim", "shim-alb.example.com", "https-only")],
            behavior("origin-shim", "allow-all"),
            [],
            acm_cert(),
        )
    ]
)

EMPTY_ACCOUNT = {
    "DistributionList": {"Marker": "", "MaxItems": 100, "IsTruncated": False, "Quantity": 0}
}


FIXTURES = {
    "messy-account.json": MESSY,
    "hardened-account.json": HARDENED,
    "viewer-http-only.json": VIEWER_HTTP_ONLY,
    "empty-account.json": EMPTY_ACCOUNT,
}


def main() -> None:
    for name, payload in FIXTURES.items():
        path = HERE / name
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {path}")


if __name__ == "__main__":
    main()
