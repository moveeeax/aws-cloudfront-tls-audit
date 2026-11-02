"""Collector tests run entirely offline through botocore's Stubber."""

from __future__ import annotations

import boto3
import pytest
from botocore.stub import Stubber

from aws_cloudfront_tls_audit.collect import (
    CLOUDFRONT_REGION,
    distribution_name,
    list_distributions,
)
from aws_cloudfront_tls_audit.model import AwsError

from .conftest import load


@pytest.fixture
def client():
    return boto3.client(
        "cloudfront",
        region_name=CLOUDFRONT_REGION,
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )


def test_stub_accepts_the_recorded_fixtures(client):
    """Guards the fixtures against drifting from the real response shape."""
    with Stubber(client) as stub:
        stub.add_response("list_distributions", load("messy-account.json"), {})
        got = list_distributions(client)
    assert [d["Id"] for d in got] == [
        "E1DEFAULTCERTAAA",
        "E2WEAKTLSBBBBBB",
        "E3ORIGINCCCCCCC",
        "E4HARDENEDDDDDD",
    ]


def test_empty_account_returns_no_items(client):
    with Stubber(client) as stub:
        stub.add_response("list_distributions", load("empty-account.json"), {})
        assert list_distributions(client) == []


def test_pagination_walks_every_page(client):
    first = load("messy-account.json")
    first["DistributionList"]["IsTruncated"] = True
    first["DistributionList"]["NextMarker"] = "page-2"
    second = load("hardened-account.json")
    with Stubber(client) as stub:
        stub.add_response("list_distributions", first, {})
        stub.add_response("list_distributions", second, {"Marker": "page-2"})
        got = list_distributions(client)
    assert len(got) == 6
    assert got[-1]["Id"] == "E6CLEANFFFFFFFF"


def test_distribution_filter_is_applied(client):
    with Stubber(client) as stub:
        stub.add_response("list_distributions", load("messy-account.json"), {})
        got = list_distributions(client, ["E3ORIGINCCCCCCC"])
    assert [d["Id"] for d in got] == ["E3ORIGINCCCCCCC"]


def test_access_denied_becomes_aws_error(client):
    with Stubber(client) as stub:
        stub.add_client_error(
            "list_distributions",
            service_error_code="AccessDenied",
            service_message="User is not authorized to perform cloudfront:ListDistributions",
            http_status_code=403,
        )
        with pytest.raises(AwsError) as exc:
            list_distributions(client)
    assert "ListDistributions" in str(exc.value)


def test_distribution_name_falls_back_to_domain():
    assert distribution_name({"Aliases": {"Quantity": 0}, "DomainName": "d1.cloudfront.net"}) == (
        "d1.cloudfront.net"
    )
    assert distribution_name({"Id": "EONLYID"}) == "EONLYID"
