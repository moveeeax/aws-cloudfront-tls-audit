"""Pull full distribution configs out of CloudFront in one paginated pass.

``ListDistributions`` already returns ``ViewerCertificate``, ``Aliases``,
``Origins``, ``DefaultCacheBehavior`` and ``CacheBehaviors`` for every
distribution, so there is no reason to call ``GetDistributionConfig`` per
distribution. CloudFront is a global service: the client is pinned to
``us-east-1`` and the CLI exposes no ``--region``.
"""

from __future__ import annotations

from typing import Iterable, Sequence

from .model import AwsError

CLOUDFRONT_REGION = "us-east-1"


def make_client(profile: str | None = None):
    """Build a CloudFront client, surfacing credential problems as AwsError."""
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError

    try:
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        return session.client("cloudfront", region_name=CLOUDFRONT_REGION)
    except (BotoCoreError, ClientError) as exc:
        raise AwsError(str(exc)) from exc


def list_distributions(client, only: Sequence[str] | None = None) -> list[dict]:
    """Return every distribution summary, optionally filtered by id.

    Pagination is driven by the service paginator so a >100 distribution
    account is handled without any manual ``Marker`` juggling.
    """
    from botocore.exceptions import BotoCoreError, ClientError

    wanted = set(only or ())
    out: list[dict] = []
    try:
        paginator = client.get_paginator("list_distributions")
        for page in paginator.paginate():
            for item in _page_items(page):
                if wanted and item.get("Id") not in wanted:
                    continue
                out.append(item)
    except (BotoCoreError, ClientError) as exc:
        raise AwsError(str(exc)) from exc
    return out


def _page_items(page: dict) -> Iterable[dict]:
    """An empty account returns a DistributionList with no Items key at all."""
    return page.get("DistributionList", {}).get("Items") or []


def distribution_name(dist: dict) -> str:
    """Prefer the first alias; fall back to the cloudfront.net domain name."""
    aliases = (dist.get("Aliases") or {}).get("Items") or []
    if aliases:
        return aliases[0]
    return dist.get("DomainName") or dist.get("Id", "<unknown>")
