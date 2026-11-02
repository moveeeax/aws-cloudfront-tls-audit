from __future__ import annotations

import json
import pathlib

import pytest

EXAMPLES = pathlib.Path(__file__).resolve().parent.parent / "examples"


def load(name: str) -> dict:
    return json.loads((EXAMPLES / name).read_text(encoding="utf-8"))


def items(name: str) -> list[dict]:
    return load(name)["DistributionList"].get("Items") or []


@pytest.fixture
def examples_dir() -> pathlib.Path:
    return EXAMPLES


@pytest.fixture
def messy() -> list[dict]:
    return items("messy-account.json")


@pytest.fixture
def hardened() -> list[dict]:
    return items("hardened-account.json")


@pytest.fixture
def viewer_http_only() -> list[dict]:
    return items("viewer-http-only.json")
