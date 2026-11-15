from pathlib import Path

import pytest

from redteam.cases import load_suite

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="session")
def suite():
    return load_suite(ROOT / "cases" / "core-v1.yaml")


@pytest.fixture(scope="session")
def cases(suite):
    return {c.id: c for c in suite.cases}


@pytest.fixture
def anyio_backend():
    return "asyncio"
