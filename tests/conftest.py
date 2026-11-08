import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

ROOT = Path(__file__).resolve().parents[1]
POLICIES = ROOT / "policies"


@pytest.fixture(scope="session")
def gate():
    """The 30-day log replayed once. Tests that change state build their own gate."""
    from ztgate.app import build_gate

    return build_gate(7, POLICIES)


@pytest.fixture(scope="session")
def summary(gate):
    from ztgate import analytics

    return analytics.summary(gate)
