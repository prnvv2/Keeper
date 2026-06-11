import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from keeper.core.engine import PolicyEngine
from keeper.core.pipeline import Pipeline, RequestContext


@pytest.fixture
def policy_engine():
    return PolicyEngine()


@pytest.fixture
def pipeline(policy_engine):
    return Pipeline(policy_engine)


@pytest.fixture
def ctx():
    return RequestContext(
        prompt="test prompt",
        user_id="test-user",
        session_id="test-session",
        ip="127.0.0.1",
    )


@pytest.fixture
def sample_config():
    return {
        "enabled": True,
        "rate_limit": "100/min",
        "block_ips": [],
        "max_prompt_length": 4096,
        "block_escape_seq": True,
        "threshold": 0.75,
        "model": "llama3.2",
        "max_history": 20,
        "drift_threshold": 0.6,
    }
