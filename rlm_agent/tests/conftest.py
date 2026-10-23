"""Shared test fixtures and helpers."""

import json
import sys
from pathlib import Path

import pytest

# Ensure rlm_agent is importable from the project root
PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

FIXTURES_DIR = Path(__file__).parent.parent / "eval_fixtures"
GROUND_TRUTH_DIR = FIXTURES_DIR / "ground_truth"

FIXTURE_IDS = [
    "f1_minimal_twotier",
    "f2_threetier_segmented",
    "f3_privsep_service_accounts",
    "f4_patched_vs_vulnerable",
    "f5_chained_vulnerabilities",
    "f6_intent_vs_effective",
    "f7_negative_control",
]


def load_ground_truth(fixture_id: str) -> dict:
    """Load ground truth JSON for a fixture."""
    gt_file = GROUND_TRUTH_DIR / f"{fixture_id}.json"
    if not gt_file.exists():
        pytest.skip(f"No ground truth file: {gt_file}")
    return json.loads(gt_file.read_text())


@pytest.fixture(params=FIXTURE_IDS)
def fixture_id(request):
    """Parametrize over all fixture IDs."""
    return request.param


@pytest.fixture
def ground_truth(fixture_id):
    """Load ground truth for the current fixture."""
    return load_ground_truth(fixture_id)
