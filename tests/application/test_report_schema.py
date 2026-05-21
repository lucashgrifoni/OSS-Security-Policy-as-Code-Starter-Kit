"""Validate evaluation JSON against the published schema."""

from __future__ import annotations

import json

import pytest
from jsonschema import Draft202012Validator
from tests.conftest import EXAMPLE_HARDENED, INVALID_WORKFLOW_FIXTURE, ROOT

from oss_policy_kit.application.engine import evaluate_repository
from oss_policy_kit.application.loader import bundled_kit_root, load_catalog, load_profile_by_id
from oss_policy_kit.application.reporting import report_to_dict

SCHEMA_PATH = ROOT / "reports" / "schema" / "evaluation-result.schema.json"


@pytest.fixture(scope="module")
def evaluation_schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def test_evaluation_report_validates_against_schema(
    evaluation_schema: dict,
) -> None:
    root = bundled_kit_root()
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    profile = load_profile_by_id(root, "github-level-1")
    report = evaluate_repository(
        repo_root=EXAMPLE_HARDENED,
        profile=profile,
        catalog=catalog,
        waiver_outcome=None,
        scorecard=None,
    )
    payload = report_to_dict(report)
    Draft202012Validator(evaluation_schema).validate(payload)


def test_invalid_workflow_report_validates_against_schema(
    evaluation_schema: dict,
) -> None:
    root = bundled_kit_root()
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    profile = load_profile_by_id(root, "github-level-1")
    report = evaluate_repository(
        repo_root=INVALID_WORKFLOW_FIXTURE,
        profile=profile,
        catalog=catalog,
        waiver_outcome=None,
        scorecard=None,
    )
    payload = report_to_dict(report)
    Draft202012Validator(evaluation_schema).validate(payload)
    assert payload["operational_warnings"]
