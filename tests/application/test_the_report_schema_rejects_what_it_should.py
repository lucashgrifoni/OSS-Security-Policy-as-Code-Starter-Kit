"""The report schema must be asked to say no, not only to say yes.

Every existing test that touches `reports/2.0` feeds it a document that should validate.
Both functions in `test_report_schema.py` are named `..._validates_against_schema`, and the
second one is about an invalid *workflow* whose report is still a valid document. No test in
the repository mentions `ValidationError`, and the eight files that load the schema all load
it to prove conformance.

The consequence is not hypothetical. Delete a name from `required`, widen the `state` enum,
loosen a type, and the whole suite stays green: nothing in it would notice the schema had
been weakened. A schema nobody has watched reject anything is a shape, not a gate.

Every case here is derived from the schema itself rather than listed, so a field added to
`required` later is covered the day it is added, and a field removed from `required` stops
being asserted on the same day. That is the property a hand-written list of mutations cannot
have.

This does not address the forged-report problem, and should not be read as doing so. A
report with nine verdicts flipped from FAIL to PASS is schema-valid, because the schema
describes the shape and not the truth. Catching that needs a digest over the results, which
is a separate mechanism.
"""

from __future__ import annotations

import json
from copy import deepcopy
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from tests.conftest import EXAMPLE_HARDENED, ROOT

from oss_policy_kit.application.engine import evaluate_repository
from oss_policy_kit.application.loader import bundled_kit_root, load_catalog, load_profile_by_id
from oss_policy_kit.application.reporting import report_to_dict

_SCHEMA_PATH = ROOT / "src" / "oss_policy_kit" / "data" / "schema" / "reports" / "2.0.json"
_SCHEMA: dict[str, Any] = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))

_TOP_REQUIRED: list[str] = list(_SCHEMA.get("required") or [])
_CONTROL_SCHEMA: dict[str, Any] = _SCHEMA["properties"]["controls"]["items"]
_CONTROL_REQUIRED: list[str] = list(_CONTROL_SCHEMA.get("required") or [])
_STATES: list[str] = list(_CONTROL_SCHEMA["properties"]["state"]["enum"])


@pytest.fixture(scope="module")
def valid_report() -> dict[str, Any]:
    """A real report, produced the way the kit produces one.

    Hand-writing a document here would test the schema against my idea of the wire format.
    This one comes out of `report_to_dict`, so a mutation below removes something the kit
    actually emits.
    """

    root = bundled_kit_root()
    payload = report_to_dict(
        evaluate_repository(
            repo_root=EXAMPLE_HARDENED,
            profile=load_profile_by_id(root, "github-level-1"),
            catalog=load_catalog(root / "controls" / "catalog.yaml"),
            waiver_outcome=None,
            scorecard=None,
        )
    )
    assert payload.get("controls"), "the fixture report has no controls, so nothing below is exercised"
    return payload


def test_the_unmutated_report_validates() -> None:
    """The control leg. Without it, every rejection below could be the fixture being broken."""

    root = bundled_kit_root()
    payload = report_to_dict(
        evaluate_repository(
            repo_root=EXAMPLE_HARDENED,
            profile=load_profile_by_id(root, "github-level-1"),
            catalog=load_catalog(root / "controls" / "catalog.yaml"),
            waiver_outcome=None,
            scorecard=None,
        )
    )

    assert Draft202012Validator(_SCHEMA).is_valid(payload)


def test_the_schema_declares_something_to_require() -> None:
    """Anti-vacuum: an empty `required` would make every deletion case pass trivially."""

    assert len(_TOP_REQUIRED) >= 10, f"the schema declares {len(_TOP_REQUIRED)} required top-level fields"
    assert len(_CONTROL_REQUIRED) >= 7, f"a control declares {len(_CONTROL_REQUIRED)} required fields"
    assert len(_STATES) == 6, f"the state enum has {len(_STATES)} values; it had six when this was written"


@pytest.mark.parametrize("field", _TOP_REQUIRED)
def test_a_report_missing_a_required_field_is_rejected(field: str, valid_report: dict[str, Any]) -> None:
    document = deepcopy(valid_report)
    del document[field]

    assert not Draft202012Validator(_SCHEMA).is_valid(document), (
        f"the schema accepts a report with no `{field}`, although it lists it under `required`. "
        "Either the constraint is not doing what it says or the document is validated against "
        "something looser than this file."
    )


@pytest.mark.parametrize("field", _CONTROL_REQUIRED)
def test_a_control_missing_a_required_field_is_rejected(field: str, valid_report: dict[str, Any]) -> None:
    document = deepcopy(valid_report)
    del document["controls"][0][field]

    assert not Draft202012Validator(_SCHEMA).is_valid(document), (
        f"the schema accepts a control with no `{field}`, although it lists it under `required`"
    )


def test_a_state_outside_the_enum_is_rejected(valid_report: dict[str, Any]) -> None:
    """The one that matters most: a state nobody defined must not reach a consumer as valid."""

    document = deepcopy(valid_report)
    document["controls"][0]["state"] = "MOSTLY_PASS"

    assert not Draft202012Validator(_SCHEMA).is_valid(document), (
        f"the schema accepts `state: 'MOSTLY_PASS'`, which is outside the declared enum {_STATES}. "
        "A consumer branching on the six states would fall through every branch."
    )


def test_the_lowercase_spelling_of_a_state_is_rejected(valid_report: dict[str, Any]) -> None:
    """`pass` was the pre-2.0 spelling, so this is the mistake a stale consumer actually makes."""

    document = deepcopy(valid_report)
    document["controls"][0]["state"] = _STATES[0].lower()

    assert not Draft202012Validator(_SCHEMA).is_valid(document)


def test_a_field_of_the_wrong_type_is_rejected(valid_report: dict[str, Any]) -> None:
    document = deepcopy(valid_report)
    document["controls_total"] = str(document["controls_total"])

    assert not Draft202012Validator(_SCHEMA).is_valid(document), (
        "the schema accepts `controls_total` as a string, so a consumer doing arithmetic on it "
        "gets a TypeError from a document the kit called valid"
    )
