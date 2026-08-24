"""A byte-order mark is an encoding artefact, not a defect in the document.

Windows editors write UTF-8 with a signature by default, so an adopter who edits an evidence
file in Notepad gets a leading `\\ufeff`. Every JSON read in the kit used `encoding="utf-8"`,
which decodes that BOM into the string and makes `json.loads` raise on the very first
character -- so a perfectly valid evidence file came back as one the kit could not read.

The verdict that produced is honest (`manual-review-required`, never `pass`), which is why this
is a P2 and not a P0. But it is still the kit refusing a document it can read, and telling the
adopter to regenerate a file that is already correct.

Found by the metamorphic probe in the campaign's phase-1 second clean round: the transformation
"add a UTF-8 BOM" must not change any verdict, and it changed one.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from oss_policy_kit.application.evaluators import eval_llm_218a_ps_001
from oss_policy_kit.domain.models import ControlStatus

_BOM = "﻿"

#: (label, relative path, body, the evaluator that reads it, the verdict without a BOM)
_EVIDENCE_READS: tuple[tuple[str, str, str, object, ControlStatus], ...] = (
    (
        "llm-release-integrity",
        ".oss-policy-kit/evidence/llm-release-integrity.json",
        json.dumps({"model_sha": "a" * 64, "model_version": "2.1.0"}),
        eval_llm_218a_ps_001,
        ControlStatus.PASS,
    ),
)


@pytest.mark.parametrize(
    ("label", "rel", "body", "evaluate", "expected"), _EVIDENCE_READS, ids=[c[0] for c in _EVIDENCE_READS]
)
def test_a_bom_does_not_make_valid_evidence_unreadable(
    tmp_path: Path, label: str, rel: str, body: str, evaluate: object, expected: ControlStatus
) -> None:
    target = tmp_path / rel
    target.parent.mkdir(parents=True, exist_ok=True)

    target.write_text(body, encoding="utf-8")
    without_bom = evaluate(SimpleNamespace(repo_root=tmp_path))  # type: ignore[operator]
    assert without_bom.status is expected, f"{label}: the fixture itself is wrong: {without_bom.reason}"

    target.write_text(_BOM + body, encoding="utf-8")
    with_bom = evaluate(SimpleNamespace(repo_root=tmp_path))  # type: ignore[operator]

    assert with_bom.status is without_bom.status, (
        f"{label}: adding a byte-order mark changed the verdict "
        f"({without_bom.status.value} -> {with_bom.status.value}). A BOM is how Windows editors "
        f"save UTF-8; the document is unchanged: {with_bom.reason}"
    )


def test_the_capped_reader_tolerates_a_signature(tmp_path: Path) -> None:
    """The systemic half: the one defensive read every CLI loader routes through.

    `utf-8-sig` strips a leading BOM on decode and is byte-for-byte `utf-8` when there is none,
    so this is the whole fix for the class rather than a per-call-site patch. It is a *read*
    encoding only -- writing with it would emit a BOM the kit never wants to produce.
    """

    from oss_policy_kit.application.input_limits import MAX_EVIDENCE_BYTES, load_capped_document  # noqa: PLC0415

    document = tmp_path / "evidence.json"
    document.write_text(_BOM + json.dumps({"schema_version": "v1"}), encoding="utf-8")

    assert load_capped_document(document, MAX_EVIDENCE_BYTES, label="evidence", parser=json.loads) == {
        "schema_version": "v1"
    }
