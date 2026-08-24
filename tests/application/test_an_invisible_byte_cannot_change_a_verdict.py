"""A byte-order mark must not change what the kit concludes about a repository.

A BOM is invisible in every editor, is emitted by default by several Windows tools, and carries
no meaning: `utf-8-sig` strips it on decode and is identical to `utf-8` when it is absent. The
kit already settled on `utf-8-sig` as the reading encoding for user-controlled documents -- this
file pins the two readers that were still on plain `utf-8` while feeding a parser that rejects
the mark.

The dependency-update case is the one that matters, and it is worth being precise about why,
because the mechanism runs through a piece of code that is *right*:

  `_update_config_names` answers `None` for a config it cannot read, and its caller then falls
  back to a raw-text scan, with the reason written beside it -- "a config the parser cannot read
  keeps the old text read, so the parser cannot become a way to lose the entry". That is correct
  when the file genuinely cannot be read. It is not correct when the file is perfectly readable
  and the kit reached for the wrong encoding, because the fallback then reinstates exactly the
  behaviour a fix removed on purpose: prose deciding the verdict.

Measured before this test existed, on a `renovate.json` naming `openai` only in a `description`:

    without BOM  ->  manual-review-required   (correct: no selector names an LLM SDK)
    with BOM     ->  pass                     (the description was read as a reference)

So an invisible byte turned a withheld verdict into a claim about the repository. YAML is not
affected -- PyYAML tolerates a leading U+FEFF, verified below so a future encoding change cannot
quietly break the half that works today.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from oss_policy_kit.application.drift import REPORT_CONTRACT, load_report_json
from oss_policy_kit.application.evaluators import _shared as s
from oss_policy_kit.application.evaluators._shared import _update_config_names
from oss_policy_kit.application.evaluators.ai import eval_llm_218a_rv_001
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis

BOM = "﻿"

#: Names an LLM SDK in prose only. Parsed, no selector mentions it; read as raw text, it is there.
_RENOVATE_PROSE_ONLY = json.dumps(
    {
        "description": "we deliberately do not depend on openai here",
        "packageRules": [{"matchPackageNames": ["requests"]}],
    }
)

_DEPENDABOT = "version: 2\nupdates:\n  - package-ecosystem: pip\n    allow:\n      - dependency-name: requests\n"


def _ctx(repo_root: Path) -> s.EvalContext:
    """A real `EvalContext`; this control reads only `repo_root` off it."""

    return s.EvalContext(
        repo_root=repo_root,
        profile_id="ai-agent-level-2",
        workflows=WorkflowAnalysis(),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
    )


def _repo(tmp_path: Path, name: str, body: str, *, bom: bool) -> Path:
    root = tmp_path / ("with-bom" if bom else "without-bom")
    (root / ".github").mkdir(parents=True, exist_ok=True)
    (root / name).write_text((BOM if bom else "") + body, encoding="utf-8")
    return root


def test_a_byte_order_mark_does_not_turn_prose_into_a_reference(tmp_path: Path) -> None:
    """The invariant: the same document decorated with a BOM yields the same verdict."""

    without = eval_llm_218a_rv_001(_ctx(_repo(tmp_path, "renovate.json", _RENOVATE_PROSE_ONLY, bom=False)))
    with_bom = eval_llm_218a_rv_001(_ctx(_repo(tmp_path, "renovate.json", _RENOVATE_PROSE_ONLY, bom=True)))

    assert with_bom.status == without.status, (
        f"a BOM changed the verdict from {without.status.value} to {with_bom.status.value}"
    )


def test_a_byte_order_mark_does_not_hide_a_real_selector(tmp_path: Path) -> None:
    """And the mirror case: a config that really does name an SDK must still be read as one.

    Without this, reading the BOM'd file as unparseable could be "fixed" by making the reader
    refuse more, which would trade a false pass for a false miss.
    """

    naming_openai = json.dumps({"packageRules": [{"matchPackageNames": ["openai", "requests"]}]})
    root = _repo(tmp_path, "renovate.json", naming_openai, bom=True)

    assert eval_llm_218a_rv_001(_ctx(root)).status.value == "pass"


@pytest.mark.parametrize("bom", [False, True])
def test_the_update_config_reader_sees_the_same_selectors_either_way(tmp_path: Path, bom: bool) -> None:
    """`None` is this reader's word for "could not read" and must be reserved for that."""

    config = tmp_path / f"renovate-{int(bom)}.json"
    config.write_text((BOM if bom else "") + _RENOVATE_PROSE_ONLY, encoding="utf-8")

    assert _update_config_names(config) == {"requests"}


@pytest.mark.parametrize("bom", [False, True])
def test_a_yaml_update_config_was_never_affected_and_stays_that_way(tmp_path: Path, bom: bool) -> None:
    """PyYAML tolerates a leading U+FEFF, so the YAML half worked before this fix and still does."""

    config = tmp_path / f"dependabot-{int(bom)}.yml"
    config.write_text((BOM if bom else "") + _DEPENDABOT, encoding="utf-8")

    assert _update_config_names(config) == {"requests"}


def _report() -> dict[str, Any]:
    return {
        "contract_version": REPORT_CONTRACT,
        "generated_at": "2026-06-15T12:00:00Z",
        "profile": {"id": "github-level-1"},
        "results": [],
    }


@pytest.mark.parametrize("bom", [False, True])
def test_a_report_is_not_rejected_for_a_byte_order_mark(tmp_path: Path, bom: bool) -> None:
    """`diff-reports` reads a report the operator hands it; a BOM is not a malformed report.

    Refusing here is a milder failure than the verdict flip above -- it says "I cannot read this"
    about a file it can read -- but it is the same defect, and an adopter whose editor writes a
    BOM cannot tell what is wrong from the message.
    """

    path = tmp_path / f"report-{int(bom)}.json"
    path.write_text((BOM if bom else "") + json.dumps(_report()), encoding="utf-8")

    assert load_report_json(path, label="--before report")["contract_version"] == REPORT_CONTRACT
