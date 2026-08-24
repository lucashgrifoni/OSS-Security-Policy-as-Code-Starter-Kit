"""Existing is not the same as being there, and absence is not the same as not knowing.

Four AI controls credited an artifact for existing, without opening it:

* ``mkdir prompts`` satisfied "prompt registry present";
* ``touch MODEL_CARD.md`` satisfied "model versioning artifact present";
* ``model_sha: "x"`` satisfied the one evidence-backed control in the family;
* a file merely NAMED ``test_prompt_injection.py`` satisfied "adversarial test file present" --
  and its sweep had no skip list, so one inside ``site-packages`` or a bundled example fixture
  counted as the adopter's own test.

A fifth read absence as a claim: ``LLM-218A-PW-001`` answered `not-applicable` -- "LLM controls
do not apply to this repo" -- when a word did not appear in a manifest's text. That is the state
no summary counts, so it is the quietest place for a false statement. It is now reserved for the
case where every manifest was READ and none declares an SDK; a repository with no manifest at
all is one the kit knows nothing about, and says so.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from oss_policy_kit.application.evaluators import (
    eval_ai_agent_003,
    eval_ai_agent_006,
    eval_ai_agent_008,
    eval_ai_agent_010,
    eval_llm_218a_po_002,
    eval_llm_218a_ps_001,
    eval_llm_218a_ps_002,
    eval_llm_218a_pw_001,
    eval_llm_218a_pw_002,
)
from oss_policy_kit.domain.models import ControlStatus

_INTEGRITY = ".oss-policy-kit/evidence/llm-release-integrity.json"

#: (label, evaluator, files, the artifact really carries something)
_ARTIFACTS: tuple[tuple[str, object, dict[str, str], bool], ...] = (
    ("prompts-dir-empty", eval_llm_218a_po_002, {"prompts/.keep": ""}, False),
    ("prompts-dir-whitespace", eval_llm_218a_po_002, {"prompts/system.md": "   \n\n"}, False),
    ("prompts-dir-real", eval_llm_218a_po_002, {"prompts/system.md": "You are a careful assistant.\n"}, True),
    ("model-card-empty", eval_llm_218a_ps_002, {"MODEL_CARD.md": ""}, False),
    ("model-card-whitespace", eval_llm_218a_ps_002, {"MODEL_CARD.md": "  \n"}, False),
    ("model-card-real", eval_llm_218a_ps_002, {"MODEL_CARD.md": "# Card\nVersion 2.1.0\n"}, True),
    (
        "integrity-placeholder-sha",
        eval_llm_218a_ps_001,
        {_INTEGRITY: json.dumps({"model_sha": "x", "model_version": "2.1.0"})},
        False,
    ),
    (
        "integrity-placeholder-version",
        eval_llm_218a_ps_001,
        {_INTEGRITY: json.dumps({"model_sha": "a" * 64, "model_version": "TBD"})},
        False,
    ),
    (
        "integrity-real",
        eval_llm_218a_ps_001,
        {_INTEGRITY: json.dumps({"model_sha": "a" * 64, "model_version": "2.1.0"})},
        True,
    ),
    ("adversarial-test-empty", eval_llm_218a_pw_002, {"tests/test_prompt_injection.py": ""}, False),
    (
        "adversarial-test-vendored",
        eval_llm_218a_pw_002,
        {".venv-ci/Lib/site-packages/pkg/test_adversarial.py": "def test_x():\n    assert True\n"},
        False,
    ),
    (
        "adversarial-test-real",
        eval_llm_218a_pw_002,
        {"tests/test_prompt_injection.py": "def test_x():\n    assert True\n"},
        True,
    ),
)


def _repo(tmp_path: Path, files: dict[str, str]) -> SimpleNamespace:
    for rel, body in files.items():
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")
    return SimpleNamespace(repo_root=tmp_path)


@pytest.mark.parametrize(("label", "evaluate", "files", "real"), _ARTIFACTS, ids=[a[0] for a in _ARTIFACTS])
def test_an_artifact_counts_only_when_it_carries_something(
    tmp_path: Path, label: str, evaluate: object, files: dict[str, str], real: bool
) -> None:
    outcome = evaluate(_repo(tmp_path, files))  # type: ignore[operator]

    if real:
        assert outcome.status is ControlStatus.PASS, (
            f"{label}: the artifact is really there and the control stopped crediting it "
            f"({outcome.status.value}): {outcome.reason}"
        )
    else:
        assert outcome.status is not ControlStatus.PASS, (
            f"{label}: an empty or placeholder artifact was reported as the control being satisfied: {outcome.reason}"
        )


#: (label, files, the expected status name)
_SDK_APPLICABILITY: tuple[tuple[str, dict[str, str], ControlStatus], ...] = (
    (
        "manifest-read-no-sdk",
        {"pyproject.toml": '[project]\nname = "a"\nversion = "1"\ndependencies = ["httpx"]\n'},
        ControlStatus.NOT_APPLICABLE,
    ),
    (
        "manifest-read-with-sdk",
        {"pyproject.toml": '[project]\nname = "a"\nversion = "1"\ndependencies = ["openai"]\n'},
        ControlStatus.PASS,
    ),
    ("no-manifest-at-all", {"main.go": "package main\n"}, ControlStatus.MANUAL_REVIEW_REQUIRED),
    (
        "manifest-unparseable",
        {"pyproject.toml": "[project\nbroken = \n"},
        ControlStatus.MANUAL_REVIEW_REQUIRED,
    ),
)


@pytest.mark.parametrize(("label", "files", "expected"), _SDK_APPLICABILITY, ids=[c[0] for c in _SDK_APPLICABILITY])
def test_not_applicable_needs_a_manifest_that_was_actually_read(
    tmp_path: Path, label: str, files: dict[str, str], expected: ControlStatus
) -> None:
    """ "This repository does not use an LLM" is a claim, and it needs to have been checked."""

    outcome = eval_llm_218a_pw_001(_repo(tmp_path, files))

    assert outcome.status is expected, (
        f"{label}: expected {expected.value} and got {outcome.status.value}. `not-applicable` "
        "asserts something about the repository; it is only available once every manifest has "
        f"been read: {outcome.reason}"
    )


#: A repository that DOCUMENTS agent vocabulary without being an agent -- a linter, a policy
#: pack, a training repo, or this kit itself. `AI-AGENT-003` and `AI-AGENT-008` still FAIL it
#: and `AI-AGENT-006` still passes it, because those three sweep raw text with no applicability
#: gate; see the note in the module docstring. Only `AI-AGENT-010` is fixed here, and it is
#: fixed by reading the binding rather than by an applicability gate.
_VOCABULARY_ONLY = {
    "pyproject.toml": '[project]\nname = "linter"\nversion = "1"\ndependencies = ["click"]\n',
    "rules/patterns.py": (
        "ANTIPATTERNS = (\n"
        '    "token_passthrough",\n'
        '    "use_user_credentials",\n'
        ")\n"
        "RATE_LIMIT_HINTS = (\n"
        '    "rate limit",\n'
        '    "quota",\n'
        ")\n"
        'MODEL_HINTS = ("model", "claude", "gpt-")\n'
    ),
}

#: The same vocabulary in a repository that really is an agent, with two real defects in it.
_REAL_AGENT = {
    "pyproject.toml": '[project]\nname = "agent"\nversion = "1"\ndependencies = ["langchain", "openai"]\n',
    "config.yaml": "model: gpt-4o\n",
    "auth.py": "HEADERS = {'Authorization': token_passthrough}\n",
}


def test_a_pattern_list_is_not_a_configured_model(tmp_path: Path) -> None:
    """`MODEL_HINTS = ("model", "claude", "gpt-")` declares a detector, not a model.

    A configuration binds one scalar; a detector declares a collection. That difference is
    structural, which is why reading the value side separates them without anyone having to
    enumerate which repositories are tools.
    """

    outcome = eval_ai_agent_010(_repo(tmp_path, _VOCABULARY_ONLY))

    assert outcome.status is not ControlStatus.FAIL, (
        "AI-AGENT-010 failed a repository that merely lists the aliases it detects, which is "
        f"exit 1 under `--fail-on fail`: {outcome.reason}"
    )


def test_a_real_agent_is_still_judged(tmp_path: Path) -> None:
    """The counterpart. Removing a false positive must not remove the true one beside it."""

    ctx = _repo(tmp_path, _REAL_AGENT)

    assert eval_ai_agent_008(ctx).status is ControlStatus.FAIL, "the token passthrough went unreported"
    assert eval_ai_agent_010(ctx).status is ControlStatus.FAIL, "the unpinned model went unreported"
    assert eval_ai_agent_003(ctx).status is not ControlStatus.NOT_APPLICABLE
    assert eval_ai_agent_006(ctx).status is not ControlStatus.NOT_APPLICABLE
