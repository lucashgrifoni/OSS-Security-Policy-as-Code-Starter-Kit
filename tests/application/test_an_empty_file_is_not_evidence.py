"""`touch` must not pass a control, and the sweep is derived rather than listed.

Nine controls answered PASS for a repository whose entire content was one zero-byte file,
because each tested a path for existence and never for content. Measured on the tree at
v10.0.22:

    DEP-UPDATE-001        renovate.json                   -> PASS  (assurance=deterministic)
    CRA-ART14-CSAF-001    .well-known/csaf                -> PASS
    LLM-AI-ACT-003        risk-management.md              -> PASS
    SEC-FUZZ-001          fuzz/target_fuzz.go             -> PASS
    AGENT-ASI-GOAL-001    prompts/system.md               -> PASS
    AUDIT-STREAM-060      .github/audit-log-streaming.yml -> PASS
    SLSA-SRC-005          (same)                          -> PASS
    SLSA-SRC-008          (same)                          -> PASS
    RELEASE-ARCHIVE-063   RELEASE_ARCHIVAL.md             -> PASS

The list is the symptom. The sweep below is the guard: it builds one repository holding an
empty file at every path the kit treats as a signal, runs EVERY control in the registry over
it, and fails on any PASS. A control added tomorrow that tests a tenth path for existence is
caught without anybody remembering to extend a list -- which is how the first nine survived
three rounds of review that each checked a list somebody wrote by hand.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from oss_policy_kit.application.evaluators import EVALUATOR_REGISTRY, _shared as sh
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import analyze_workflows

#: Signal paths gathered from the kit's own constants rather than retyped here, so a path added
#: to any of these tuples joins the sweep automatically.
_DERIVED_SIGNAL_PATHS: tuple[str, ...] = tuple(
    sorted(
        set(sh._AUDIT_STREAM_SIGNAL_PATHS)
        | set(sh._RELEASE_ARCHIVE_SIGNAL_PATHS)
    )
)

#: Paths the constants above do not cover, each one a control's own literal. Kept short and
#: explicit: every entry here is a place the derived collection could not reach.
_EXTRA_SIGNAL_PATHS: tuple[str, ...] = (
    ".github/dependabot.yml",
    ".github/renovate.json",
    ".well-known/csaf",
    "AGENTS.md",
    "CODEOWNERS",
    "CONTRIBUTING.md",
    "RELEASE_ARCHIVAL.md",
    "SECURITY.md",
    "SYSTEM_PROMPT.md",
    "fuzz/target_fuzz.go",
    "prompts/system.md",
    "renovate.json",
    "risk-management.md",
    "system_prompt.md",
)


@pytest.fixture(scope="module")
def hollow_repo(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A repository whose every signal path exists and holds nothing at all."""

    root = tmp_path_factory.mktemp("hollow")
    for rel in _DERIVED_SIGNAL_PATHS + _EXTRA_SIGNAL_PATHS:
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"")
    return root


def _ctx(root: Path) -> sh.EvalContext:
    return sh.EvalContext(
        repo_root=root,
        profile_id="github-level-1",
        workflows=analyze_workflows(root),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
    )


def test_the_sweep_has_something_to_sweep() -> None:
    """The anti-vacuum assertion: a guard over an empty registry passes and proves nothing."""

    assert len(EVALUATOR_REGISTRY) > 200
    assert len(_DERIVED_SIGNAL_PATHS) >= 2


def test_no_control_passes_a_repository_made_only_of_empty_files(hollow_repo: Path) -> None:
    ctx = _ctx(hollow_repo)

    passing = []
    for control_id, evaluator in sorted(EVALUATOR_REGISTRY.items()):
        outcome = evaluator(ctx)
        if outcome.status is ControlStatus.PASS:
            passing.append(f"{control_id}: {outcome.reason[:110]}")

    assert not passing, (
        "these controls answered PASS for a repository whose every file is zero bytes, so the "
        "file existing is the whole verdict:\n  " + "\n  ".join(passing)
    )


@pytest.mark.parametrize(
    ("control_id", "rel", "body"),
    [
        ("DEP-UPDATE-001", "renovate.json", '{"extends": ["config:recommended"]}'),
        ("CRA-ART14-CSAF-001", ".well-known/csaf", "advisory feed"),
        ("LLM-AI-ACT-003", "risk-management.md", "# Risk management plan"),
        ("SEC-FUZZ-001", "fuzz/target_fuzz.go", "package fuzz"),
        ("AGENT-ASI-GOAL-001", "prompts/system.md", "You are a build assistant."),
        ("AUDIT-STREAM-060", ".github/audit-log-streaming.yml", "streaming: on"),
        ("SLSA-SRC-005", ".github/audit-log-streaming.yml", "streaming: on"),
        ("SLSA-SRC-008", ".github/audit-log-streaming.yml", "streaming: on"),
        ("RELEASE-ARCHIVE-063", "RELEASE_ARCHIVAL.md", "Our release archival policy."),
    ],
)
def test_the_same_path_with_content_in_it_still_passes(
    control_id: str, rel: str, body: str, tmp_path: Path
) -> None:
    """The over-withdrawal guard: refusing `touch` must not refuse the real thing.

    Without this half, the cheapest way to make the sweep above pass is to stop any of these
    controls passing at all, which trades a false PASS for a useless control.
    """

    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")

    outcome = EVALUATOR_REGISTRY[control_id](_ctx(tmp_path))

    assert outcome.status is ControlStatus.PASS, (
        f"{control_id} no longer recognises real content at {rel}: {outcome.reason}"
    )
