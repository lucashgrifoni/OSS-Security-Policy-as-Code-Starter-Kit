"""Applicability is a positive claim, and five controls were deciding it from a lossy read.

`PUBLISH-OIDC-001/002/003`, `WORM-PUBLISH-SCOPE-001` and `SCANNER-INTEGRITY-001` all decide
whether they apply by scanning workflow text for a keyword. Each opened the file with
``read_text(encoding="utf-8", errors="replace")``, so a workflow saved as UTF-16 arrived as
mojibake, matched no keyword, and dropped out of discovery exactly as an absent one does.

Measured on the tree at v10.0.22, two repositories whose ``publish.yml`` differed only in its
encoding:

    PUBLISH-OIDC-001        FAIL -> NOT_APPLICABLE   "No publish workflow detected"
    PUBLISH-OIDC-002        FAIL -> NOT_APPLICABLE
    PUBLISH-OIDC-003        FAIL -> NOT_APPLICABLE   "No npm publish step detected"
    SCANNER-INTEGRITY-001   FAIL -> NOT_APPLICABLE   "No scanner actions referenced"
    WORM-PUBLISH-SCOPE-001  PASS -> NOT_APPLICABLE

    exit 1 -> exit 0

`--fail-on degraded` does not close this by itself and never did: it counts ``fail`` and
``manual-review-required``, and all five landed in ``not-applicable``, which it does not count.
That is why the fix has to be a withdrawal to ``manual-review-required`` rather than a note.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from oss_policy_kit.application.evaluators import EVALUATOR_REGISTRY
from oss_policy_kit.application.evaluators import _shared as sh
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import analyze_workflows

#: Every watched control has something to say about this workflow: it publishes to PyPI and to
#: npm, runs a scanner action pinned to a branch, declares no `id-token`, and scopes no branch.
PUBLISH = (
    "name: publish\n"
    "# {comment}\n"
    "on:\n"
    "  push:\n"
    "jobs:\n"
    "  release:\n"
    "    runs-on: ubuntu-latest\n"
    "    steps:\n"
    "      - uses: aquasecurity/trivy-action@master\n"
    "      - run: twine upload dist/*\n"
    "      - run: npm publish\n"
)

WIDE_COMMENT = "漢字"
NARROW_COMMENT = "publicação"

WATCHED = [
    "PUBLISH-OIDC-001",
    "PUBLISH-OIDC-002",
    "PUBLISH-OIDC-003",
    "WORM-PUBLISH-SCOPE-001",
    "SCANNER-INTEGRITY-001",
]

#: `--fail-on degraded` counts exactly these two. `not-applicable` is not among them, which is
#: the whole reason a false applicability verdict turns a red pipeline green.
COUNTED_BY_FAIL_ON_DEGRADED = {ControlStatus.FAIL, ControlStatus.MANUAL_REVIEW_REQUIRED}


def _repo(tmp_path: Path, comment: str, encoding: str) -> Path:
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "publish.yml").write_bytes(PUBLISH.format(comment=comment).encode(encoding))
    return tmp_path


def _ctx(root: Path) -> sh.EvalContext:
    return sh.EvalContext(
        repo_root=root,
        profile_id="oss-publish-readiness-1",
        workflows=analyze_workflows(root),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
    )


@pytest.mark.parametrize("control_id", WATCHED)
def test_an_unreadable_publish_workflow_never_reads_as_a_repo_that_does_not_publish(
    control_id: str, tmp_path: Path
) -> None:
    root = _repo(tmp_path, WIDE_COMMENT, "utf-16-le")

    outcome = EVALUATOR_REGISTRY[control_id](_ctx(root))

    assert outcome.status is not ControlStatus.NOT_APPLICABLE, (
        f"{control_id} declared itself not applicable over a publish workflow it never read: {outcome.reason}"
    )


def test_the_gate_the_operator_was_told_to_use_actually_closes_it(tmp_path: Path) -> None:
    """`--fail-on degraded` must see at least as much on the unreadable repo as on the readable one.

    The pre-fix numbers were 4 and 0: every control the operator relied on fell into a bucket
    that policy does not count.
    """

    readable = _ctx(_repo(tmp_path / "a", NARROW_COMMENT, "utf-8"))
    (tmp_path / "b").mkdir(parents=True, exist_ok=True)
    unreadable = _ctx(_repo(tmp_path / "b", WIDE_COMMENT, "utf-16-le"))

    def counted(ctx: sh.EvalContext) -> int:
        return sum(1 for cid in WATCHED if EVALUATOR_REGISTRY[cid](ctx).status in COUNTED_BY_FAIL_ON_DEGRADED)

    assert counted(unreadable) >= counted(readable) > 0


@pytest.mark.parametrize("control_id", WATCHED)
@pytest.mark.parametrize("encoding", ["utf-8", "utf-16"])
def test_a_publish_workflow_it_can_read_is_still_judged(control_id: str, encoding: str, tmp_path: Path) -> None:
    """The over-withdrawal guard: a readable workflow, in either encoding, is not withdrawn."""

    root = _repo(tmp_path, NARROW_COMMENT, encoding)

    outcome = EVALUATOR_REGISTRY[control_id](_ctx(root))

    assert outcome.status is not ControlStatus.NOT_APPLICABLE, (
        f"{control_id} lost sight of a readable publish workflow written {encoding}"
    )
    assert "was never read" not in outcome.reason, (
        f"{control_id} withdrew over a workflow it could read: {outcome.reason}"
    )


def test_a_repository_with_no_publish_workflow_is_still_not_applicable(tmp_path: Path) -> None:
    """The other half of the guard: a real absence must keep answering not-applicable."""

    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text("name: ci\non:\n  push:\njobs: {}\n", encoding="utf-8")

    ctx = _ctx(tmp_path)

    assert EVALUATOR_REGISTRY["PUBLISH-OIDC-001"](ctx).status is ControlStatus.NOT_APPLICABLE
    assert EVALUATOR_REGISTRY["WORM-PUBLISH-SCOPE-001"](ctx).status is ControlStatus.NOT_APPLICABLE


def test_the_withdrawal_names_the_file_and_the_fix(tmp_path: Path) -> None:
    root = _repo(tmp_path, WIDE_COMMENT, "utf-16-le")

    outcome = EVALUATOR_REGISTRY["PUBLISH-OIDC-001"](_ctx(root))

    assert outcome.status is ControlStatus.MANUAL_REVIEW_REQUIRED
    assert "publish.yml" in outcome.reason
    assert "byte-order mark" in outcome.remediation
