"""`CONT-SIGN-001` reads `.gitlab-ci.yml`, which is a file where its siblings are directories.

The control walks three workflow locations: `.github/workflows/` and `.azure-pipelines/` are
directories it globs, and `.gitlab-ci.yml` is a single file it appends directly. That last branch
had no test of its own -- it was covered incidentally, by whichever other test happened to leave a
`.gitlab-ci.yml` behind, which is why it appeared as an uncovered line in one run of the suite and
not in the next.

Incidental coverage is not a defect in the product, but it is a guard nobody owns: the branch can
stop being exercised because an unrelated test changed its fixture. These two cases own it.

A GitLab-only repository is a real shape -- no `.github/` at all -- so the branch is the whole
answer for those adopters, not an edge case.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from oss_policy_kit.application.evaluators_containers import eval_cont_sign_001
from oss_policy_kit.domain.models import ControlStatus

_DOCKERFILE = "FROM python:3.12-slim\nRUN echo hi\n"


def _gitlab_repo(root: Path, pipeline: str) -> SimpleNamespace:
    (root / "Dockerfile").write_text(_DOCKERFILE, encoding="utf-8")
    (root / ".gitlab-ci.yml").write_text(pipeline, encoding="utf-8")
    return SimpleNamespace(repo_root=root)


def test_a_gitlab_pipeline_that_signs_is_credited(tmp_path: Path) -> None:
    """`.gitlab-ci.yml` is a file, and the control has to read it as one."""

    ctx = _gitlab_repo(
        tmp_path,
        "release:\n  script:\n    - cosign sign --yes $IMAGE@$DIGEST\n",
    )

    outcome = eval_cont_sign_001(ctx)

    assert outcome.status is ControlStatus.PASS
    assert ".gitlab-ci.yml" in outcome.reason


def test_a_gitlab_pipeline_that_does_not_sign_is_not_credited(tmp_path: Path) -> None:
    """The counterpart, without which the test above would pass on a control that credits anything."""

    ctx = _gitlab_repo(tmp_path, "release:\n  script:\n    - docker push $IMAGE\n")

    outcome = eval_cont_sign_001(ctx)

    assert outcome.status is ControlStatus.MANUAL_REVIEW_REQUIRED
    assert "cosign" in outcome.reason.lower()
