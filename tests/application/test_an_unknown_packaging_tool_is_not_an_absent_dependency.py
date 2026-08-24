"""`recognised` has to be per TABLE, not per file, and an unknown table is not prose to grep.

`_llm_sdk_scan` may only answer `not-applicable` -- "LLM controls do not apply to this
repository" -- when it actually read where the repository declares its dependencies. The previous
round made that a per-FILE flag, and an adversarial review found both halves of the mistake:

* `[project]` with an empty `dependencies` list sets the flag, so a `pyproject.toml` that also
  carries `[tool.uv].dev-dependencies = ["openai"]` was called conclusive and the SDK vanished.
  The escape hatch was dead in exactly the case it was built for.
* A `pyproject.toml` carrying only `[build-system]` recognised nothing, fell back to the raw-text
  read, and `# we evaluated openai and rejected it` became a PASS -- reopening the
  comment-decides-the-verdict class this campaign had already closed.

So: read the tools that exist (uv, rye and pixi join poetry, pdm and hatch), and when a
`[tool.*]` table declares dependencies in a shape this reader does not know, say so instead of
guessing. Unknown becomes `manual-review-required`, never `not-applicable` and never a text
search. That trade is deliberate and recorded: where HEAD answered PASS by grepping, an unknown
future tool now answers "I could not tell" -- and HEAD's PASS came from the same read that
credited comments, so it is not a finding worth preserving.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from oss_policy_kit.application.evaluators import eval_llm_218a_pw_001
from oss_policy_kit.domain.models import ControlStatus

_PROJECT = '[project]\nname = "a"\nversion = "1"\ndependencies = []\n\n'

#: (label, pyproject body, expected status)
_CASES: tuple[tuple[str, str, ControlStatus], ...] = (
    ("uv-dev-dependencies", _PROJECT + '[tool.uv]\ndev-dependencies = ["openai"]\n', ControlStatus.PASS),
    ("rye-dev-dependencies", _PROJECT + '[tool.rye]\ndev-dependencies = ["openai>=1.2"]\n', ControlStatus.PASS),
    ("pixi-dependencies", _PROJECT + '[tool.pixi.dependencies]\nopenai = "*"\n', ControlStatus.PASS),
    (
        "pixi-pypi-dependencies",
        _PROJECT + '[tool.pixi.pypi-dependencies]\nanthropic = "*"\n',
        ControlStatus.PASS,
    ),
    # The class this must not reopen: a comment is the strongest statement that something is NOT
    # used, and it may never become proof that it is -- not even where the reader is lost.
    (
        "comment-in-an-unreadable-surface",
        '[build-system]\nrequires = ["setuptools"]\n# we evaluated openai and rejected it\n',
        ControlStatus.MANUAL_REVIEW_REQUIRED,
    ),
    # A tool nobody has written yet, declaring dependencies in a shape with a recognisable name.
    # Not knowing where an SDK would be declared is not the same as knowing there is none.
    (
        "unknown-tool-with-a-dependency-table",
        _PROJECT + '[tool.futurepm]\ndependencies = ["httpx"]\n',
        ControlStatus.MANUAL_REVIEW_REQUIRED,
    ),
    # And the answer `not-applicable` still has to be available, or the rule above would make the
    # kit permanently unsure about every Python project.
    (
        "pep621-complete-and-empty",
        '[project]\nname = "a"\nversion = "1"\ndependencies = ["httpx"]\n',
        ControlStatus.NOT_APPLICABLE,
    ),
    (
        "pep621-plus-known-tool",
        _PROJECT + '[tool.poetry.dependencies]\nhttpx = "^0.27"\n',
        ControlStatus.NOT_APPLICABLE,
    ),
    # A `[tool.*]` table that is configuration rather than dependencies leaves the answer intact.
    ("tool-table-without-dependencies", _PROJECT + "[tool.ruff]\nline-length = 120\n", ControlStatus.NOT_APPLICABLE),
)


@pytest.mark.parametrize(("label", "body", "expected"), _CASES, ids=[c[0] for c in _CASES])
def test_where_a_project_declares_its_dependencies_decides_what_may_be_claimed(
    tmp_path: Path, label: str, body: str, expected: ControlStatus
) -> None:
    (tmp_path / "pyproject.toml").write_text(body, encoding="utf-8")

    outcome = eval_llm_218a_pw_001(SimpleNamespace(repo_root=tmp_path))

    assert outcome.status is expected, (
        f"{label}: expected {expected.value} and got {outcome.status.value}. `not-applicable` is a "
        f"claim about the repository and needs the reader to have found where it declares "
        f"anything; a comment is never that place: {outcome.reason}"
    )
