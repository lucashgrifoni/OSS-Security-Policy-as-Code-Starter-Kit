"""A skip-list names directories *inside* the repository, so it belongs on the relative path.

`PATH-02` fixed this in the Terraform walker, where the consequence was severe: a repository
checked out under `build/` scanned as having no Terraform, and twelve controls asserted that
positively. These five siblings share the defect and differ in direction -- their skip-lists hold
`.git`, `.venv`, `node_modules`, `site-packages`, so an ancestor with one of those names makes the
kit *refuse to credit* work that is really there, rather than credit work that is not.

That is the safe direction, which is why this is P2 and not P1. It is still wrong: this project's
own guard tests repeat that removing a false positive must not remove a true finding, and here a
true PASS disappears because of where the adopter cloned.

Reachable without an attacker: a repo cloned into a virtualenv tree, a tool vendored under
`node_modules/`, or CI that checks out beneath a cache directory with one of these names.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from oss_policy_kit.application.evaluators import (
    eval_llm_218a_pw_002,
    eval_llm_ai_act_002,
)
from oss_policy_kit.domain.models import ControlStatus

#: Ancestor names drawn from the skip-lists these controls consult.
_COLLIDING_ANCESTORS = [".venv", "node_modules", "__pycache__", ".tox"]


def _repo(root: Path) -> SimpleNamespace:
    (root / "src").mkdir(parents=True, exist_ok=True)
    (root / "tests").mkdir(parents=True, exist_ok=True)
    (root / "LICENSE").write_text("MIT\n", encoding="utf-8")
    (root / "src" / "app.py").write_text("def f(t):\n    return content_moderation(t)\n", encoding="utf-8")
    (root / "tests" / "test_prompt_injection.py").write_text("def test_x():\n    assert True\n", encoding="utf-8")
    return SimpleNamespace(repo_root=root)


_CONTROLS = [
    ("LLM-AI-ACT-002", eval_llm_ai_act_002),
    ("LLM-218A-PW-002", eval_llm_218a_pw_002),
]


@pytest.mark.parametrize(("control_id", "evaluate"), _CONTROLS, ids=[c[0] for c in _CONTROLS])
@pytest.mark.parametrize("ancestor", _COLLIDING_ANCESTORS)
def test_an_ancestor_directory_name_does_not_hide_the_repository_own_files(
    tmp_path: Path, control_id: str, evaluate: object, ancestor: str
) -> None:
    plain = evaluate(_repo(tmp_path / "plain" / "repo"))  # type: ignore[operator]
    nested = evaluate(_repo(tmp_path / ancestor / "repo"))  # type: ignore[operator]

    assert plain.status is ControlStatus.PASS, f"{control_id}: the control case is wrong: {plain.reason}"
    assert nested.status is plain.status, (
        f"{control_id}: the identical repository, cloned under '{ancestor}/', answered "
        f"{nested.status.value} instead of {plain.status.value}. The checkout location is not "
        f"repository content: {nested.reason}"
    )


def test_the_skip_list_still_skips_those_directories_inside_the_repository(tmp_path: Path) -> None:
    """The counterpart: vendored code inside the repository must stay excluded.

    Without this, the fix above could be 'stop skipping anything', which would credit somebody
    else's test as the adopter's own -- the defect FIX-5 was written to remove.
    """

    root = tmp_path / "repo"
    _repo(root)
    vendored = root / ".venv" / "Lib" / "site-packages" / "pkg"
    vendored.mkdir(parents=True)
    (vendored / "test_prompt_injection.py").write_text("def test_y():\n    assert True\n", encoding="utf-8")

    bare = tmp_path / "bare"
    (bare / ".venv" / "Lib" / "site-packages" / "pkg").mkdir(parents=True)
    (bare / ".venv" / "Lib" / "site-packages" / "pkg" / "test_prompt_injection.py").write_text(
        "def test_y():\n    assert True\n", encoding="utf-8"
    )
    (bare / "LICENSE").write_text("MIT\n", encoding="utf-8")

    only_vendored = eval_llm_218a_pw_002(SimpleNamespace(repo_root=bare))

    assert only_vendored.status is not ControlStatus.PASS, (
        "a test that exists only inside the repository's own vendored tree was credited as the "
        f"adopter's adversarial test: {only_vendored.reason}"
    )


def test_a_path_outside_the_repository_keeps_its_absolute_parts(tmp_path: Path) -> None:
    """The deliberate fallback, and the reason real vendoring is still refused.

    `relative_to` raises for a path that is not under the repository, and the helper answers with
    the path's own parts rather than pretending it is repo-relative. That is what keeps a file
    under somebody else's `site-packages` classified as vendored: it is not the adopter's work no
    matter where their repository happens to sit.

    Without this branch the helper would return an empty tuple for such a path, and every
    skip-list check on it would silently pass.
    """

    from oss_policy_kit.application.evaluators._shared import _is_vendored, _parts_within_repo  # noqa: PLC0415

    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "elsewhere" / ".venv" / "Lib" / "site-packages" / "pkg" / "mod.py"
    outside.parent.mkdir(parents=True)
    outside.write_text("x\n", encoding="utf-8")

    parts = _parts_within_repo(outside, repo)

    assert "site-packages" in parts, "the outside path lost the parts that identify it as vendored"
    assert parts == outside.parts
    assert _is_vendored(outside, repo), "a file in another tree's site-packages was treated as the adopter's own"
