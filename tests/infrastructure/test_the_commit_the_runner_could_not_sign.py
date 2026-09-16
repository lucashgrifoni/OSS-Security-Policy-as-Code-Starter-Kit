"""The commit that replaces `git commit` on the runner, and the two ways it could lose a file.

A runner has no signing key, so the sample-reports job pushed an unsigned commit and the
`required_signatures` rule blocked every release pull request behind it. The fix routes the
write through the GitHub API, which signs it. What these tests hold is the part that is not
about signatures at all: the set of paths that reaches the commit.

Two failure modes matter and neither raises on its own. A DELETED file dropped from the tree
leaves a stale sample report in the repository forever, looking regenerated. A file outside the
prefix silently entering the tree would widen a blast radius the `git add <prefix>` it replaces
kept narrow.

The network is not touched: `tree_entries` takes its blob-maker as an argument precisely so the
shape of the payload can be asserted without it.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from scripts.push_signed_commit import changed_paths, tree_entries


def _repo(tmp_path: Path) -> Path:
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.email", "t@t.test"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "commit.gpgsign", "false"], cwd=tmp_path, check=True)
    reports = tmp_path / "docs" / "sample-reports"
    reports.mkdir(parents=True)
    (reports / "kept.json").write_text("{}\n", encoding="utf-8")
    (reports / "removed.json").write_text("{}\n", encoding="utf-8")
    (tmp_path / "unrelated.txt").write_text("nao mexer\n", encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-qm", "base"], cwd=tmp_path, check=True)
    return tmp_path


def test_a_modified_file_is_collected(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    (repo / "docs" / "sample-reports" / "kept.json").write_text('{"v": 2}\n', encoding="utf-8")

    assert changed_paths(repo, "docs/sample-reports/") == [("M", "docs/sample-reports/kept.json")]


def test_a_deleted_file_is_collected_as_a_deletion(tmp_path: Path) -> None:
    """The quiet one: a dropped deletion leaves a stale report that looks regenerated."""

    repo = _repo(tmp_path)
    (repo / "docs" / "sample-reports" / "removed.json").unlink()

    assert changed_paths(repo, "docs/sample-reports/") == [("D", "docs/sample-reports/removed.json")]


def test_a_brand_new_report_is_collected(tmp_path: Path) -> None:
    """The third way a file goes missing, and the one my own first draft had.

    The code this replaced ran `git add <prefix>`, which stages a path git has never seen.
    Reading `git diff` instead would report no change for exactly that path, so a regeneration
    that produced a new sample report would commit every neighbour and quietly omit it.
    """

    repo = _repo(tmp_path)
    (repo / "docs" / "sample-reports" / "added.json").write_text("{}\n", encoding="utf-8")
    (repo / "docs" / "sample-reports" / "kept.json").write_text('{"v": 2}\n', encoding="utf-8")

    assert sorted(changed_paths(repo, "docs/sample-reports/")) == [
        ("M", "docs/sample-reports/added.json"),
        ("M", "docs/sample-reports/kept.json"),
    ]


def test_a_change_outside_the_prefix_is_not_collected(tmp_path: Path) -> None:
    """The blast radius the `git add <prefix>` it replaces kept narrow."""

    repo = _repo(tmp_path)
    (repo / "unrelated.txt").write_text("mexido\n", encoding="utf-8")

    assert changed_paths(repo, "docs/sample-reports/") == []


def test_nothing_changed_is_an_empty_list_not_an_error(tmp_path: Path) -> None:
    assert changed_paths(_repo(tmp_path), "docs/sample-reports/") == []


def test_a_deletion_becomes_a_null_sha(tmp_path: Path) -> None:
    """`sha: None` is how the API is told to remove a path from the base tree."""

    entries = tree_entries(tmp_path, [("D", "docs/sample-reports/gone.json")], lambda _c: "nunca")

    assert entries == [{"path": "docs/sample-reports/gone.json", "mode": "100644", "type": "blob", "sha": None}]


def test_a_modification_carries_the_blob_the_maker_returned(tmp_path: Path) -> None:
    target = tmp_path / "docs" / "sample-reports"
    target.mkdir(parents=True)
    (target / "a.json").write_bytes(b'{"x": 1}')
    seen: list[bytes] = []

    entries = tree_entries(
        tmp_path,
        [("M", "docs/sample-reports/a.json")],
        lambda content: seen.append(content) or "blob-sha",  # type: ignore[func-returns-value]
    )

    assert seen == [b'{"x": 1}'], "the file bytes were not the ones handed to the blob maker"
    assert entries[0]["sha"] == "blob-sha"


def test_a_file_with_non_utf8_bytes_still_reaches_the_tree(tmp_path: Path) -> None:
    """Read as bytes and base64-encoded, so a report is never decoded and re-encoded.

    The sample reports are JSON today. Reading them as text would make this step the one place
    in the pipeline that could corrupt a byte it did not understand.
    """

    target = tmp_path / "docs" / "sample-reports"
    target.mkdir(parents=True)
    (target / "b.json").write_bytes(b"\xff\xfe{}")
    seen: list[bytes] = []

    tree_entries(tmp_path, [("M", "docs/sample-reports/b.json")], lambda c: seen.append(c) or "s")  # type: ignore[func-returns-value]

    assert seen == [b"\xff\xfe{}"]


def test_the_script_refuses_to_run_without_a_token(monkeypatch: pytest.MonkeyPatch) -> None:
    """Without the App token the commit would be made by something that cannot sign it."""

    from scripts.push_signed_commit import main

    monkeypatch.delenv("GITHUB_TOKEN", raising=False)

    with pytest.raises(SystemExit) as caught:
        main(["--repo", "o/r", "--branch", "b", "--prefix", "p/", "--message", "m"])

    assert "GITHUB_TOKEN" in str(caught.value)
