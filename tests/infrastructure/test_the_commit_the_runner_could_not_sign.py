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

import ast
import subprocess
from pathlib import Path

import pytest
from scripts.push_signed_commit import changed_paths, gh_argv, tree_entries

#: The node types `ast.get_docstring` accepts; anything else raises rather than returning None.
_DOCUMENTABLE = (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)


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

    monkeypatch.delenv("GH_TOKEN", raising=False)

    with pytest.raises(SystemExit) as caught:
        main(["--repo", "o/r", "--branch", "b", "--prefix", "p/", "--message", "m"])

    assert "GH_TOKEN" in str(caught.value)


def test_no_url_is_built_in_this_file() -> None:
    """The reason the calls go through `gh` at all.

    The first version wrote the request by hand: it joined a base URL with a path built from
    `--repo` and `--branch`, and put the token in an Authorization header. Snyk Code read that
    as an SSRF sink fed by a command-line argument, and Semgrep flagged the same construct, on a
    repository that carries no suppression of either. `gh` resolves the host and reads the token
    from the environment, so neither a URL nor a credential is assembled here.
    """

    path = Path(__file__).resolve().parents[2] / "scripts" / "push_signed_commit.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))

    imported = {
        node.module.split(".")[0] if isinstance(node, ast.ImportFrom) and node.module else alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in getattr(node, "names", [])
    }
    # Docstrings are prose about this change and say both words on purpose, so the check reads
    # the literals the code evaluates rather than the file's text.
    # clean=False: the cleaned form is dedented and would no longer equal the raw literal the
    # Constant node carries, so every indented docstring would slip back into the comparison.
    docstrings = {ast.get_docstring(n, clean=False) for n in ast.walk(tree) if isinstance(n, _DOCUMENTABLE)}
    literals = [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value not in docstrings
    ]

    assert "urllib" not in imported, f"imports: {sorted(imported)}"
    assert not [text for text in literals if "https://" in text], "this file builds a URL"
    assert not [text for text in literals if "Authorization" in text], "this file builds a credential header"


def test_the_body_goes_in_on_stdin_not_as_arguments() -> None:
    """`gh`'s field flags coerce types and split on `=`; a report's bytes get neither."""

    write = gh_argv("POST", "/repos/o/r/git/blobs", has_body=True)
    read = gh_argv("GET", "/repos/o/r/git/ref/heads/b", has_body=False)

    assert write[:5] == ["gh", "api", "--method", "POST", "/repos/o/r/git/blobs"]
    assert write[-2:] == ["--input", "-"]
    assert "--input" not in read, "a GET has no body, so nothing should be waiting on stdin"
    assert "--field" not in write and "-f" not in write
