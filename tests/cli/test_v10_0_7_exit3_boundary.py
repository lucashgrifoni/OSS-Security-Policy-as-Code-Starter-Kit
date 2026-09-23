"""Exit 3 must mean a defect in the kit, and nothing else.

Three releases tried to close this class by walking a list of read sites, and each one
missed a site. An AST sweep of ``src/`` explains why: **128** parses of
repository-controlled input, 76 of them inside no ``try`` at all. The most recent escape
was the evaluators' own evidence reader, which turned a 1 KB file *inside a scanned
repository* into an exit 3 — reachable by evaluating an untrusted clone.

So the guarantee moved to the boundary. Every command's last-resort handler routes
through ``exit_for_unexpected``, which asks ``is_bad_input`` whether the exception is a
statement about the input or about the kit. That holds for all 128 sites and for the
next one somebody adds without noticing.

Per-site handling still matters — it is what lets ONE unreadable file degrade ONE
control instead of ending the run — but it is no longer the thing standing between an
adopter and a crash.

The structural test at the bottom is the one that matters over time: it fails when a NEW
unwired handler appears, not when an old one regresses.
"""

from __future__ import annotations

import ast
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from oss_policy_kit.application.input_limits import MAX_JSON_DEPTH, is_bad_input

CLI_DIR = Path(__file__).resolve().parents[2] / "src" / "oss_policy_kit" / "cli"

#: The two-line shape every command used before the classifier existed.
_RAW_HANDLER = re.compile(r"Unexpected error:\[/red\]\s*\{markup_safe\(exc\)\}")


def _run(target: Path, out: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "oss_policy_kit",
            "evaluate",
            "--target",
            str(target),
            "--profile",
            "github-level-3",
            "--output-dir",
            str(out),
            "--summary-only",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env={"PATH": "", "SYSTEMROOT": "C:\\Windows", "COLUMNS": "200", "NO_COLOR": "1", "TERM": "dumb"}
        | {k: v for k, v in __import__("os").environ.items() if k in {"PATH", "SYSTEMROOT", "PYTHONPATH"}},
    )


def _repo(tmp_path: Path, evidence_body: str) -> Path:
    repo = tmp_path / "repo"
    (repo / ".oss-policy-kit" / "evidence").mkdir(parents=True)
    (repo / "README.md").write_text("# x\n", encoding="utf-8")
    (repo / ".oss-policy-kit" / "evidence" / "branch-protection.json").write_text(evidence_body, encoding="utf-8")
    return repo


@pytest.mark.parametrize(
    ("label", "body", "phrase"),
    [
        ("deep", "[" * 3000 + "1" + "]" * 3000, "nested too deeply"),
        ("bigint", '{"n": ' + "9" * 5000 + "}", "4300 digits"),
    ],
)
def test_hostile_evidence_inside_the_repo_is_exit_2(label: str, body: str, phrase: str, tmp_path: Path) -> None:
    """The file is inside the evaluated repository, not a flag the operator typed.

    That is what made this the worst defect of the cycle: cloning an untrusted repo and
    running the gate against it was a one-file denial of service.
    """

    repo = _repo(tmp_path, body)

    result = _run(repo, tmp_path / f"out-{label}")

    combined = result.stdout + result.stderr
    assert result.returncode == 2, f"exit={result.returncode}\n{combined}"
    assert phrase in combined, combined
    assert "Unexpected error" not in combined
    assert "Traceback" not in combined
    # CPython's own remediation advice is about the interpreter, not about the file.
    assert "set_int_max_str_digits" not in combined
    assert str(tmp_path) not in combined.replace("\\\\", "\\"), "the message leaked the host path"


def test_an_unreadable_ci_file_is_neither_a_defect_nor_the_end_of_the_run(tmp_path: Path) -> None:
    """A directory named like a workflow used to end the whole evaluation at exit 3.

    This asserted exit 2 until FINAL-13, and exit 2 was the defect: under github-level-3,
    CI-WFCALLSHA-055 read the directory a second time outside any guard, after the parser
    had recorded it as unread, and the bad-input handler ended the run with no report. One
    unreadable file inside a repository degrades the controls that needed it and the run
    finishes (ADR-045, and `test_one_unreadable_file_does_not_end_the_run.py`). What this
    test owns is unchanged: the answer is never exit 3 and never a traceback.
    """

    repo = tmp_path / "repo"
    (repo / ".github" / "workflows" / "adir.yml").mkdir(parents=True)
    (repo / "README.md").write_text("# x\n", encoding="utf-8")
    (repo / ".github" / "workflows" / "ci.yml").write_text("name: ci\n", encoding="utf-8")

    result = _run(repo, tmp_path / "out")

    combined = result.stdout + result.stderr
    assert result.returncode in {0, 1}, f"exit={result.returncode}\n{combined}"
    assert "Unexpected error" not in combined
    assert "Traceback" not in combined


def test_healthy_repo_is_unaffected(tmp_path: Path) -> None:
    """The classifier must not turn a working evaluation into an error."""

    repo = _repo(tmp_path, json.dumps({"schema_version": "x", "collected_at": "2026-01-01"}))

    result = _run(repo, tmp_path / "out")

    assert result.returncode in {0, 1}, f"exit={result.returncode}\n{result.stdout}{result.stderr}"


# --------------------------------------------------------------------------------------
# The classifier itself
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "exc",
    [
        OSError(13, "Permission denied"),
        FileNotFoundError(2, "No such file or directory"),
        RecursionError("maximum recursion depth exceeded"),
        UnicodeDecodeError("utf-8", b"\xff\xfe", 0, 1, "invalid start byte"),
        yaml.YAMLError("while scanning"),
        ValueError("Exceeds the limit (4300 digits) for integer string conversion: value has 5000 digits"),
    ],
)
def test_input_failures_are_classified_as_input(exc: BaseException) -> None:
    assert is_bad_input(exc)


@pytest.mark.parametrize(
    "exc",
    [
        ValueError("not enough values to unpack"),
        KeyError("controls"),
        TypeError("unsupported operand"),
        AttributeError("'NoneType' object has no attribute 'get'"),
        ZeroDivisionError("division by zero"),
    ],
)
def test_kit_defects_stay_exit_3(exc: BaseException) -> None:
    """A bare ValueError is a defect until proven otherwise.

    Widening the classifier to every ``ValueError`` would relabel a real bug as the
    adopter's bad input, which is the opposite of what exit 3 exists for.
    """

    assert not is_bad_input(exc)


def test_depth_budget_is_the_documented_one() -> None:
    assert MAX_JSON_DEPTH == 200


# --------------------------------------------------------------------------------------
# The guard that matters over time
# --------------------------------------------------------------------------------------


def test_no_command_still_raises_exit_3_directly() -> None:
    """Every last-resort handler goes through the classifier.

    A per-command test would pass on the other 22. This fails when a NEW command is added
    with the old copy-pasted two-liner, which is exactly how the surface grew to 23.
    """

    offenders = []
    for path in sorted(CLI_DIR.glob("*.py")):
        text = path.read_text(encoding="utf-8")
        # The classifier's own exit-3 branch is the one legitimate occurrence. It is
        # excluded by function span rather than by filename, so the rest of common.py
        # stays covered -- and common.py is where the largest command lives.
        exempt: set[int] = set()
        for node in ast.walk(ast.parse(text)):
            if isinstance(node, ast.FunctionDef) and node.name == "exit_for_unexpected":
                exempt = set(range(node.lineno, (node.end_lineno or node.lineno) + 1))
        for lineno, line in enumerate(text.split("\n"), 1):
            if lineno not in exempt and _RAW_HANDLER.search(line):
                offenders.append(f"{path.name}:{lineno}")

    assert not offenders, (
        "these handlers print 'Unexpected error' directly instead of calling "
        f"exit_for_unexpected(exc), so bad input reaches exit 3 there: {offenders}"
    )
