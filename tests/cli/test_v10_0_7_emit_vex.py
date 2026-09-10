"""v10.0.7 regression: ``emit-vex`` stops publishing silently-wrong documents.

Two defects from the v10.0.6 clean-room validation, both of the "exit 0 and say
nothing" class:

- **A one-character typo in ``--waivers`` changed the published document.** With
  the real waivers file the VEX carries ``state: not_affected`` /
  ``justification: code_not_reachable``; with ``ws.yaml`` misspelt ``wa.yaml`` the
  same command emitted ``state: in_triage`` and the "Manufacturer analysis pending"
  placeholder, at exit 0, with stdout *and* stderr completely silent. A directory
  behaved identically. Every other bad-waivers case (unreadable file, bad entry,
  expired entry, unmatched id) already warned — this was the one silent branch.

- **Structurally invalid SARIF was accepted.** ``{"runs": [1, 2, 3]}`` and
  ``{"runs": [{..., "results": null}]}`` produced an empty VEX document at exit 0
  ("0 vulnerability ID(s)"), which a downstream consumer reads as "the manufacturer
  scanned and has nothing to declare".

Also covered, found while fixing the above and of the same class:

- A deeply nested ``--osv-sarif`` crashed the C JSON scanner and escaped as exit 3
  ("Unexpected error: maximum recursion depth exceeded").
- The ``OSError`` read branch rendered ``str(exc)``, which carries the absolute
  filename (M-002).

The negative controls matter as much as the positives here: a guard that fires on
the *correct* waivers path, or refuses a legitimately sparse SARIF, would be a
worse bug than the one being fixed. Those tests are marked "control" below.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from oss_policy_kit.cli import emit_vex as ev

# --------------------------------------------------------------------------- #
# fixtures / helpers
# --------------------------------------------------------------------------- #

_VULN_ID = "CVE-2024-0001"

_GOOD_SARIF: dict[str, Any] = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {"driver": {"name": "osv-scanner", "rules": [{"id": _VULN_ID}]}},
            "results": [{"ruleId": _VULN_ID}],
        }
    ],
}

_WAIVERS_YAML = (
    "waivers:\n"
    f"  - vulnerability_ids: [{_VULN_ID}]\n"
    "    justification: dependency is never loaded at runtime\n"
    "    owner: appsec@example.org\n"
    "    vex_justification: code_not_reachable\n"
)


def _run_cli(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    """Invoke the real CLI from *cwd* with a wide, colourless terminal.

    ``COLUMNS`` is pinned because Rich hard-wraps stderr at the terminal width, and a
    wrapped message splits assertion needles mid-phrase (the failure then depends on
    the machine, not on the code). Callers still normalise whitespace via ``_norm``.
    """

    env = {**os.environ, "COLUMNS": "300", "NO_COLOR": "1", "TERM": "dumb"}
    return subprocess.run(
        [sys.executable, "-m", "oss_policy_kit", *args],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        text=True,
        cwd=cwd,
        env=env,
    )


def _norm(text: str) -> str:
    """Collapse whitespace so a Rich line break cannot hide a needle."""

    return " ".join(text.split())


def _write(tmp_path: Path, name: str, payload: object) -> Path:
    p = tmp_path / name
    p.write_text(json.dumps(payload), encoding="utf-8")
    return p


def _waivers(tmp_path: Path) -> Path:
    p = tmp_path / "ws.yaml"
    p.write_text(_WAIVERS_YAML, encoding="utf-8")
    return p


def _lab(tmp_path: Path) -> Path:
    """A working directory holding a valid SARIF and a valid waivers file."""

    _write(tmp_path, "osv.sarif.json", _GOOD_SARIF)
    _waivers(tmp_path)
    return tmp_path


def _analysis(stdout: str) -> dict[str, str]:
    return json.loads(stdout)["vulnerabilities"][0]["analysis"]


# --------------------------------------------------------------------------- #
# Defect A — an explicit --waivers path that cannot be read is no longer silent
# --------------------------------------------------------------------------- #


def test_waivers_typo_is_reported_instead_of_silently_changing_the_document(tmp_path: Path) -> None:
    """The headline defect: `--waivers wa.yaml` (one character off) must say so.

    The command may still emit a document, but it may not do so in silence: the
    operator asked for waivers and got none, and the difference is visible only in
    the published VEX.
    """

    lab = _lab(tmp_path)
    proc = _run_cli(["emit-vex", "--osv-sarif", "osv.sarif.json", "--waivers", "wa.yaml"], cwd=lab)

    assert proc.returncode != 3, f"stderr={proc.stderr}"
    assert "Traceback" not in proc.stderr
    err = _norm(proc.stderr)
    assert "Waiver warning:" in err, f"stderr was silent: {proc.stderr!r}"
    assert "wa.yaml" in err
    assert "does not exist" in err


def test_waivers_typo_warning_accompanies_the_downgraded_analysis(tmp_path: Path) -> None:
    """The warning must be attached to the run that actually lost the waiver.

    Asserting on the emitted document as well as on stderr is what makes this test
    about the defect (a document that quietly says `in_triage`) rather than about a
    log line that happens to exist.
    """

    lab = _lab(tmp_path)
    proc = _run_cli(["emit-vex", "--osv-sarif", "osv.sarif.json", "--waivers", "wa.yaml"], cwd=lab)

    assert proc.returncode == 0, f"stderr={proc.stderr}"
    assert _analysis(proc.stdout)["state"] == "in_triage"
    assert "Waiver warning:" in _norm(proc.stderr)


def test_waivers_directory_is_reported(tmp_path: Path) -> None:
    """A directory passed to --waivers behaved exactly like the typo: silence."""

    lab = _lab(tmp_path)
    (lab / "waiverdir").mkdir()
    proc = _run_cli(["emit-vex", "--osv-sarif", "osv.sarif.json", "--waivers", "waiverdir"], cwd=lab)

    assert proc.returncode != 3, f"stderr={proc.stderr}"
    err = _norm(proc.stderr)
    assert "Waiver warning:" in err, f"stderr was silent: {proc.stderr!r}"
    assert "is a directory, not a file" in err


def test_waivers_warning_reaches_openvex_too(tmp_path: Path) -> None:
    """--format openvex reads the same waivers and had the same silent branch."""

    lab = _lab(tmp_path)
    proc = _run_cli(
        [
            "emit-vex",
            "--osv-sarif",
            "osv.sarif.json",
            "--waivers",
            "wa.yaml",
            "--format",
            "openvex",
            "--product",
            "pkg:pypi/acme@1.2.3",
        ],
        cwd=lab,
    )

    assert proc.returncode != 3, f"stderr={proc.stderr}"
    assert "Waiver warning:" in _norm(proc.stderr)
    assert json.loads(proc.stdout)["statements"][0]["status"] == "under_investigation"


def test_waivers_warning_does_not_leak_an_absolute_path(tmp_path: Path) -> None:
    """M-002: the message echoes what the operator typed, never a resolved path.

    Asserted with a RELATIVE argument on purpose. With an absolute argument the
    assertion would pass for the wrong reason (the needle would be the input), and on
    Windows a resolved path can also come back in 8.3 short form, which no
    long-form needle would match.
    """

    lab = _lab(tmp_path)
    proc = _run_cli(["emit-vex", "--osv-sarif", "osv.sarif.json", "--waivers", "wa.yaml"], cwd=lab)

    err = _norm(proc.stderr)
    assert "Waiver warning:" in err
    assert str(lab) not in proc.stderr
    assert lab.as_posix() not in proc.stderr
    assert lab.name not in proc.stderr


def test_control_correct_waivers_path_applies_the_waiver_and_says_nothing(tmp_path: Path) -> None:
    """Control: the one-character difference. The good path must stay clean.

    This is the mutation guard against "warn unconditionally": a warning here would
    make the flag useless and train operators to ignore the line.
    """

    lab = _lab(tmp_path)
    proc = _run_cli(["emit-vex", "--osv-sarif", "osv.sarif.json", "--waivers", "ws.yaml"], cwd=lab)

    assert proc.returncode == 0, f"stderr={proc.stderr}"
    analysis = _analysis(proc.stdout)
    assert analysis["state"] == "not_affected"
    assert analysis["justification"] == "code_not_reachable"
    assert "Waiver warning:" not in proc.stderr, proc.stderr


def test_control_absent_default_waivers_stays_silent(tmp_path: Path) -> None:
    """Control: a project with no waivers/waivers.yaml is an ordinary state.

    The flag was never typed, so there is nothing to correct and nothing to say.
    """

    lab = _lab(tmp_path)
    assert not (lab / "waivers").exists()
    proc = _run_cli(["emit-vex", "--osv-sarif", "osv.sarif.json"], cwd=lab)

    assert proc.returncode == 0, f"stderr={proc.stderr}"
    assert "Waiver warning:" not in proc.stderr, proc.stderr


def test_explicit_waivers_warning_helper_branches(tmp_path: Path) -> None:
    """Unit view of the same three states, independent of Rich rendering."""

    good = _waivers(tmp_path)
    a_dir = tmp_path / "d"
    a_dir.mkdir()

    assert ev._explicit_waivers_warning(good) is None
    missing = ev._explicit_waivers_warning(Path("nope.yaml"))
    assert missing is not None
    assert "does not exist" in missing
    directory = ev._explicit_waivers_warning(a_dir)
    assert directory is not None
    assert "is a directory" in directory


# --------------------------------------------------------------------------- #
# Defect B — structurally invalid SARIF is refused instead of yielding an empty VEX
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("label", "payload", "needle"),
    [
        ("runs_of_integers", {"runs": [1, 2, 3]}, "runs[0] must be an object, not a number"),
        (
            "results_null",
            {"runs": [{"tool": {"driver": {"rules": [{"id": _VULN_ID}]}}, "results": None}]},
            "runs[0].results must be an array, not null",
        ),
        (
            "results_string",
            {"runs": [{"results": "nope"}]},
            "runs[0].results must be an array, not a string",
        ),
        (
            "rules_not_an_array",
            {"runs": [{"tool": {"driver": {"rules": "nope"}}, "results": []}]},
            "runs[0].tool.driver.rules must be an array, not a string",
        ),
        (
            "result_entry_not_an_object",
            {"runs": [{"results": [{"ruleId": _VULN_ID}, 7]}]},
            "runs[0].results[1] must be an object, not a number",
        ),
        (
            "tool_not_an_object",
            {"runs": [{"tool": "osv-scanner", "results": []}]},
            "runs[0].tool must be an object, not a string",
        ),
    ],
)
def test_structurally_invalid_sarif_exits_2_and_names_the_field(
    tmp_path: Path, label: str, payload: dict[str, object], needle: str
) -> None:
    """Each shape must be refused with exit 2 and a message naming the offending field."""

    _waivers(tmp_path)
    _write(tmp_path, "bad.sarif.json", payload)
    proc = _run_cli(["emit-vex", "--osv-sarif", "bad.sarif.json", "--waivers", "ws.yaml"], cwd=tmp_path)

    assert proc.returncode == 2, f"[{label}] stdout={proc.stdout} stderr={proc.stderr}"
    assert "Traceback" not in proc.stderr
    assert "Unexpected error" not in proc.stderr
    assert needle in _norm(proc.stderr), f"[{label}] stderr={proc.stderr!r}"
    # The refusal replaces the document; nothing may be written to stdout.
    assert proc.stdout.strip() == "", f"[{label}] emitted a document anyway: {proc.stdout!r}"


def test_invalid_sarif_never_emits_an_empty_vex_document(tmp_path: Path) -> None:
    """The concrete harm: "0 vulnerability ID(s)" written to --output at exit 0.

    A consumer cannot tell that document apart from an honest clean scan.
    """

    _waivers(tmp_path)
    _write(tmp_path, "bad.sarif.json", {"runs": [1, 2, 3]})
    out = tmp_path / "vex.json"
    proc = _run_cli(
        ["emit-vex", "--osv-sarif", "bad.sarif.json", "--waivers", "ws.yaml", "--output", str(out)],
        cwd=tmp_path,
    )

    assert proc.returncode == 2, f"stderr={proc.stderr}"
    assert not out.exists(), f"wrote a VEX document from a malformed scan: {out.read_text(encoding='utf-8')}"


def test_invalid_sarif_refused_under_openvex_too(tmp_path: Path) -> None:
    """The same gate applies to --format openvex (same reader, same harm)."""

    _waivers(tmp_path)
    _write(tmp_path, "bad.sarif.json", {"runs": [{"results": None}]})
    proc = _run_cli(
        [
            "emit-vex",
            "--osv-sarif",
            "bad.sarif.json",
            "--waivers",
            "ws.yaml",
            "--format",
            "openvex",
            "--product",
            "pkg:pypi/acme@1.2.3",
        ],
        cwd=tmp_path,
    )

    assert proc.returncode == 2, f"stdout={proc.stdout} stderr={proc.stderr}"
    assert "not a structurally valid SARIF document" in _norm(proc.stderr)
    assert proc.stdout.strip() == ""


def test_structure_refusal_does_not_leak_an_absolute_path(tmp_path: Path) -> None:
    """M-002: the refusal names the SARIF by basename, never by resolved path."""

    _waivers(tmp_path)
    _write(tmp_path, "bad.sarif.json", {"runs": [1]})
    proc = _run_cli(["emit-vex", "--osv-sarif", "bad.sarif.json", "--waivers", "ws.yaml"], cwd=tmp_path)

    assert proc.returncode == 2, proc.stderr + proc.stdout
    assert "bad.sarif.json" in _norm(proc.stderr)
    assert str(tmp_path) not in proc.stderr
    assert tmp_path.as_posix() not in proc.stderr
    assert tmp_path.name not in proc.stderr


@pytest.mark.parametrize(
    ("label", "payload"),
    [
        ("empty_runs", {"version": "2.1.0", "runs": []}),
        ("run_without_results", {"runs": [{"tool": {"driver": {"rules": [{"id": _VULN_ID}]}}}]}),
        ("run_without_tool", {"runs": [{"results": [{"ruleId": _VULN_ID}]}]}),
        ("empty_results_array", {"runs": [{"tool": {"driver": {"rules": []}}, "results": []}]}),
        ("driver_without_rules", {"runs": [{"tool": {"driver": {"name": "osv-scanner"}}, "results": []}]}),
        ("valid_full_document", _GOOD_SARIF),
    ],
)
def test_control_legitimate_sarif_shapes_still_succeed(tmp_path: Path, label: str, payload: object) -> None:
    """Control: sparse-but-valid SARIF must keep working.

    Mutation guard against over-tightening — refusing a clean scan (``runs: []``) or a
    hand-trimmed fixture would break every honest adopter to catch a malformed one.
    """

    _waivers(tmp_path)
    _write(tmp_path, "ok.sarif.json", payload)
    proc = _run_cli(["emit-vex", "--osv-sarif", "ok.sarif.json", "--waivers", "ws.yaml"], cwd=tmp_path)

    assert proc.returncode == 0, f"[{label}] stderr={proc.stderr}"
    assert json.loads(proc.stdout)["bomFormat"] == "CycloneDX"


def test_validate_sarif_structure_accepts_and_rejects() -> None:
    """Unit view: the validator is strict about present-but-wrong, quiet about absent."""

    assert ev._validate_sarif_structure(_GOOD_SARIF) == []
    assert ev._validate_sarif_structure({"runs": []}) == []
    assert ev._validate_sarif_structure({"runs": [{}]}) == []
    assert ev._validate_sarif_structure({"runs": "nope"}) == ["'runs' must be an array"]
    assert ev._validate_sarif_structure({}) == ["'runs' must be an array"]
    assert ev._validate_sarif_structure({"runs": [None]}) == ["runs[0] must be an object, not null"]


def test_validate_sarif_structure_caps_the_message_list() -> None:
    """A hostile SARIF must not turn into a message list proportional to its size."""

    doc = {"runs": [{"results": list(range(5000))}]}
    errs = ev._validate_sarif_structure(doc)
    assert len(errs) == ev._MAX_SARIF_STRUCTURE_ERRORS
    assert errs[0] == "runs[0].results[0] must be an object, not a number"


def test_bad_element_errors_stops_at_its_budget() -> None:
    """The cap must be enforced while *collecting*, not only while reporting.

    Truncating at the end would still build one message per bad entry first, and a
    20 MiB SARIF holds millions of them — the outer ``errs[:limit]`` hides that, so
    the budget is asserted here where it is actually spent.
    """

    items: list[object] = list(range(1000))
    assert len(ev._bad_element_errors("x", items, 3)) == 3
    assert ev._bad_element_errors("x", items, 0) == []
    assert ev._bad_element_errors("x", items, -1) == []
    # Well-formed entries never consume budget.
    assert ev._bad_element_errors("x", [{"a": 1}, {"b": 2}], 5) == []


def test_collect_sarif_data_stays_tolerant() -> None:
    """The reader keeps skipping what it cannot understand — strictness lives in the gate.

    Pinned so a future change cannot move the refusal into the shared reader, where it
    would also break the evaluator paths that legitimately read partial SARIF.
    """

    ids, refs = ev._collect_sarif_data(
        {
            "runs": [
                123,
                {"tool": {"driver": {"rules": [7, {"id": "CVE-A", "helpUri": "https://osv.dev/CVE-A"}]}}},
                {"results": ["x", {"ruleId": "CVE-B"}]},
            ]
        }
    )
    assert ids == ["CVE-A", "CVE-B"]
    assert refs == {"CVE-A": ["https://osv.dev/CVE-A"]}


# --------------------------------------------------------------------------- #
# Same class, found while fixing the above
# --------------------------------------------------------------------------- #


def test_deeply_nested_sarif_exits_2_not_3(tmp_path: Path) -> None:
    """A deep document exhausted the C JSON scanner and escaped as exit 3.

    ``RecursionError`` is a ``RuntimeError``, so neither the ``OSError`` nor the
    ``JSONDecodeError`` handler caught it. Depth is now checked before parsing, with
    the shared ``too_deep_reason`` so one problem has one explanation.
    """

    _waivers(tmp_path)
    depth = 6000
    payload = '{"version":"2.1.0","runs":[],"x":' + ('{"a":' * depth) + "1" + ("}" * depth) + "}"
    (tmp_path / "deep.sarif.json").write_text(payload, encoding="utf-8")

    proc = _run_cli(["emit-vex", "--osv-sarif", "deep.sarif.json", "--waivers", "ws.yaml"], cwd=tmp_path)

    assert proc.returncode == 2, f"stdout={proc.stdout} stderr={proc.stderr}"
    assert "Traceback" not in proc.stderr
    assert "Unexpected error" not in proc.stderr
    assert "nested too deeply" in _norm(proc.stderr)


def test_sarif_read_error_does_not_leak_the_absolute_filename(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """M-002: ``str(OSError)`` carries the absolute filename; ``bad_input_detail`` does not.

    The leaked path is supplied by the test rather than by the OS so both sides of the
    assertion are exact — a real ``PermissionError`` cannot be provoked portably, and
    a resolved Windows path can come back in 8.3 short form.
    """

    sarif = _write(tmp_path, "osv.sarif.json", _GOOD_SARIF)
    # A synthetic drive root rather than a home-directory shape: the public-hygiene
    # scanner flags home-looking paths in tracked files by pattern, and it is right to —
    # a repository cannot tell a fabricated account name from a real one.
    secret = r"Z:\srv\vol1\acct-name\projects\private\osv.sarif.json"

    def _denied(self: Path, *a: object, **k: object) -> str:
        raise PermissionError(13, "Permission denied", secret)

    monkeypatch.setattr(Path, "read_text", _denied)
    doc, err = ev._read_sarif_document(sarif)

    assert doc == {}
    assert err is not None
    assert "Could not read SARIF" in err
    assert "Permission denied" in err
    assert secret not in err
    assert "some-account" not in err
