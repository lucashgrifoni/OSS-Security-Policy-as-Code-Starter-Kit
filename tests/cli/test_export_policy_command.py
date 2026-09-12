"""Coverage for the ``export-policy`` command (ADR-035).

Three layers:

1. Golden byte-stability + CLI surface + renderer/validator units — always run
   (including CI), no external tooling needed.
2. ``test_generated_cel_compiles_and_evaluates`` — compiles every generated CEL
   expression with ``cel-python`` and checks the aggregate gates correctly.
   Skipped where ``celpy`` is not installed (CI does not install it).
3. ``test_generated_rego_checks_and_gates`` — runs ``opa check`` + ``opa eval``
   on the generated Rego. Skipped where the ``opa`` binary is not available.

Layers 2 and 3 are the real proof that the generated policy is valid for the
target engines; they encode, durably, the local verification done when the
renderers were authored.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from oss_policy_kit.application.loader import bundled_kit_root, load_catalog, load_profile_by_id
from oss_policy_kit.cli import export_policy as ep
from oss_policy_kit.cli.main import app
from oss_policy_kit.domain.errors import InvalidInputError

runner = CliRunner()

GOLDEN_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "golden"
REPO_ROOT = Path(__file__).resolve().parents[2]

_PROFILE = "github-level-1"
_CONTROL_IDS = [
    "GOV-SEC-001",
    "GOV-CON-002",
    "GOV-COWN-003",
    "GOV-LIC-004",
    "CI-WF-005",
    "CI-PERM-006",
    "CI-DANGER-007",
    "CI-PIN-008",
    "CI-LEAST-009",
    "SEC-CODEQL-010",
    "SEC-DEPREV-011",
    "REL-CHANGE-012",
    "GOV-DISC-013",
    "GOV-WAIV-014",
]


def _good_report() -> dict:
    return {"controls": [{"id": c, "state": "PASS"} for c in _CONTROL_IDS]}


def _bad_report() -> dict:
    report = _good_report()
    report["controls"][7]["state"] = "FAIL"  # CI-PIN-008 fails the gate
    return report


def _find_opa() -> str | None:
    found = shutil.which("opa")
    if found:
        return found
    for cand in (REPO_ROOT / ".venv-ci" / "opa.exe", REPO_ROOT / ".venv-ci" / "opa"):
        if cand.is_file():
            return str(cand)
    return None


# --- Golden byte-stability (always runs, including CI) ----------------------


def test_rego_matches_golden(tmp_path: Path) -> None:
    out = tmp_path / "p.rego"
    res = runner.invoke(app, ["export-policy", "--profile", _PROFILE, "--format", "rego", "--output", str(out)])
    assert res.exit_code == 0, res.output
    expected = (GOLDEN_DIR / "export_policy.github_level_1.rego").read_text(encoding="utf-8")
    assert out.read_text(encoding="utf-8") == expected


def test_cel_matches_golden(tmp_path: Path) -> None:
    out = tmp_path / "p.cel"
    res = runner.invoke(app, ["export-policy", "--profile", _PROFILE, "--format", "cel", "--output", str(out)])
    assert res.exit_code == 0, res.output
    expected = (GOLDEN_DIR / "export_policy.github_level_1.cel").read_text(encoding="utf-8")
    assert out.read_text(encoding="utf-8") == expected


def test_render_is_deterministic() -> None:
    """Rendering the same profile twice must produce the same policy text.

    The failure this guards is a renderer that iterates something unordered or reaches
    for a clock or a uuid: the emitted Rego/CEL would then differ between runs, and an
    adopter diffing two exports of an unchanged profile would see phantom churn.

    Reloading the catalog and profile for the second render is deliberate. Comparing two
    renders of the *same* in-memory objects would still pass if ordering came from those
    objects' identity rather than from their content.
    """
    root = bundled_kit_root()
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    prof = load_profile_by_id(root, _PROFILE)

    rego_first = ep._render_rego(prof, catalog)
    cel_first = ep._render_cel(prof, catalog)

    catalog_reloaded = load_catalog(root / "controls" / "catalog.yaml")
    prof_reloaded = load_profile_by_id(root, _PROFILE)

    assert rego_first == ep._render_rego(prof_reloaded, catalog_reloaded), (
        "Rego output changed for an unchanged profile loaded a second time"
    )
    assert cel_first == ep._render_cel(prof_reloaded, catalog_reloaded), (
        "CEL output changed for an unchanged profile loaded a second time"
    )


# --- CLI surface ------------------------------------------------------------


def test_default_output_path_rego(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    res = runner.invoke(app, ["export-policy", "--profile", _PROFILE])
    assert res.exit_code == 0, res.output
    assert (tmp_path / "policy.rego").is_file()
    assert "format=rego" in res.output


def test_default_output_path_cel(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    res = runner.invoke(app, ["export-policy", "--profile", _PROFILE, "--format", "cel"])
    assert res.exit_code == 0, res.output
    assert (tmp_path / "policy.cel").is_file()


def test_validate_ok(tmp_path: Path) -> None:
    out = tmp_path / "p.rego"
    res = runner.invoke(
        app,
        ["export-policy", "--profile", _PROFILE, "--format", "rego", "--output", str(out), "--validate"],
    )
    assert res.exit_code == 0, res.output


def test_format_is_case_insensitive(tmp_path: Path) -> None:
    out = tmp_path / "p.rego"
    res = runner.invoke(app, ["export-policy", "--profile", _PROFILE, "--format", "REGO", "--output", str(out)])
    assert res.exit_code == 0, res.output


def test_bad_format() -> None:
    res = runner.invoke(app, ["export-policy", "--profile", _PROFILE, "--format", "yaml"])
    # Clean OssPolicyKitError -> Exit(2), not an uncaught InvalidInputError traceback (exit 1).
    assert res.exit_code == 2
    assert not isinstance(res.exception, InvalidInputError)


def test_unknown_profile() -> None:
    res = runner.invoke(app, ["export-policy", "--profile", "does-not-exist-profile"])
    assert res.exit_code == 2
    assert not isinstance(res.exception, InvalidInputError)


# --- Renderer / validator units ---------------------------------------------


def test_validate_helpers_catch_malformed() -> None:
    assert ep._validate("package osspolicykit\nallow := true\n", "rego") == []
    assert ep._validate("allow := true\n", "rego")  # missing package header
    assert ep._validate("package osspolicykit\ndeny if {\n", "rego")  # unbalanced braces

    good_cel = '# FIDELITY BOUNDARY\nreport.controls.exists(c, c.id == "X")\n'
    assert ep._validate(good_cel, "cel") == []
    assert ep._validate('report.controls.exists(c, c.id == "X")\n', "cel")  # missing header
    assert ep._validate("# FIDELITY BOUNDARY\n", "cel")  # no expressions


def test_rego_has_one_deny_per_control() -> None:
    root = bundled_kit_root()
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    prof = load_profile_by_id(root, _PROFILE)
    rego = ep._render_rego(prof, catalog)
    assert rego.count("deny contains msg if {") == len(set(prof.control_ids))
    assert "package osspolicykit" in rego
    assert "FIDELITY BOUNDARY" in rego
    for cid in prof.control_ids:
        assert f'not control_satisfied("{cid}")' in rego


def test_cel_has_one_expression_per_control_plus_aggregate() -> None:
    root = bundled_kit_root()
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    prof = load_profile_by_id(root, _PROFILE)
    cel = ep._render_cel(prof, catalog)
    exprs = [ln for ln in cel.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    assert len(exprs) == len(set(prof.control_ids)) + 1  # per-control + aggregate
    assert "FIDELITY BOUNDARY" in cel


# --- Real engine verification ----------------------------------------------
#
# The two halves below do not run in the same places, and the comment that stood here
# said neither of them ran in CI. That stopped being true once the quality job started
# installing opa by pinned digest: the Rego half runs on every Linux gate run, and
# tests/infrastructure/test_the_rego_fidelity_check_still_runs_in_ci.py holds it there,
# so removing that install step fails a test instead of silently turning this into a skip.
#
# The CEL half still runs nowhere automatically. `celpy` appears in no extra, no workflow
# and no image, so `importorskip` skips it on every leg. The generated CEL was checked by
# hand against cel-python 0.5.0 on 2026-09-10 -- it compiles, the passing report evaluates
# true and the failing one false, and a renderer mutated to emit `===` was caught by the
# parser -- but that is one dated run, not a gate. Installing cel-python costs five
# transitive dependencies, one of them a compiled extension (google-re2), on three matrix
# legs; that is the decision to take before this line may claim CI verifies CEL.


def test_generated_cel_compiles_and_evaluates() -> None:
    celpy = pytest.importorskip("celpy")
    root = bundled_kit_root()
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    prof = load_profile_by_id(root, _PROFILE)
    text = ep._render_cel(prof, catalog)
    exprs = [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    env = celpy.Environment()
    programs = [env.program(env.compile(expr)) for expr in exprs]  # compile() raises on syntax error
    aggregate = programs[-1]
    # celpy returns its own BoolType; coerce to a plain bool for the assertion.
    assert bool(aggregate.evaluate({"report": celpy.json_to_cel(_good_report())})) is True
    assert bool(aggregate.evaluate({"report": celpy.json_to_cel(_bad_report())})) is False


def test_generated_rego_checks_and_gates(tmp_path: Path) -> None:
    opa = _find_opa()
    if opa is None:
        pytest.skip("opa binary not available")
    policy = tmp_path / "policy.rego"
    res = runner.invoke(app, ["export-policy", "--profile", _PROFILE, "--format", "rego", "--output", str(policy)])
    assert res.exit_code == 0, res.output

    check = subprocess.run(
        [opa, "check", str(policy)], capture_output=True, encoding="utf-8", errors="replace", text=True
    )  # noqa: S603
    assert check.returncode == 0, check.stderr

    good = tmp_path / "good.json"
    good.write_text(json.dumps(_good_report()), encoding="utf-8")
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(_bad_report()), encoding="utf-8")

    def _allow(inp: Path) -> str:
        cmd = [opa, "eval", "-d", str(policy), "-i", str(inp), "data.osspolicykit.allow", "--format", "raw"]
        proc = subprocess.run(cmd, capture_output=True, encoding="utf-8", errors="replace", text=True)  # noqa: S603
        assert proc.returncode == 0, proc.stderr
        return proc.stdout.strip()

    assert _allow(good) == "true"
    assert _allow(bad) == "false"


# --- A control id must arrive as a string, never as syntax ------------------
#
# `--profile` takes a path, and the profile schema constrains `controls` items only to a
# non-empty string, so any string can name a control. Both renderers used to interpolate that
# string straight into a quoted literal. Measured on the parent commit with the profile below:
#
#     Rego   opa check REJECTS       rego_parse_error: unexpected ; token
#     CEL    8 of 9 expressions fail to compile
#     kit    --validate exits 0 for both
#
# The output is run by another engine in somebody's gate, so a quote in an id was a way to write
# policy. `_policy_string` closes it, and the 112 files rendered from the 56 bundled profiles are
# byte-identical before and after, which is why the golden tests above still pass.

#: Hostile ids, built from parts rather than written as literals: the point of each one is an
#: escape sequence, and a literal spelling of it is exactly what a copy through a shell or an
#: editor gets wrong. `chr(10)` is a newline, `chr(92)` a backslash.
_HOSTILE_IDS = [
    "GOV-SEC-001",
    'C-1" ; allow := true # ',  # closes the literal, then writes a rule
    "C-2" + chr(10) + "not_a_control",  # breaks out of the single-line comment
    "C-3" + chr(92),  # trailing backslash swallows the closing quote
]


def _hostile_profile(tmp_path: Path) -> Path:
    """A schema-valid profile whose control ids are hostile. YAML is a superset of JSON."""

    path = tmp_path / "hostile.yaml"
    path.write_text(
        json.dumps({"id": "hostile-1", "title": "Hostile", "controls": _HOSTILE_IDS}),
        encoding="utf-8",
    )
    return path


def test_the_string_helper_escapes_what_both_engines_need() -> None:
    """Rego and CEL both take JSON string syntax, which is why one helper serves both."""

    assert ep._policy_string("GOV-SEC-001") == '"GOV-SEC-001"'
    assert ep._policy_string('a"b') == json.dumps('a"b')
    assert ep._policy_string("a" + chr(10) + "b") == json.dumps("a" + chr(10) + "b")
    assert ep._policy_string("a" + chr(92)) == json.dumps("a" + chr(92))
    # Every result is a legal JSON string, which is the property both engines need.
    for raw in [*_HOSTILE_IDS, "", " ", chr(10), chr(92) * 3]:
        assert json.loads(ep._policy_string(raw)) == raw


@pytest.mark.parametrize("fmt", ["rego", "cel"])
def test_a_hostile_id_adds_no_lines_to_the_rendered_policy(fmt: str, tmp_path: Path) -> None:
    """A newline inside an id must stay inside its literal, not become a line of the file.

    The obvious assertion here -- that the injected fragment does not appear in the text -- is a
    bad oracle, and writing it that way failed for the right reason: `allow := true` DOES appear,
    escaped, inside the literal `"C-1\\" ; allow := true #"`. Appearing as data is not the same
    as being policy, and a substring search cannot tell them apart.

    Line count can. Rendering a benign profile with the same number of controls gives the shape
    the renderer intends; a hostile id that escaped would produce more lines than that.
    """

    benign = tmp_path / "benign.yaml"
    benign.write_text(
        json.dumps({"id": "benign-1", "title": "Benign", "controls": [f"C-{n}" for n in range(len(_HOSTILE_IDS))]}),
        encoding="utf-8",
    )

    def _render(profile: Path, name: str) -> list[str]:
        out = tmp_path / f"{name}.{fmt}"
        res = runner.invoke(app, ["export-policy", "--profile", str(profile), "--format", fmt, "--output", str(out)])
        assert res.exit_code == 0, res.output
        return out.read_text(encoding="utf-8").splitlines()

    assert len(_render(_hostile_profile(tmp_path), "hostile")) == len(_render(benign, "benign"))


def test_a_hostile_control_id_still_produces_policy_opa_accepts(tmp_path: Path) -> None:
    """`opa check` is the only authority on whether this file is Rego.

    The kit's own `--validate` counts braces, which is why it answered 0 while opa answered 1.
    """

    opa = _find_opa()
    if opa is None:
        pytest.skip("opa binary not available")

    policy = tmp_path / "policy.rego"
    res = runner.invoke(
        app,
        ["export-policy", "--profile", str(_hostile_profile(tmp_path)), "--format", "rego", "--output", str(policy)],
    )
    assert res.exit_code == 0, res.output

    check = subprocess.run(  # noqa: S603
        [opa, "check", str(policy)], capture_output=True, encoding="utf-8", errors="replace", text=True
    )
    assert check.returncode == 0, check.stderr


def test_the_injected_rule_does_not_decide_the_gate(tmp_path: Path) -> None:
    """The half that matters. A syntactically valid policy can still be the attacker's policy.

    The report supplied here satisfies none of the profile's controls, so the gate must refuse.
    If the fragment in the id had become a rule, `allow` would be unconditionally true and this
    would pass while the repository failed every control.
    """

    opa = _find_opa()
    if opa is None:
        pytest.skip("opa binary not available")

    policy = tmp_path / "policy.rego"
    runner.invoke(
        app,
        ["export-policy", "--profile", str(_hostile_profile(tmp_path)), "--format", "rego", "--output", str(policy)],
    )
    empty = tmp_path / "empty.json"
    empty.write_text(json.dumps({"controls": []}), encoding="utf-8")

    proc = subprocess.run(  # noqa: S603
        [opa, "eval", "-d", str(policy), "-i", str(empty), "data.osspolicykit.allow", "--format", "raw"],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "false"


def test_every_expression_of_a_hostile_profile_compiles_as_cel(tmp_path: Path) -> None:
    """An expression that does not compile is a gate that never denies."""

    celpy = pytest.importorskip("celpy")

    out = tmp_path / "policy.cel"
    runner.invoke(
        app,
        ["export-policy", "--profile", str(_hostile_profile(tmp_path)), "--format", "cel", "--output", str(out)],
    )
    exprs = [
        ln for ln in out.read_text(encoding="utf-8").splitlines() if ln.strip() and not ln.lstrip().startswith("#")
    ]
    assert exprs, "no expressions emitted"

    env = celpy.Environment()
    for expr in exprs:
        env.program(env.compile(expr))


@pytest.mark.parametrize("fmt", ["rego", "cel"])
def test_a_hostile_profile_id_stays_inside_the_header_comment(fmt: str, tmp_path: Path) -> None:
    """The profile id is interpolated into five comment lines of the header.

    `_one_line` was applied to the profile title and not to the id, the same asymmetry the
    per-control comment had. A newline in the id put text at the start of a line, outside any
    comment, three times, and the file then failed to parse before reaching `package`.
    """

    nl = chr(10)
    profile = tmp_path / "p.yaml"
    profile.write_text(
        json.dumps(
            {
                "id": "p-1" + nl + "allow_everything := true" + nl + "# ",
                "title": "T" + nl + "allow_also := true" + nl + "# ",
                "controls": ["GOV-SEC-001"],
            }
        ),
        encoding="utf-8",
    )
    out = tmp_path / f"policy.{fmt}"
    res = runner.invoke(app, ["export-policy", "--profile", str(profile), "--format", fmt, "--output", str(out)])
    assert res.exit_code == 0, res.output

    for line in out.read_text(encoding="utf-8").splitlines():
        assert not line.startswith("allow_everything"), "the id escaped its comment"
        assert not line.startswith("allow_also"), "the title escaped its comment"
