"""v10.0.7 round 2: ``emit-vex`` refuses the wrong file instead of publishing about it.

Three defects from the clean-room validation of the built wheel:

- **A 5000-digit integer in the SARIF escaped as an internal error.** The depth guard
  landed in v10.0.7; its big-integer sibling did not. CPython refuses to convert an
  integer literal longer than 4300 digits and raises a *bare* ``ValueError`` — not a
  ``json.JSONDecodeError`` — so nothing in this module caught it, and the interpreter's
  own ``use sys.set_int_max_str_digits()`` advice reached the operator, who cannot act
  on it. The direct contrast is in the same command: a 3000-level deep SARIF is refused
  cleanly, and a long number was not.

- **The kit's own SARIF became a VEX document about policy controls.** Fed
  ``export-evidence --format sarif`` (or ``evaluate --sarif-output``), emit-vex exited 0,
  passed ``--validate``, and wrote a structurally perfect CycloneDX 1.6 document whose
  entries were ``GOV-SEC-001`` and friends. Published, that asserts to every downstream
  consumer that the manufacturer analysed those *as vulnerabilities*. A structurally
  valid document about the wrong universe of identifiers is worse than no document.

- **The waiver typo warning was escaped twice.** ``--waivers "[dev]waivers.yaml"`` came
  back as ``'\\[dev]waivers.yaml'``: ``_explicit_waivers_warning`` escaped the path for
  Rich and the caller escaped the result again. The whole point of that message is to let
  the operator compare one token against their own command line, and it showed them a
  backslash they never typed. Two siblings in the same file had the same bug in the two
  possible directions (escaped twice; not escaped at all) and are covered here too.

The controls matter as much as the positives. A gate that refuses a legitimate scan, or a
message that stops surviving Rich rendering, would each be worse than the defect being
fixed — so the over-tightening guards are marked "control" below.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from oss_policy_kit.application.loader import bundled_kit_root, load_catalog
from oss_policy_kit.cli import emit_vex as ev

# --------------------------------------------------------------------------- #
# fixtures / helpers
# --------------------------------------------------------------------------- #

_VULN_ID = "CVE-2024-0001"

#: A minimal but honest OSV-Scanner document.
_OSV_SARIF: dict[str, Any] = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {"driver": {"name": "osv-scanner", "rules": [{"id": _VULN_ID}]}},
            "results": [{"ruleId": _VULN_ID}],
        }
    ],
}

#: The kit's own ``export-evidence --format sarif`` shape: policy control ids, kit
#: producer name. Structurally a flawless SARIF; semantically not a vulnerability scan.
_KIT_CONTROL_IDS = ["GOV-SEC-001", "CI-PIN-008", "SAST-OSV-068", "GH-IMMUTREL-070"]

_KIT_SARIF: dict[str, Any] = {
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    "version": "2.1.0",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "oss-policy-kit",
                    "informationUri": "https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit",
                    "rules": [{"id": c} for c in _KIT_CONTROL_IDS],
                }
            },
            "results": [{"ruleId": c, "kind": "fail", "level": "warning"} for c in _KIT_CONTROL_IDS],
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

    ``COLUMNS`` is pinned near the kit's own 512-column ceiling because Rich hard-wraps
    stderr at the terminal width; an unpinned width makes a needle's survival depend on
    the machine running the suite rather than on the code. Callers still normalise
    whitespace through :func:`_norm`, and every *exact* message assertion is made at unit
    level where Rich is not involved at all.
    """

    env = {**os.environ, "COLUMNS": "500", "NO_COLOR": "1", "TERM": "dumb"}
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


def _big_integer_sarif(tmp_path: Path, name: str = "big.sarif.json", digits: int = 5000) -> Path:
    """A structurally valid OSV SARIF carrying one absurdly long integer literal."""

    payload = (
        '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"osv-scanner",'
        f'"rules":[{{"id":"{_VULN_ID}"}}]}}}},'
        f'"results":[{{"ruleId":"{_VULN_ID}","properties":{{"n":{"9" * digits}}}}}]}}]}}'
    )
    p = tmp_path / name
    p.write_text(payload, encoding="utf-8")
    return p


# --------------------------------------------------------------------------- #
# Defect A — a 5000-digit integer is bad input (exit 2), not an internal error
# --------------------------------------------------------------------------- #


def test_big_integer_sarif_is_refused_by_the_reader_itself(tmp_path: Path) -> None:
    """The headline: ``_read_sarif_document`` must RETURN the reason, not raise it.

    Pre-fix this call raised ``ValueError`` straight through the reader, the validator and
    ``_run_emit_vex``, leaving the CLI's last-resort handler to guess what happened. Every
    other hostile-document case is answered here, and so is this one.
    """

    p = _big_integer_sarif(tmp_path)

    doc, err = ev._read_sarif_document(p)

    assert doc == {}
    assert err is not None
    assert "big.sarif.json" in err, err
    assert "4300 digits" in err, err


def test_big_integer_message_drops_cpython_interpreter_advice(tmp_path: Path) -> None:
    """CPython says "use sys.set_int_max_str_digits()"; the operator must fix the FILE.

    The advice is about the interpreter running the kit, not about the document the
    adopter has to correct, and it arrived verbatim because nothing translated it.
    """

    p = _big_integer_sarif(tmp_path)
    _doc, err = ev._read_sarif_document(p)

    assert err is not None
    assert "set_int_max_str_digits" not in err, err
    assert "sys." not in err, err


def test_big_integer_sarif_exits_2_and_names_the_file(tmp_path: Path) -> None:
    """End-to-end: exit 2, no traceback, and the message identifies which file to fix."""

    _waivers(tmp_path)
    _big_integer_sarif(tmp_path)

    proc = _run_cli(["emit-vex", "--osv-sarif", "big.sarif.json", "--waivers", "ws.yaml"], cwd=tmp_path)

    assert proc.returncode == 2, f"stdout={proc.stdout} stderr={proc.stderr}"
    assert "Traceback" not in proc.stderr
    assert "Unexpected error" not in proc.stderr
    err = _norm(proc.stderr)
    assert "big.sarif.json" in err, err
    assert "set_int_max_str_digits" not in err, err
    # A refusal replaces the document; nothing may reach a consumer.
    assert proc.stdout.strip() == "", proc.stdout


def test_big_integer_refusal_reaches_openvex_and_writes_no_document(tmp_path: Path) -> None:
    """The same reader serves ``--format openvex``, and ``--output`` must stay unwritten."""

    _waivers(tmp_path)
    _big_integer_sarif(tmp_path)
    out = tmp_path / "vex.json"

    proc = _run_cli(
        [
            "emit-vex",
            "--osv-sarif",
            "big.sarif.json",
            "--waivers",
            "ws.yaml",
            "--format",
            "openvex",
            "--product",
            "pkg:pypi/acme@1.2.3",
            "--output",
            str(out),
        ],
        cwd=tmp_path,
    )

    assert proc.returncode == 2, f"stdout={proc.stdout} stderr={proc.stderr}"
    assert not out.exists(), "emitted a VEX document from a document it could not parse"


def test_big_integer_and_deep_nesting_are_answered_the_same_way(tmp_path: Path) -> None:
    """The contrast that named the defect: two hostile documents, one outcome.

    A 3000-level deep SARIF was already refused with exit 2 while a long number crashed
    out. Pinning them together stops the two guards from drifting apart again.
    """

    _waivers(tmp_path)
    _big_integer_sarif(tmp_path)
    depth = 3000
    (tmp_path / "deep.sarif.json").write_text(
        '{"version":"2.1.0","runs":[],"x":' + ('{"a":' * depth) + "1" + ("}" * depth) + "}",
        encoding="utf-8",
    )

    for name in ("big.sarif.json", "deep.sarif.json"):
        proc = _run_cli(["emit-vex", "--osv-sarif", name, "--waivers", "ws.yaml"], cwd=tmp_path)
        assert proc.returncode == 2, f"[{name}] stderr={proc.stderr}"
        assert "Traceback" not in proc.stderr, name
        assert "Unexpected error" not in proc.stderr, name
        assert proc.stdout.strip() == "", name


def test_big_integer_refusal_does_not_leak_an_absolute_path(tmp_path: Path) -> None:
    """M-002: the message names the basename the operator typed, never the resolved path.

    Asserted with a RELATIVE argument and a separator-free needle (the distinctive
    directory NAME). With an absolute argument the needle would be the input itself, and a
    resolved Windows path can also come back in 8.3 short form, which no long-form needle
    would ever match.
    """

    lab = tmp_path / "vexlab-round2-dir"
    lab.mkdir()
    _waivers(lab)
    _big_integer_sarif(lab)

    proc = _run_cli(["emit-vex", "--osv-sarif", "big.sarif.json", "--waivers", "ws.yaml"], cwd=lab)

    assert proc.returncode == 2, proc.stderr + proc.stdout
    assert "big.sarif.json" in _norm(proc.stderr)
    assert lab.name not in proc.stderr, proc.stderr
    assert str(lab) not in proc.stderr
    assert lab.as_posix() not in proc.stderr


def test_control_ordinary_numbers_are_still_parsed(tmp_path: Path) -> None:
    """Control: a SARIF full of normal numbers must keep working.

    Mutation guard against "refuse anything numeric" — real OSV-Scanner output carries
    line numbers, offsets and scores on nearly every result.
    """

    _waivers(tmp_path)
    payload = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "osv-scanner", "rules": [{"id": _VULN_ID}]}},
                "results": [
                    {
                        "ruleId": _VULN_ID,
                        "properties": {"score": 9.8, "count": 10**18, "digits": int("9" * 4299)},
                    }
                ],
            }
        ],
    }
    _write(tmp_path, "ok.sarif.json", payload)

    proc = _run_cli(["emit-vex", "--osv-sarif", "ok.sarif.json", "--waivers", "ws.yaml"], cwd=tmp_path)

    assert proc.returncode == 0, f"stderr={proc.stderr}"
    assert json.loads(proc.stdout)["vulnerabilities"][0]["id"] == _VULN_ID


# --------------------------------------------------------------------------- #
# Defect B — a valid SARIF that is not a vulnerability scan is refused
# --------------------------------------------------------------------------- #


def test_kit_evaluation_sarif_is_refused_instead_of_becoming_a_vex_document(tmp_path: Path) -> None:
    """The headline: control ids must never be published as vulnerabilities.

    Pre-fix this exact command exited 0 and printed a CycloneDX 1.6 document whose
    ``vulnerabilities[].id`` values were ``GOV-SEC-001`` and friends.
    """

    _waivers(tmp_path)
    _write(tmp_path, "kit.sarif.json", _KIT_SARIF)

    proc = _run_cli(["emit-vex", "--osv-sarif", "kit.sarif.json", "--waivers", "ws.yaml"], cwd=tmp_path)

    assert proc.returncode == 2, f"stdout={proc.stdout} stderr={proc.stderr}"
    assert "Traceback" not in proc.stderr
    assert "Unexpected error" not in proc.stderr
    assert proc.stdout.strip() == "", f"published a VEX document about policy controls: {proc.stdout!r}"
    err = _norm(proc.stderr)
    assert "GOV-SEC-001" in err, err
    assert "kit.sarif.json" in err, err


def test_validate_no_longer_blesses_the_wrong_document(tmp_path: Path) -> None:
    """``--validate`` passing was the most misleading part: it checked the OUTPUT's shape.

    The document it approved was a perfectly formed CycloneDX 1.6 VEX; the problem was
    never its structure. The refusal has to happen on the way in.
    """

    _waivers(tmp_path)
    _write(tmp_path, "kit.sarif.json", _KIT_SARIF)

    proc = _run_cli(["emit-vex", "--osv-sarif", "kit.sarif.json", "--waivers", "ws.yaml", "--validate"], cwd=tmp_path)

    assert proc.returncode == 2, f"stdout={proc.stdout} stderr={proc.stderr}"
    assert proc.stdout.strip() == ""


def test_kit_sarif_refused_under_openvex_and_writes_no_file(tmp_path: Path) -> None:
    """Same gate on the OpenVEX path, and ``--output`` must remain unwritten."""

    _waivers(tmp_path)
    _write(tmp_path, "kit.sarif.json", _KIT_SARIF)
    out = tmp_path / "vex.openvex.json"

    proc = _run_cli(
        [
            "emit-vex",
            "--osv-sarif",
            "kit.sarif.json",
            "--waivers",
            "ws.yaml",
            "--format",
            "openvex",
            "--product",
            "pkg:pypi/acme@1.2.3",
            "--output",
            str(out),
        ],
        cwd=tmp_path,
    )

    assert proc.returncode == 2, f"stdout={proc.stdout} stderr={proc.stderr}"
    assert not out.exists(), f"wrote an OpenVEX document about policy controls: {out}"


def test_third_party_non_vulnerability_sarif_is_refused_too(tmp_path: Path) -> None:
    """The gate is about the ids, not about this kit.

    A Semgrep / Checkov style SARIF is exactly as wrong an input, and a rule that only
    recognised the kit's own producer name would let it through.
    """

    _waivers(tmp_path)
    payload = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "semgrep", "rules": [{"id": "python.lang.security.audit.eval-detected"}]}},
                "results": [{"ruleId": "python.lang.security.audit.eval-detected"}],
            }
        ],
    }
    _write(tmp_path, "semgrep.sarif.json", payload)

    proc = _run_cli(["emit-vex", "--osv-sarif", "semgrep.sarif.json", "--waivers", "ws.yaml"], cwd=tmp_path)

    assert proc.returncode == 2, f"stdout={proc.stdout} stderr={proc.stderr}"
    assert proc.stdout.strip() == ""
    assert "semgrep" in _norm(proc.stderr)


def test_wrong_input_refusal_does_not_leak_an_absolute_path(tmp_path: Path) -> None:
    """M-002: basename only, asserted with a relative argument and a separator-free needle."""

    lab = tmp_path / "vexlab-wronginput-dir"
    lab.mkdir()
    _waivers(lab)
    _write(lab, "kit.sarif.json", _KIT_SARIF)

    proc = _run_cli(["emit-vex", "--osv-sarif", "kit.sarif.json", "--waivers", "ws.yaml"], cwd=lab)

    assert proc.returncode == 2, proc.stderr + proc.stdout
    assert "kit.sarif.json" in _norm(proc.stderr)
    assert lab.name not in proc.stderr, proc.stderr
    assert str(lab) not in proc.stderr
    assert lab.as_posix() not in proc.stderr


def test_wrong_input_error_names_the_producer_when_the_kit_wrote_the_file(tmp_path: Path) -> None:
    """Unit view of the message, free of Rich wrapping.

    The producer name is a diagnosis, not the gate: it tells the operator *which* command
    made the file they pointed at.
    """

    msg = ev._wrong_input_error(Path("kit.sarif.json"), _KIT_SARIF, sorted(_KIT_CONTROL_IDS))

    assert msg is not None
    assert "does not look like a vulnerability scan" in msg
    assert "oss-policy-kit" in msg
    assert "export-evidence --format sarif" in msg
    assert "osv-scanner --format sarif" in msg
    # A sample of the offending ids, capped — a hostile SARIF must not dictate the length.
    assert "CI-PIN-008" in msg
    assert msg.count(",") < 20, msg


def test_wrong_input_error_caps_everything_the_document_controls() -> None:
    """A hostile SARIF can carry a one-megabyte "id" and a one-megabyte driver name.

    Both are quoted back to the operator, so both are capped: nothing the refused
    document controls may set the length of the refusal.
    """

    huge = "z" * 100_000
    ids = [f"{huge}-{i}" for i in range(500)]
    doc = {"runs": [{"tool": {"driver": {"name": "q" * 100_000, "rules": [{"id": i} for i in ids]}}}]}

    msg = ev._wrong_input_error(Path("hostile.sarif.json"), doc, ids)

    assert msg is not None
    assert len(msg) < 1000, len(msg)
    assert huge not in msg
    assert "q" * 1000 not in msg


def test_control_a_real_osv_scan_is_still_emitted(tmp_path: Path) -> None:
    """Control: the whole point of the command must keep working."""

    _waivers(tmp_path)
    _write(tmp_path, "osv.sarif.json", _OSV_SARIF)

    proc = _run_cli(["emit-vex", "--osv-sarif", "osv.sarif.json", "--waivers", "ws.yaml"], cwd=tmp_path)

    assert proc.returncode == 0, f"stderr={proc.stderr}"
    doc = json.loads(proc.stdout)
    assert doc["vulnerabilities"][0]["id"] == _VULN_ID
    assert doc["vulnerabilities"][0]["analysis"]["state"] == "not_affected"


def test_control_an_empty_scan_still_emits_an_empty_document(tmp_path: Path) -> None:
    """Control: zero findings is a legitimate answer, and a clean scan must not be refused.

    ``examples/hardened-repo`` ships exactly this file. Refusing it would break the kit's
    own walkthrough and every adopter whose dependencies are clean.
    """

    _waivers(tmp_path)
    _write(
        tmp_path,
        "clean.sarif.json",
        {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "osv-scanner", "rules": []}}, "results": []}],
        },
    )

    proc = _run_cli(["emit-vex", "--osv-sarif", "clean.sarif.json", "--waivers", "ws.yaml"], cwd=tmp_path)

    assert proc.returncode == 0, f"stderr={proc.stderr}"
    assert json.loads(proc.stdout)["vulnerabilities"] == []


def test_control_one_recognisable_id_carries_the_whole_document(tmp_path: Path) -> None:
    """Control: the documented escape hatch, pinned so it cannot be tightened by accident.

    A prefix this kit has never heard of must not cost an adopter their run, so a single
    id it *does* recognise is enough for the file. Over-tightening here would refuse real
    scans from ecosystems added to OSV after this release.
    """

    ids = ["SOMEDB-XYZ-1", "another.weird.rule.id", "CVE-2024-9999"]
    doc = {"runs": [{"tool": {"driver": {"rules": [{"id": i} for i in ids]}}}]}

    assert ev._wrong_input_error(Path("mixed.sarif.json"), doc, ids) is None


def test_control_no_ids_at_all_is_never_refused() -> None:
    """Control: nothing to misrepresent means nothing to refuse."""

    assert ev._wrong_input_error(Path("x.sarif.json"), _OSV_SARIF, []) is None


@pytest.mark.parametrize(
    "vid",
    [
        "CVE-2024-0001",
        "CVE-1",
        "GHSA-m5pq-gvj9-9vr8",
        "GHSA-zzzz",
        "RUSTSEC-2022-0013",
        "PYSEC-2026-196",
        "GO-2024-1234",
        "OSV-2021-889",
        "DSA-5678-1",
        "USN-6543-1",
        "ALSA-2023:1234",
        "openSUSE-SU-2024:1234-1",
        "SNYK-PYTHON-REQUESTS-1234",
        "MAL-2024-1234",
        "XSA-2024-9",  # unlisted prefix, carried by the <DB>-<YYYY>-<seq> fallback
    ],
)
def test_vulnerability_ids_are_recognised(vid: str) -> None:
    """Every shape OSV-Scanner and its neighbours emit must pass the identity check."""

    assert ev._looks_like_vulnerability_id(vid), vid


@pytest.mark.parametrize(
    "rule_id",
    [
        "GOV-SEC-001",
        "CI-PIN-008",
        "SAST-OSV-068",
        "GH-IMMUTREL-070",
        "github-level-1",
        "python.lang.security.audit.eval-detected",
        "CKV_AWS_20",
        "",
        "-",
        "no-hyphen",
    ],
)
def test_non_vulnerability_ids_are_rejected(rule_id: str) -> None:
    """Policy control ids and scanner rule names are not vulnerability identifiers."""

    assert not ev._looks_like_vulnerability_id(rule_id), rule_id


def test_no_bundled_control_id_can_pass_as_a_vulnerability_id() -> None:
    """The fence under the whole gate, asserted against the real catalog.

    The refusal only works while no control id looks like an advisory id — a future
    control named ``CVE-...`` or shaped ``XX-2027-001`` would silently re-open the defect
    for every profile that includes it, and nothing else in the suite would notice.
    """

    catalog = load_catalog(bundled_kit_root() / "controls" / "catalog.yaml")
    assert catalog, "catalog failed to load; the fence below would pass vacuously"

    offenders = [cid for cid in catalog if ev._looks_like_vulnerability_id(cid)]

    assert offenders == [], offenders


# --------------------------------------------------------------------------- #
# Defect C — Rich escaping happens exactly once, at the print site
# --------------------------------------------------------------------------- #

_BRACKET_NAME = "[dev]waivers.yaml"
"""A basename carrying a Rich style tag. No separator in it, on purpose: a needle
containing ``/`` or ``\\`` would be testing path normalisation rather than escaping."""


def test_waivers_warning_helper_returns_the_path_unescaped(tmp_path: Path) -> None:
    """The helper must hand the caller raw text; the caller owns the single escape."""

    msg = ev._explicit_waivers_warning(Path(_BRACKET_NAME))

    assert msg is not None
    assert _BRACKET_NAME in msg, msg
    assert "\\[dev]" not in msg, msg


def test_waivers_typo_warning_shows_the_path_exactly_as_typed(tmp_path: Path) -> None:
    """End-to-end: no backslash the operator never typed, and no token Rich ate.

    Both failure directions are asserted, because the two available mistakes here are
    opposites: escaping twice adds a character, escaping zero times deletes ``[dev]``
    entirely. Only escaping once shows the operator what they wrote.
    """

    _write(tmp_path, "osv.sarif.json", _OSV_SARIF)

    proc = _run_cli(["emit-vex", "--osv-sarif", "osv.sarif.json", "--waivers", _BRACKET_NAME], cwd=tmp_path)

    assert proc.returncode == 0, f"stderr={proc.stderr}"
    err = _norm(proc.stderr)
    assert "Waiver warning:" in err, err
    assert _BRACKET_NAME in err, err
    assert "\\[dev]" not in err, err


def test_sarif_structure_refusal_shows_the_filename_exactly_as_typed(tmp_path: Path) -> None:
    """Sibling, same direction: the structural refusal escaped its filename twice."""

    name = "[dev].sarif.json"
    _write(tmp_path, name, {"runs": [1, 2, 3]})

    proc = _run_cli(["emit-vex", "--osv-sarif", name], cwd=tmp_path)

    assert proc.returncode == 2, f"stderr={proc.stderr}"
    err = _norm(proc.stderr)
    assert name in err, err
    assert "\\[dev]" not in err, err


def test_wrote_line_names_the_output_file_it_actually_wrote(tmp_path: Path) -> None:
    """Sibling, opposite direction: this one was not escaped at all.

    ``--output "[dev]-out.json"`` was confirmed back as ``-out.json`` — Rich read
    ``[dev]`` as a style tag and deleted it, so the success line named a file that does
    not exist while the real one sat next to it.
    """

    _write(tmp_path, "osv.sarif.json", _OSV_SARIF)
    out_name = "[dev]-out.json"

    proc = _run_cli(["emit-vex", "--osv-sarif", "osv.sarif.json", "--output", out_name], cwd=tmp_path)

    assert proc.returncode == 0, f"stderr={proc.stderr}"
    assert (tmp_path / out_name).is_file()
    err = _norm(proc.stderr)
    assert out_name in err, err
    assert "\\[dev]" not in err, err


def test_control_waivers_warning_still_survives_rich_rendering(tmp_path: Path) -> None:
    """Control against "fix it by escaping nowhere".

    Dropping the remaining ``markup_safe`` at the print site would also remove the
    backslash — and delete ``[dev]`` from the rendered line, which is the original bug
    this escaping exists to prevent.
    """

    _write(tmp_path, "osv.sarif.json", _OSV_SARIF)

    proc = _run_cli(["emit-vex", "--osv-sarif", "osv.sarif.json", "--waivers", _BRACKET_NAME], cwd=tmp_path)

    assert "[dev]" in proc.stderr, proc.stderr
    assert "]waivers.yaml" in proc.stderr, proc.stderr
