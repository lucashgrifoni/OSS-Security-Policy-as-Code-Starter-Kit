"""Two documentation claims that the code did not support, held against the code.

Both were found by reading the docs next to a real run rather than next to each other.

`docs/release-hardening-workflow.md` told the reader that the report JSON "contains a
`results` array (one entry per control)". The key is `controls`. Anyone who followed that
sentence wrote a parser against a field that has never existed in the 2.0 contract.

`reports/README.md` said "The internal copy is what the CLI validates against". True for the
evidence schemas and the profile spec, false for the two output contracts: nothing in the kit
opens `reports/2.0.json` or `findings/1.0.json`. A reader took that sentence as an assurance
that a report coming out of the kit had been checked against the schema published beside it.

The second test is the one worth keeping. It asserts the *code* fact, not the sentence, so it
fires in both directions: if someone later wires report validation up, it fails and sends
them to the paragraph that currently says the wiring is absent.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

from tests.conftest import ROOT

_SRC = ROOT / "src" / "oss_policy_kit"

#: The schemas the kit ships. The split is the point: shipping is not loading.
_OUTPUT_CONTRACT_SCHEMAS = ("reports/2.0.json", "findings/1.0.json")
_LOADED_SCHEMAS = ("profile-spec.schema.json", "evidence-branch-protection.schema.json")


def _python_sources() -> list[Path]:
    """Every module of the kit except the packaged data it carries."""

    return [p for p in _SRC.rglob("*.py") if "data" not in p.relative_to(_SRC).parts]


def _referencing_modules(needle: str) -> list[str]:
    hits = []
    for path in _python_sources():
        if needle in path.read_text(encoding="utf-8", errors="replace"):
            hits.append(path.relative_to(ROOT).as_posix())
    return sorted(hits)


def test_the_report_key_the_docs_name_is_the_key_a_report_has(tmp_path: Path) -> None:
    """Check the documented field name against a report the kit just wrote.

    A string comparison against the word "controls" would pass on a document that named a
    field the product had renamed. This generates one and reads its keys.
    """

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "LICENSE").write_text("x\n", encoding="utf-8")
    out = tmp_path / "out"

    subprocess.run(
        [
            sys.executable,
            "-P",
            "-m",
            "oss_policy_kit",
            "evaluate",
            "--target",
            str(repo),
            "--profile",
            "github-level-1",
            "--output-dir",
            str(out),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    report = json.loads((out / "evaluation-report.json").read_text(encoding="utf-8"))

    prose = (ROOT / "docs" / "release-hardening-workflow.md").read_text(encoding="utf-8")
    named = set(re.findall(r"contains a `(\w+)` array", prose))

    assert named, "the sentence describing the report's array shape is gone or was reworded"
    for key in named:
        assert key in report, (
            f"docs/release-hardening-workflow.md says the report contains a `{key}` array, and a "
            f"report written by this build has no such key. Its top-level keys are: "
            f"{sorted(report)}"
        )


def test_nothing_loads_the_two_output_contract_schemas() -> None:
    """The code fact behind the corrected paragraph, asserted directly.

    This is deliberately not a check on the wording. If report validation is implemented
    later this test fails, which is the signal to go and delete the paragraph saying it is
    absent. A test on the sentence alone would stay green through that change and leave the
    docs claiming a gap that had been closed.
    """

    loaded = {name: _referencing_modules(name) for name in _OUTPUT_CONTRACT_SCHEMAS}
    offenders = {name: mods for name, mods in loaded.items() if mods}

    assert not offenders, (
        "Something now reads an output-contract schema:\n  "
        + "\n  ".join(f"{name} <- {', '.join(mods)}" for name, mods in offenders.items())
        + "\n\nThat is an improvement, not a defect. reports/README.md carries a paragraph "
        "saying these two are shipped and never loaded; update it and then this test."
    )


def test_the_schemas_that_are_loaded_still_are() -> None:
    """The other half of the claim, so the corrected paragraph is not half right either.

    The paragraph draws a line between the evidence and profile schemas, which are read and
    validated against, and the two output contracts, which are not. Without this, the line
    could become true by the wrong side moving.
    """

    for name in _LOADED_SCHEMAS:
        assert _referencing_modules(name), (
            f"{name} is no longer referenced by any module. reports/README.md says the "
            "evidence schemas and the profile spec are read at runtime; if that stopped "
            "being true, the paragraph needs rewriting."
        )


def test_the_readme_no_longer_makes_the_blanket_claim() -> None:
    """The sentence itself, kept short because the tests above carry the weight."""

    prose = (ROOT / "reports" / "README.md").read_text(encoding="utf-8")

    assert "The internal copy is what the CLI validates against" not in prose
    assert "nothing in the kit loads `reports/2.0.json` or `findings/1.0.json`" in prose
