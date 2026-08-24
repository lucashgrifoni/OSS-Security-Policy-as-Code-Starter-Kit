"""How a manifest is ENCODED must not change what it is understood to declare.

Every reader in this kit is supposed to reach text through `decode_source`, whose whole reason to
exist is the invariant *never read less than the previous release read*. Three manifest readers
never joined that funnel, and each drifted a different way:

    requirements.txt   read as plain UTF-8, so a leading BOM stuck to the first package name and
                       the first requirement vanished. `openai==1.2.0` on line one stopped being
                       a declared dependency, and `LLM-218A-PW-001` answered `not-applicable` --
                       "LLM controls do not apply to this repository" -- about a repository whose
                       first line declares an LLM SDK. Measured against `HEAD`: pass -> n/a.

    pyproject.toml     handed to `tomllib.load` as a BINARY handle, which decodes strictly. A
                       UTF-16 file raised `UnicodeDecodeError` from inside the evaluator, and
                       `_toml_document` suppressed `OSError` and `TOMLDecodeError` but not that.
                       Measured at the CLI boundary, which is the only place the harm is legible:

                           HEAD    exit 0, 13 controls, full report
                           before  exit 2, no report at all

                       One UTF-16 file anywhere in a target made the kit refuse to evaluate the
                       whole repository. That is worse than a wrong verdict: an adopter gating CI
                       on the exit code gets a usage error, and there is no report to look at.

    package.json       read as `utf-8-sig`, so it survived the BOM and not the wide encodings.
                       Left inconsistent, this is how the class comes back: one reader still
                       treats an encoding as an absent dependency.

A BOM is not a defect. YAML 1.2 requires UTF-16 and UTF-32 support, JSON parsers detect the width
from the first bytes (RFC 4627 s3), and every Windows editor writes a UTF-8 BOM on request. These
files are valid, `pip install -r` and `tomllib` and `npm` all read them, and the kit has to too.

Metamorphic rather than example-based on purpose: the property is that the ANSWER IS THE SAME in
every encoding the project claims to support. A case-by-case test would have been written for the
encoding whoever wrote it happened to think of, which is exactly how three readers ended up
disagreeing about the same repository.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from oss_policy_kit.application.evaluators import eval_llm_218a_pw_001
from oss_policy_kit.domain.models import ControlStatus

#: One repository, three ways of writing down the same fact: it depends on an LLM SDK.
_MANIFESTS: dict[str, str] = {
    "requirements.txt": "openai==1.2.0\nhttpx==0.27\n",
    "pyproject.toml": '[project]\nname = "a"\nversion = "1"\ndependencies = ["openai>=1.2"]\n',
    "package.json": json.dumps({"name": "a", "dependencies": {"openai": "^4"}}),
}

#: Every encoding `decode_source` documents support for. `utf-16-le` carries no BOM and is
#: deduced from its NUL stride, which is the case a BOM-only reader silently mis-handles.
_ENCODINGS = ("utf-8", "utf-8-sig", "utf-16", "utf-16-le", "utf-32")


def _repo(tmp_path: Path, filename: str, encoding: str) -> SimpleNamespace:
    (tmp_path / filename).write_bytes(_MANIFESTS[filename].encode(encoding))
    return SimpleNamespace(repo_root=tmp_path)


@pytest.mark.parametrize("filename", sorted(_MANIFESTS))
@pytest.mark.parametrize("encoding", _ENCODINGS)
def test_the_same_declaration_reads_the_same_in_every_encoding(tmp_path: Path, filename: str, encoding: str) -> None:
    """`not-applicable` is a positive claim, and an encoding is never evidence for it."""

    outcome = eval_llm_218a_pw_001(_repo(tmp_path, filename, encoding))

    assert outcome.status is ControlStatus.PASS, (
        f"{filename} written as {encoding} declares an LLM SDK on its first line and the control "
        f"answered {outcome.status.value}. Removing a false positive must not remove a true "
        f"finding, and how a file is encoded is not a fact about what it declares: {outcome.reason}"
    )


def test_a_wide_manifest_does_not_abort_the_whole_evaluation(tmp_path: Path) -> None:
    """The process-level half, which no in-process assertion can see.

    The failure this pins was not a wrong verdict -- it was `exit 2` and no report, from a target
    the previous release evaluated to completion. Run as a subprocess deliberately: the harm is
    the exit code and the missing artifact, and both only exist at the CLI boundary.
    """

    target = tmp_path / "target"
    target.mkdir()
    (target / "pyproject.toml").write_bytes(_MANIFESTS["pyproject.toml"].encode("utf-16"))
    out = tmp_path / "out"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "oss_policy_kit",
            "evaluate",
            "--target",
            str(target),
            "--profile",
            "appsec-llm-ssdf-218a-1",
            "--output-dir",
            str(out),
        ],
        capture_output=True,
        text=True,
        timeout=300,
    )

    assert result.returncode == 0, (
        "one UTF-16 manifest inside the target made the kit refuse to evaluate the repository at "
        f"all (exit {result.returncode}). `HEAD` evaluated the same target to completion.\n"
        f"stdout: {result.stdout[-400:]}\nstderr: {result.stderr[-400:]}"
    )
    assert (out / "evaluation-report.json").is_file(), (
        "the run reported success and produced no report, which is the same outcome as the abort "
        "for anyone consuming the artifact"
    )
