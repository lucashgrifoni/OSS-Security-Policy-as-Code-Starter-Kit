"""No `${{ }}` may be substituted into the text of a `run:` script.

GitHub Actions expands `${{ }}` **before** the shell sees the line, so the expanded value
becomes part of the program rather than an argument to it. A value carrying a quote, a
newline or a `$(...)` therefore runs as code. `zizmor/template-injection` flags the shape;
nine alerts were open against this repository's own publish workflows when this guard was
written, including five in the step that writes the container publish summary.

None of the flagged values was attacker-controlled: they came from earlier steps of the same
workflow, from workflow-level `env:` constants, and from `github.repository`. The shape is
fixed anyway, for a reason specific to this repository — it ships a kit that tells adopters
not to write it, and `templates/workflows/` are files an adopter copies. A starter kit that
teaches CI hardening cannot carry the pattern in its own release machinery.

The fix everywhere is the same: bind the value in the step's `env:` and read it as `$VAR`,
so the shell receives data instead of program text.

**This guard is absolute rather than an allowlist.** An earlier draft exempted
`${{ env.X }}` for workflow-level constants, which is where the two surviving occurrences
lived, and the exemption would have let the next one in unnoticed. Zero is a line a reviewer
can hold; "zero except the safe ones" is a judgement call repeated at every pull request.

Covers the repository's own workflows and both copies of the workflow templates the kit
ships, because a template is a file someone else will run.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

_REPO_ROOT = Path(__file__).resolve().parents[1]

#: Every tree holding workflow YAML this project is responsible for. The second and third
#: are shipped to adopters: `templates/workflows/` is browsed on GitHub and
#: `src/.../data/templates/workflows/` is what `init --with-workflow` writes.
_WORKFLOW_ROOTS = (
    Path(".github/workflows"),
    Path("templates/workflows"),
    Path("src/oss_policy_kit/data/templates/workflows"),
)

_EXPANSION = re.compile(r"\$\{\{[^}]*\}\}")


def _workflow_files() -> list[Path]:
    found: list[Path] = []
    for root in _WORKFLOW_ROOTS:
        directory = _REPO_ROOT / root
        if not directory.is_dir():
            continue
        found.extend(sorted(directory.glob("*.yml")))
        found.extend(sorted(directory.glob("*.yaml")))
    return found


def _run_scripts(document: Any) -> list[tuple[str, str, str]]:
    """Yield (job id, step name, run text) for every step that has a `run:`."""

    out: list[tuple[str, str, str]] = []
    jobs = (document or {}).get("jobs")
    if not isinstance(jobs, dict):
        return out
    for job_id, job in jobs.items():
        if not isinstance(job, dict):
            continue
        for step in job.get("steps") or []:
            if not isinstance(step, dict):
                continue
            script = step.get("run")
            if isinstance(script, str) and script:
                out.append((str(job_id), str(step.get("name") or "<unnamed>"), script))
    return out


def test_the_workflow_roots_are_where_this_guard_thinks_they_are() -> None:
    """A guard that silently scans nothing is worse than no guard.

    If a directory is renamed, the assertions below all pass over an empty list. This pins
    the denominator so that failure is loud.
    """

    files = _workflow_files()
    assert len(files) >= 15, f"expected the three workflow roots to hold files, found {len(files)}"
    for root in _WORKFLOW_ROOTS:
        assert (_REPO_ROOT / root).is_dir(), f"workflow root disappeared: {root}"


@pytest.mark.parametrize("path", _workflow_files(), ids=lambda p: f"{p.parent.name}/{p.name}")
def test_no_template_expansion_is_substituted_into_a_run_script(path: Path) -> None:
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    offenders: list[str] = []
    for job_id, step_name, script in _run_scripts(document):
        for found in _EXPANSION.findall(script):
            offenders.append(f"{path.relative_to(_REPO_ROOT).as_posix()} :: {job_id} :: {step_name} :: {found}")

    assert not offenders, (
        "A `${{ }}` expansion is substituted into the text of a run script, so its value is "
        "executed rather than passed as data. Bind it in the step's `env:` and read `$VAR` "
        "instead:\n  " + "\n  ".join(offenders)
    )


def test_the_detector_sees_an_expansion_that_is_actually_there() -> None:
    """The assertion above is only worth its runtime if the regex matches the real shape.

    Written against the exact line this guard was created for, taken verbatim from
    `publish-container.yml` before the fix.
    """

    document = yaml.safe_load(
        "jobs:\n"
        "  publish:\n"
        "    steps:\n"
        "      - name: Summary\n"
        "        run: |\n"
        '          echo "- **Digest**: ${{ steps.build.outputs.digest }}"\n'
    )
    scripts = _run_scripts(document)
    assert len(scripts) == 1
    assert _EXPANSION.findall(scripts[0][2]) == ["${{ steps.build.outputs.digest }}"]


def test_the_detector_does_not_fire_on_a_shell_variable() -> None:
    """`${VAR}` is the form this guard is steering people towards; it must not be flagged."""

    document = yaml.safe_load(
        "jobs:\n"
        "  publish:\n"
        "    steps:\n"
        "      - name: Summary\n"
        "        env:\n"
        "          IMAGE_DIGEST: placeholder\n"
        "        run: |\n"
        '          echo "- **Digest**: ${IMAGE_DIGEST}"\n'
    )
    assert _EXPANSION.findall(_run_scripts(document)[0][2]) == []
