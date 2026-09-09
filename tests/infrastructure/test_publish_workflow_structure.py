"""Structural regression tests for .github/workflows/publish-pypi.yml.

Guards against SBOM artefacts contaminating dist/ (which causes twine check failures).
"""

from __future__ import annotations

import re
import shlex
from pathlib import Path

import yaml

_WORKFLOW_PATH = Path(__file__).parents[2] / ".github" / "workflows" / "publish-pypi.yml"
_CONTAINER_WORKFLOW_PATH = Path(__file__).parents[2] / ".github" / "workflows" / "publish-container.yml"
_DOCKERFILE_PATH = Path(__file__).parents[2] / "Dockerfile"
_DOCKERIGNORE_PATH = Path(__file__).parents[2] / ".dockerignore"
#: Matched on identity, deliberately not on the pinned SHA. This test owns "every publish
#: job audits egress before it touches anything"; it does not own "the action is pinned".
#: Pinning is enforced by the kit's own ``CI-PIN-008`` control, which the Quality job runs
#: against this repository on every push -- a stronger check than a string here, because it
#: covers every action rather than this one.
#:
#: The SHA used to be baked in, which made every legitimate harden-runner bump fail this
#: assertion: Dependabot #162 (2.20.0 -> 2.20.1) is what surfaced it. A test that blocks the
#: upgrade it is supposed to protect is worse than no test.
_HARDEN_RUNNER_ACTION = "step-security/harden-runner@"


def _load_workflow() -> dict:
    return yaml.safe_load(_WORKFLOW_PATH.read_text(encoding="utf-8"))


def _load_container_workflow() -> dict:
    return yaml.safe_load(_CONTAINER_WORKFLOW_PATH.read_text(encoding="utf-8"))


def _build_steps(workflow: dict) -> list[dict]:
    return workflow["jobs"]["build"]["steps"]


def _dockerfile_directives() -> list[str]:
    """The Dockerfile's instructions with comments removed and continuations joined.

    Comments are dropped before anything reads the text. Stripping them is the whole
    point: this module previously asserted on a string that only existed in a comment.
    """

    text = _DOCKERFILE_PATH.read_text(encoding="utf-8")
    text = re.sub(r"\\\n\s*", " ", text)
    return [line.strip() for line in text.split("\n") if line.strip() and not line.lstrip().startswith("#")]


def _pip_command_arguments(directive: str) -> list[str]:
    """Non-flag arguments of every `pip install` / `pip wheel` in one directive.

    Returns arguments, not raw text, so that the distribution name appearing in a LABEL
    or in `ENTRYPOINT ["python", "-m", "oss_policy_kit"]` cannot be mistaken for an
    install target.
    """

    if not directive.startswith("RUN "):
        return []
    arguments: list[str] = []
    for fragment in re.split(r"&&|\|\||;", directive[4:]):
        try:
            tokens = shlex.split(fragment.strip())
        except ValueError:  # pragma: no cover - unbalanced quotes are not a shape we ship
            continue
        for i, token in enumerate(tokens):
            if Path(token).name in ("pip", "pip3") and i + 1 < len(tokens) and tokens[i + 1] in ("install", "wheel"):
                arguments.extend(t for t in tokens[i + 2 :] if not t.startswith("-"))
                break
            if (
                token == "-m"
                and i + 2 < len(tokens)
                and tokens[i + 1] == "pip"
                and tokens[i + 2] in ("install", "wheel")
            ):
                arguments.extend(t for t in tokens[i + 3 :] if not t.startswith("-"))
                break
    return arguments


def test_sbom_output_path_is_not_inside_dist() -> None:
    """SBOM must not be written to dist/ to avoid polluting wheel/sdist artifacts."""
    steps = _build_steps(_load_workflow())
    sbom_steps = [s for s in steps if "cyclonedx" in s.get("run", "").lower()]
    assert sbom_steps, "Expected at least one SBOM generation step"
    for step in sbom_steps:
        run_text: str = step["run"]
        assert "dist/sbom" not in run_text, "SBOM must not be written to dist/ — use artifacts/ or a separate path"
        assert "-o dist/" not in run_text, "SBOM output flag must not target dist/"


def test_dist_upload_artifact_does_not_include_sbom_path() -> None:
    """The 'dist' upload-artifact step must only cover the dist/ folder (no SBOM mixed in)."""
    steps = _build_steps(_load_workflow())
    upload_steps = [s for s in steps if isinstance(s.get("uses"), str) and "upload-artifact" in s["uses"]]
    dist_uploads = [s for s in upload_steps if s.get("with", {}).get("name") == "dist"]
    assert dist_uploads, "Expected an upload-artifact step named 'dist'"
    for step in dist_uploads:
        path_value: str = step["with"].get("path", "")
        assert "sbom" not in path_value.lower(), (
            "The dist artifact must not include SBOM files — keep them in a separate artifact"
        )


def test_sbom_has_dedicated_upload_artifact_step() -> None:
    """SBOM must be uploaded as its own artifact, separate from dist."""
    steps = _build_steps(_load_workflow())
    upload_steps = [s for s in steps if isinstance(s.get("uses"), str) and "upload-artifact" in s["uses"]]
    sbom_uploads = [s for s in upload_steps if s.get("with", {}).get("name") == "sbom"]
    assert sbom_uploads, "Expected a dedicated upload-artifact step named 'sbom' for the SBOM file"


def test_twine_check_step_precedes_sbom_generation() -> None:
    """twine check must run before SBOM generation so dist/ is clean when verified."""
    steps = _build_steps(_load_workflow())
    names_and_runs = [(i, s) for i, s in enumerate(steps)]

    def _is_twine_verify_step(step: dict) -> bool:
        run = str(step.get("run", ""))
        return "twine check" in run or "twine_check_dist" in run

    twine_idx = next((i for i, s in names_and_runs if _is_twine_verify_step(s)), None)
    sbom_idx = next(
        (i for i, s in names_and_runs if "cyclonedx" in s.get("run", "").lower()),
        None,
    )
    assert twine_idx is not None, "twine check step not found"
    assert sbom_idx is not None, "SBOM generation step not found"
    assert twine_idx < sbom_idx, f"twine check (step {twine_idx}) must come before SBOM generation (step {sbom_idx})"


def test_pypi_distributions_are_attested_before_upload() -> None:
    """PyPI dist artifacts should receive GitHub Artifact Attestations before publish jobs consume them."""
    workflow = _load_workflow()
    build = workflow["jobs"]["build"]
    permissions = build.get("permissions", {})
    assert permissions.get("id-token") == "write"
    assert permissions.get("attestations") == "write"

    steps = _build_steps(workflow)
    attest_steps = [s for s in steps if "attest-build-provenance" in str(s.get("uses", ""))]
    assert attest_steps, "Expected actions/attest-build-provenance for PyPI distributions"
    assert attest_steps[0]["with"]["subject-path"] == "dist/*"


def test_pypi_publish_jobs_enable_registry_attestations() -> None:
    """PyPI/TestPyPI Trusted Publishing should upload PEP 740 attestations."""
    workflow = _load_workflow()
    for job_name in ("publish-testpypi", "publish-pypi"):
        steps = workflow["jobs"][job_name]["steps"]
        publish_steps = [s for s in steps if "gh-action-pypi-publish" in str(s.get("uses", ""))]
        assert publish_steps, f"Expected PyPI publish step in {job_name}"
        assert publish_steps[0].get("with", {}).get("attestations") is True


def test_container_build_installs_from_source_not_pypi() -> None:
    """Container release builds must not race PyPI package propagation.

    This asserted `'".[all]"' in dockerfile` until 2026-09-02. The install stopped using
    `.[all]` in 6964a78, and the only thing keeping the assertion true for the thirteen
    commits after it was the string surviving inside a COMMENT that discussed the old
    install. A test whose subject is "installs from source" was being satisfied by prose
    about installing from source.

    So the Dockerfile is stripped of comments first, and the assertions are about the
    mechanism rather than about one spelling of it: the tree is copied in, the kit is
    built from the build context, and nothing installs the published package from an
    index. That survives a change of install style -- which is what happened -- and still
    fails if the image starts taking the kit from PyPI.
    """
    directives = _dockerfile_directives()
    dockerignore = _DOCKERIGNORE_PATH.read_text(encoding="utf-8").splitlines()

    assert any(d.startswith("COPY src") for d in directives), (
        "the Dockerfile no longer copies src/ into the build, so whatever it installs is "
        f"not this tree. Directives found: {directives}"
    )

    pip_args = [arg for d in directives for arg in _pip_command_arguments(d)]
    assert "." in pip_args, (
        "no pip command takes the build context `.` as its target, so the kit is not being "
        f"built from the copied tree. pip arguments found: {pip_args}"
    )

    # The distribution name, in any form pip would accept as an index lookup. Checked
    # against pip ARGUMENTS only: the name legitimately appears in LABEL metadata and in
    # `ENTRYPOINT ["python", "-m", "oss_policy_kit"]`, and matching raw text would either
    # fire on those or force this test to special-case them.
    for arg in pip_args:
        assert not re.match(r"^oss[-_]policy[-_]kit($|[\[=<>~!])", arg), (
            f"the image installs the published package (`{arg}`) instead of the checked-out "
            "tree, which races PyPI propagation on a release tag."
        )

    assert "src/" not in dockerignore
    assert "pyproject.toml" not in dockerignore
    assert "README.md" not in dockerignore
    assert "LICENSE" not in dockerignore
    assert "NOTICE" not in dockerignore


def test_release_workflows_use_non_canceling_concurrency() -> None:
    """Release workflows should serialize per ref without cancelling in-flight publishes."""
    workflows = {
        "publish-pypi": _load_workflow(),
        "publish-container": _load_container_workflow(),
    }
    for name, workflow in workflows.items():
        concurrency = workflow.get("concurrency", {})
        assert concurrency.get("group") == f"{name}-${{{{ github.ref }}}}"
        assert concurrency.get("cancel-in-progress") is False


def test_publish_workflows_start_each_job_with_harden_runner_audit() -> None:
    """Publish jobs should audit egress before any checkout, download, build, or upload step."""
    workflows = {
        "publish-pypi": _load_workflow(),
        "publish-container": _load_container_workflow(),
    }
    for workflow_name, workflow in workflows.items():
        for job_name, job in workflow["jobs"].items():
            first_step = job["steps"][0]
            assert first_step["uses"].startswith(_HARDEN_RUNNER_ACTION), (
                f"{workflow_name}:{job_name} must start with the pinned harden-runner action"
            )
            assert first_step.get("with", {}).get("egress-policy") == "audit", (
                f"{workflow_name}:{job_name} should remain in audit until publish egress is reviewed"
            )


def test_build_pins_source_date_epoch_to_the_commit_before_building() -> None:
    """Wheel timestamps must come from the commit, not the runner's clock.

    Rebuilding the published v10.0.20 wheel reproduced all 231 entries byte for byte and
    still produced a different file, because every ZIP timestamp in it was the runner's
    wall clock at checkout. An adopter cannot replay that clock, so the artifact was not
    independently verifiable by hash. Reading the epoch from `git log -1` makes it a
    property of the commit being built.
    """

    steps = _build_steps(_load_workflow())

    def _sets_source_date_epoch(step: dict) -> bool:
        run = str(step.get("run", ""))
        return "SOURCE_DATE_EPOCH=" in run and "GITHUB_ENV" in run

    epoch_index = next((i for i, s in enumerate(steps) if _sets_source_date_epoch(s)), None)
    assert epoch_index is not None, "no build step writes SOURCE_DATE_EPOCH to GITHUB_ENV"

    epoch_run = str(steps[epoch_index]["run"])
    assert "git log" in epoch_run, (
        "SOURCE_DATE_EPOCH must be derived from the commit; a literal or `date` call would "
        "drift between the tag and the artifact"
    )

    build_index = next(
        (i for i, s in enumerate(steps) if "python -m build" in str(s.get("run", ""))),
        None,
    )
    assert build_index is not None, "no `python -m build` step found"
    assert epoch_index < build_index, (
        f"SOURCE_DATE_EPOCH is set at step {epoch_index}, after the build at step {build_index}"
    )
