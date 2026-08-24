"""An image CI builds has to be scanned, not just started.

`security-ci-cd.yml` runs Trivy four times. Three are `scan-type: fs` against the source
tree; one is `scan-type: image` against the *base* image pinned in the Dockerfile. Neither
kind can see what the build adds on top of that base -- the venv, the `[all]` dependency
closure, and the pip the builder upgrades into it. The `container-build` job did build the
image, but only ran `--version` and checked the uid.

Measured on `ghcr.io/lucashgrifoni/oss-policy-kit:10.0.15`, which is also the `latest` tag
adopters pull, scanned straight from the registry:

    32 fixable vulnerabilities: 2 CRITICAL, 9 HIGH (libgnutls30, krb5, openssl, ...)
    pip 25.0.1  -- the base image's own pip, which the Dockerfile's upgrade never touches
    pip 26.1.1  -- the venv's pip, one patch below the fix for CVE-2026-8643

Most of the OS findings came from a base digest refreshed one day after that release, so a
build from the current Dockerfile no longer carries them. That is the point: nothing in CI
would have reported it either way. Reproducing the `sca-trivy` job locally returns zero
findings and never mentions pip at all, because a `pip==` pin inside a RUN string is not a
manifest a filesystem scan can read.

Limitation this guard accepts: it holds the CI build -- the one loaded locally and thrown
away -- rather than the multi-arch image `publish-container.yml` pushes straight to GHCR.
They come from the same Dockerfile, so the CI build is a proxy for the published one, and
it drifts only when the base digest moves between the two runs.
"""

from __future__ import annotations

import pytest
import yaml

from tests.conftest import ROOT

_WORKFLOWS = ROOT / ".github" / "workflows"

_BUILD_ACTION = "docker/build-push-action"
_SCAN_ACTION = "aquasecurity/trivy-action"


def _step_uses(step: dict, action: str) -> bool:
    return str(step.get("uses", "")).split("@")[0] == action


def _locally_built_images() -> list[tuple[str, str, str, list[dict]]]:
    """(workflow, job name, image ref, steps) for every image built into the local daemon.

    `load: true` is what makes the image addressable as a plain `name:tag` afterwards.
    A buildx build that only pushes has no local ref for a scanner to point at.
    """

    found: list[tuple[str, str, str, list[dict]]] = []
    for path in sorted(_WORKFLOWS.glob("*.yml")):
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        for job_id, job in (document.get("jobs") or {}).items():
            steps = job.get("steps") or []
            for step in steps:
                if not _step_uses(step, _BUILD_ACTION):
                    continue
                params = step.get("with") or {}
                if str(params.get("load", "")).lower() != "true":
                    continue
                tags = [t.strip() for t in str(params.get("tags", "")).splitlines() if t.strip()]
                if not tags:
                    continue
                found.append((path.name, str(job_id), tags[0], steps))
    return found


def _image_scans(steps: list[dict], ref: str) -> list[dict]:
    """Trivy steps that scan exactly `ref` as an image."""

    scans = []
    for step in steps:
        if not _step_uses(step, _SCAN_ACTION):
            continue
        params = step.get("with") or {}
        if str(params.get("scan-type", "")) != "image":
            continue
        if str(params.get("image-ref", "")).strip() != ref:
            continue
        scans.append(params)
    return scans


def test_ci_builds_an_image_locally_at_all() -> None:
    """Without this, every assertion below would hold over an empty list."""

    assert _locally_built_images(), (
        "no workflow builds a container image into the local daemon any more. The guards "
        "below would then pass by having nothing to check -- exactly the failure mode that "
        "let 32 fixable vulnerabilities reach the `latest` tag unreported."
    )


@pytest.mark.parametrize(
    "workflow,job,ref,steps", _locally_built_images(), ids=lambda v: v if isinstance(v, str) else ""
)
def test_a_locally_built_image_is_scanned_for_vulnerabilities(
    workflow: str, job: str, ref: str, steps: list[dict]
) -> None:
    assert _image_scans(steps, ref), (
        f"{workflow}: job `{job}` builds `{ref}` and never scans it. Running `--version` "
        "proves the entrypoint works, not that the layers are free of known-vulnerable "
        "packages -- and no other job can cover it, because the base-image scan sees only "
        "the base and the fs scans see only the source tree."
    )


@pytest.mark.parametrize(
    "workflow,job,ref,steps", _locally_built_images(), ids=lambda v: v if isinstance(v, str) else ""
)
def test_at_least_one_of_those_scans_can_actually_fail_the_build(
    workflow: str, job: str, ref: str, steps: list[dict]
) -> None:
    """A scan that always exits zero reports; it does not gate.

    `base-image-trivy` is deliberately `exit-code: "0"` and that is documented there: a
    rolling upstream base would turn master red on unrelated pull requests. The image built
    from this repository's own Dockerfile is different -- what it contains is this
    repository's decision, so a finding in it is always actionable here.
    """

    gating = [s for s in _image_scans(steps, ref) if str(s.get("exit-code", "0")).strip() == "1"]
    assert gating, (
        f"{workflow}: every image scan of `{ref}` in job `{job}` exits zero, so a "
        "CRITICAL vulnerability in the image would be printed and then ignored. At least "
        "one scan of the built image has to fail the job."
    )
