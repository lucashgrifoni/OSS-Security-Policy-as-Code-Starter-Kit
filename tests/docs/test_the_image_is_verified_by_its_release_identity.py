"""The published image is verified by digest, against the identity of its own release run.

A tag in the GitHub Container Registry can be moved to another image, and GHCR has no
setting that makes it immutable. The verification commands used to take the tag as given
and accept any workflow in the repository as the signer, so a tag moved to an older image,
signed by this same workflow for an older release, verified as the version it claimed.

Measured on 10.0.25, the commands as written now: against the published digest, `cosign
verify` and `gh attestation verify` both pass with the `v10.0.25` identity and both fail
with `v10.0.24`. The certificate's subject is the workflow file at the release tag, read
from the published signature, so the identity below is the one the signer really carries.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from tests.conftest import ROOT

_DOCS = [ROOT / "docs" / "supply-chain-verification.md", ROOT / "docs" / "container-image.md"]
_WORKFLOW = ROOT / ".github" / "workflows" / "publish-container.yml"
_SIGNER_SUFFIX = "/OSS-Security-Policy-as-Code-Starter-Kit/.github/workflows/publish-container.yml@refs/tags/v<version>"


def _commands(path: Path, tool: str) -> list[str]:
    """Every shell command in *path*'s bash blocks that starts with *tool*, continuations joined."""

    text = path.read_text(encoding="utf-8")
    joined = [block.replace("\\\n", " ") for block in re.findall(r"```bash\n(.*?)```", text, re.S)]
    return [line.strip() for block in joined for line in block.splitlines() if line.strip().startswith(tool)]


def _identity(command: str, flag: str) -> str | None:
    match = re.search(rf"{flag}\s+'([^']+)'", command)
    return match.group(1) if match else None


@pytest.mark.parametrize("doc", _DOCS, ids=lambda p: p.name)
def test_cosign_is_pinned_to_the_release_identity_and_the_digest(doc: Path) -> None:
    commands = _commands(doc, "cosign verify")

    assert commands, f"{doc.name} no longer shows how to verify the image signature"
    for command in commands:
        assert "--certificate-identity-regexp" not in command, f"a regexp accepts any signer: {command}"
        identity = _identity(command, "--certificate-identity")
        assert identity and identity.endswith(_SIGNER_SUFFIX), f"identity not bound to the release tag: {command}"
        assert re.search(r"oss-policy-kit@<digest>", command), f"verifies a movable tag, not a digest: {command}"


@pytest.mark.parametrize("doc", _DOCS, ids=lambda p: p.name)
def test_the_attestation_is_pinned_to_the_release_identity_and_the_digest(doc: Path) -> None:
    commands = _commands(doc, "gh attestation verify oci://")

    assert commands, f"{doc.name} no longer shows how to verify the image attestation"
    for command in commands:
        identity = _identity(command, "--cert-identity")
        assert identity and identity.endswith(_SIGNER_SUFFIX), f"identity not bound to the release tag: {command}"
        assert "oss-policy-kit@<digest>" in command, f"verifies a movable tag, not a digest: {command}"


def _summary_step() -> dict:
    workflow = yaml.safe_load(_WORKFLOW.read_text(encoding="utf-8"))
    steps = [s for job in workflow["jobs"].values() for s in job.get("steps", [])]
    (step,) = [
        s for s in steps if "GITHUB_STEP_SUMMARY" in str(s.get("run", "")) and "cosign verify" in str(s.get("run", ""))
    ]
    return step


def test_the_publish_summary_prints_the_same_pinned_commands() -> None:
    """What the release run tells a reader to type has to hold to the same rule as the docs."""

    step = _summary_step()
    env, run = step["env"], step["run"]

    assert "@${{ steps.build.outputs.digest }}" in env["IMAGE_REF"], env["IMAGE_REF"]
    assert env["SIGNER"] == "${{ github.server_url }}/${{ github.workflow_ref }}", env["SIGNER"]
    assert "identity-regexp" not in run
    assert "--certificate-identity '${SIGNER}'" in run
    assert "--cert-identity '${SIGNER}'" in run
