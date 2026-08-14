"""A comment cannot change what a file does, so it must not change any verdict.

This is the fence for a class that came back three times. Each earlier round fixed the sites
someone had listed, and the next round found the class alive in a file nobody had listed:
first six controls in ``workflow_parser``, then GH-PROV-023 and CI-PIN-008, then -- once a
derived sweep was finally run instead of a list -- eight controls across FIVE platforms at
once, including two that had never been looked at.

So this test does not name controls. It takes a baseline repository per platform, adds one
comment line carrying every signal phrase the kit looks for, and asserts that not a single
control changed its verdict. A ninth offender, in a file nobody has thought of, fails here on
the day it is written.

The two directions matter equally and both were real:

- **granting credit.** GL-PIPE-012 answered "pipeline(s) document artifact retention /
  signing posture" for a pipeline whose only mention of `cosign` was a note saying it had
  not been set up.
- **withholding it.** CI-DANGER-007 failed the gate for a workflow whose comment said the
  team deliberately does *not* use `pull_request_target`, and CONT-RUNTIME-003 failed a
  Dockerfile over a commented-out `curl | sh` shown as an example of what not to do.

One thing this test deliberately does NOT assert: that comments are ignored everywhere. A
credential pasted into a comment is still a leaked credential, so the secret detectors in
``aws_ci_parser`` read the file exactly as written. The rule is about capability -- does this
pipeline DO the thing -- not about content.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from oss_policy_kit.application.engine import evaluate_repository
from oss_policy_kit.application.loader import bundled_kit_root, load_catalog, load_profile_by_id

_GH_WORKFLOW = (
    "name: ci\n"
    "on:\n"
    "  push:\n"
    "    branches: [main]\n"
    "permissions:\n"
    "  contents: read\n"
    "jobs:\n"
    "  build:\n"
    "    runs-on: ubuntu-latest\n"
    "    steps:\n"
    "      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n"
    "      - run: make build\n"
)
_GITLAB_CI = "stages: [build]\nbuild:\n  stage: build\n  image: alpine:3.19\n  script:\n    - make build\n"
_AZURE = (
    "trigger:\n  branches:\n    include: [main]\n"
    "pool:\n  vmImage: ubuntu-latest\n"
    "steps:\n  - script: make build\n    displayName: Build\n"
)
_BUILDSPEC = "version: 0.2\nphases:\n  build:\n    commands:\n      - make build\n"
_DOCKERFILE = (
    "FROM python:3.12-slim@sha256:1111111111111111111111111111111111111111111111111111111111111111\n"
    "RUN useradd -m app\n"
    "USER app\n"
    'CMD ["python", "-c", "print(1)"]\n'
)

#: Every phrase the kit treats as a signal, in one line. Adding a phrase here when a new
#: signal is introduced is the cheapest way to keep this fence honest.
_SIGNALS = (
    "pull_request_target runs-on: self-hosted id-token: write merge queue merge_group "
    "dependency-review-action codeql github/codeql-action slsa provenance attestation "
    "cosign sign harden-runner egress-policy: block trivy semgrep bandit gitleaks "
    "oidc trusted publishing sbom cyclonedx spdx syft grype expire_in: artifacts: "
    "USER root --privileged sudo curl | sh secrets: inherit "
    "twine upload docker push kubectl apply terraform apply"
)

#: (label, file the platform reads, baseline body, profiles that exercise it)
_PLATFORMS: tuple[tuple[str, str, str, tuple[str, ...]], ...] = (
    ("github", ".github/workflows/ci.yml", _GH_WORKFLOW, ("github-level-3", "cis-supply-chain-1")),
    ("gitlab", ".gitlab-ci.yml", _GITLAB_CI, ("gitlab-level-3",)),
    ("azure", "azure-pipelines.yml", _AZURE, ("azure-level-3",)),
    # `aws-release-hardening-3`, not `aws-level-3`: the four controls that read the buildspec
    # capability signals (AWS-SEC-039/SCA-040/SBOM-041/PROV-043) are not in level 3, so the
    # fence was blind to the AWS strip until mutation testing showed the revert surviving.
    ("aws", "buildspec.yml", _BUILDSPEC, ("aws-release-hardening-3",)),
    ("docker", "Dockerfile", _DOCKERFILE, ("container-baseline-1",)),
)

_CASES = [(label, rel, body, profile) for label, rel, body, profiles in _PLATFORMS for profile in profiles]


def _verdicts(repo: Path, profile_id: str) -> dict[str, str]:
    root = bundled_kit_root()
    result = evaluate_repository(
        repo_root=repo,
        profile=load_profile_by_id(root, profile_id),
        catalog=load_catalog(root / "controls" / "catalog.yaml"),
        waiver_outcome=None,
        scorecard=None,
    )
    return {r.control_id: r.status.value for r in result.results}


def _repo(tmp_path: Path, name: str, rel: str, body: str) -> Path:
    repo = tmp_path / name
    target = repo / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(body, encoding="utf-8")
    (repo / "README.md").write_text("# demo\n", encoding="utf-8")
    return repo


@pytest.mark.parametrize(("label", "rel", "body", "profile"), _CASES, ids=[f"{c[0]}-{c[3]}" for c in _CASES])
def test_adding_a_comment_changes_no_verdict(label: str, rel: str, body: str, profile: str, tmp_path: Path) -> None:
    plain = _verdicts(_repo(tmp_path, f"{label}-plain", rel, body), profile)
    annotated = _verdicts(_repo(tmp_path, f"{label}-comment", rel, f"# {_SIGNALS}\n{body}"), profile)

    assert plain, f"{label}/{profile} produced no verdicts -- the fixture or profile is wrong"

    flips = {cid: (plain.get(cid), annotated.get(cid)) for cid in plain if plain.get(cid) != annotated.get(cid)}
    assert not flips, (
        f"{label}/{profile}: a comment changed these verdicts, so a control is reading file text "
        f"instead of what the file does: {flips}"
    )


def test_the_fence_would_notice_a_regression(tmp_path: Path) -> None:
    """A sweep that compares nothing passes for the wrong reason.

    Proves the harness can see a flip at all: a REAL `pull_request_target` trigger -- not a
    comment mentioning it -- must move at least one verdict. Without this, the test above
    would keep passing if `_verdicts` silently returned the same thing twice.
    """

    safe = _verdicts(_repo(tmp_path, "safe", ".github/workflows/ci.yml", _GH_WORKFLOW), "github-level-3")
    risky_body = _GH_WORKFLOW.replace("  push:\n    branches: [main]\n", "  pull_request_target:\n")
    risky = _verdicts(_repo(tmp_path, "risky", ".github/workflows/ci.yml", risky_body), "github-level-3")

    assert safe != risky, "a real pull_request_target trigger must change something, or this fence is blind"
