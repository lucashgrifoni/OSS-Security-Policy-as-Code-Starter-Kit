"""Six controls whose passing verdict was never exercised, and the near miss beside each.

A control asserted in one direction only is a control nobody has checked. These are the halves
that were missing, and each is paired with the case that must *not* produce the same verdict --
because the failure that costs an adopter is never the loud one. A build-instructions check that
matches any heading passes every repository; an EPSS gate that reads an unenriched scan as clean
tells someone their dependencies are fine when nothing measured them.

The one worth reading twice is `GH-PROV-023`. Provenance only applies to a repository that
actually releases something, and release intent is inferred from what the workflows do rather
than what they are called -- so a repository that publishes on push-to-main is in scope even
though no workflow says "release" anywhere.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from oss_policy_kit.application import evaluators_containers as containers
from oss_policy_kit.application.evaluators import github, governance, supply_chain
from oss_policy_kit.application.evaluators._shared import (
    EvalContext,
    _any_github_workflow_suggests_release_or_deploy,
)
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis

_OSV_SARIF = ".oss-policy-kit/evidence/sast/osv-scanner.sarif.json"


def _ctx(root: Path, *workflows: Path) -> EvalContext:
    return EvalContext(
        repo_root=root,
        profile_id="github-level-3",
        workflows=WorkflowAnalysis(workflow_paths=list(workflows)),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
    )


def _write(root: Path, rel: str, body: str = "x") -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path


# --------------------------------------------------------------------------- #
# Release intent inferred from what a workflow does
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("label", "body"),
    [
        ("an on: release trigger", "on:\n  release:\n    types: [published]\njobs: {}\n"),
        (
            "publishing on push to main",
            "on:\n  push:\n    branches: [main]\njobs:\n  b:\n    steps:\n      - run: npm publish\n",
        ),
        (
            "a gh release call on master",
            "on:\n  push:\n    branches: [master]\njobs:\n  b:\n    steps:\n      - run: gh release create\n",
        ),
        (
            "the pypi publish action",
            "on:\n  push:\n    branches: [main]\njobs:\n"
            "  b:\n    steps:\n      - uses: pypa/gh-action-pypi-publish@v1\n",
        ),
    ],
)
def test_a_workflow_that_ships_something_carries_release_intent(label: str, body: str, tmp_path: Path) -> None:
    wf = _write(tmp_path, ".github/workflows/ci.yml", body)
    assert _any_github_workflow_suggests_release_or_deploy(_ctx(tmp_path, wf)) is True, label


@pytest.mark.parametrize(
    ("label", "body"),
    [
        ("tests on pull requests", "on:\n  pull_request:\njobs:\n  t:\n    steps:\n      - run: pytest\n"),
        (
            "push to main that only builds",
            "on:\n  push:\n    branches: [main]\njobs:\n  b:\n    steps:\n      - run: make\n",
        ),
        (
            "a publish step on a feature branch",
            "on:\n  push:\n    branches: [dev]\njobs:\n  b:\n    steps:\n      - run: npm publish\n",
        ),
    ],
)
def test_a_workflow_that_ships_nothing_does_not(label: str, body: str, tmp_path: Path) -> None:
    """Both halves are required: shipping, and shipping from the branch that ships."""

    wf = _write(tmp_path, ".github/workflows/ci.yml", body)
    assert _any_github_workflow_suggests_release_or_deploy(_ctx(tmp_path, wf)) is False, label


def test_provenance_applies_to_a_repository_that_publishes_without_saying_release(tmp_path: Path) -> None:
    """The control is in scope here; without the inference it would report not-applicable."""

    wf = _write(
        tmp_path,
        ".github/workflows/ci.yml",
        "on:\n  push:\n    branches: [main]\njobs:\n  b:\n    steps:\n      - run: npm publish\n",
    )
    assert github.eval_gh_prov_023(_ctx(tmp_path, wf)).status is not ControlStatus.NOT_APPLICABLE


# --------------------------------------------------------------------------- #
# GOV-BUILD-072 -- can somebody build this from source
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("name", ["Makefile", "justfile", "noxfile.py", "tox.ini", "INSTALL.md", "build.sh"])
def test_a_build_entrypoint_passes_the_control(name: str, tmp_path: Path) -> None:
    _write(tmp_path, name, "all:\n\techo build\n")
    assert governance.eval_gov_build_072(_ctx(tmp_path)).status is ControlStatus.PASS


@pytest.mark.parametrize("heading", ["## Building", "# Installation", "### Development setup", "## How to build"])
def test_a_documented_build_section_passes_the_control(heading: str, tmp_path: Path) -> None:
    _write(tmp_path, "README.md", f"# App\n\n{heading}\n\nRun make.\n")
    assert governance.eval_gov_build_072(_ctx(tmp_path)).status is ControlStatus.PASS


@pytest.mark.parametrize(
    ("label", "body"),
    [
        ("a readme with no build section", "# App\n\n## Usage\n\nRun it.\n"),
        ("the word without a heading", "# App\n\nYou can build it somehow.\n"),
    ],
)
def test_a_repository_that_documents_no_build_asks_for_review(label: str, body: str, tmp_path: Path) -> None:
    """Matching any mention of the word would pass every repository with a README."""

    _write(tmp_path, "README.md", body)
    assert governance.eval_gov_build_072(_ctx(tmp_path)).status is ControlStatus.MANUAL_REVIEW_REQUIRED, label


# --------------------------------------------------------------------------- #
# GOV-DISC-065 -- an inbound disclosure SLA that is actually written down
# --------------------------------------------------------------------------- #


def _disclosure(root: Path, **overrides: Any) -> None:
    payload: dict[str, Any] = {
        "schema_version": "disclosure-policy/v1",
        "attested_at": "2026-08-11",
        "attested_by": "security-team",
        "contact": {"method": "email", "value": "security@example.com"},
        "acknowledgement_sla_hours": 24,
        "triage_sla_hours": 72,
        "public_disclosure_policy": {"default_window_days": 90, "negotiable": True},
    }
    payload.update(overrides)
    _write(root, ".oss-policy-kit/evidence/disclosure-policy.json", json.dumps(payload))


def test_a_complete_disclosure_policy_is_accepted(tmp_path: Path) -> None:
    _disclosure(tmp_path)
    assert governance.eval_gov_disc_065(_ctx(tmp_path)).status is not ControlStatus.FAIL


def test_the_schema_is_what_makes_a_missing_sla_field_impossible(tmp_path: Path) -> None:
    """Every SLA field the control reads is `required` with a floor, so the file cannot omit one.

    That is deliberate -- the refusal happens at load, naming the field, rather than later as a
    verdict -- and it is why the control's own missing-field branch has no reachable input.
    """

    _disclosure(tmp_path, acknowledgement_sla_hours=0)
    outcome = governance.eval_gov_disc_065(_ctx(tmp_path))

    assert outcome.status is ControlStatus.MANUAL_REVIEW_REQUIRED
    assert "acknowledgement_sla_hours" in outcome.reason


# --------------------------------------------------------------------------- #
# REL-ARCHIVE-063 -- how long releases are kept
# --------------------------------------------------------------------------- #


def _archival(root: Path, **overrides: Any) -> None:
    payload: dict[str, Any] = {
        "schema_version": "release-archival-policy/v1",
        "attested_at": "2026-08-11",
        "attested_by": "release-team",
        "retention_years": 10,
        "archive_destination": "github-releases",
        "vulnerability_handling_doc": "SECURITY.md",
    }
    payload.update(overrides)
    _write(root, ".oss-policy-kit/evidence/release-archival-policy.json", json.dumps(payload))


def test_a_complete_archival_policy_is_accepted(tmp_path: Path) -> None:
    _archival(tmp_path)
    assert governance.eval_release_archive_063(_ctx(tmp_path)).status is not ControlStatus.MANUAL_REVIEW_REQUIRED


def test_a_negative_retention_is_not_a_retention_period(tmp_path: Path) -> None:
    """A number the reader cannot act on is a gap, not a policy: a human has to look."""

    _archival(tmp_path, retention_years=-1)
    outcome = governance.eval_release_archive_063(_ctx(tmp_path))

    assert outcome.status is ControlStatus.MANUAL_REVIEW_REQUIRED
    assert "retention_years" in outcome.reason


def test_zero_years_is_read_as_a_policy_rather_than_as_a_missing_value(tmp_path: Path) -> None:
    """`0` is a deliberate "we keep nothing", and it earns the CRA remark, not the invalid one."""

    _archival(tmp_path, retention_years=0)
    outcome = governance.eval_release_archive_063(_ctx(tmp_path))

    assert "retention_years=0 is below" in outcome.reason
    assert "invalid retention_years" not in outcome.reason


# --------------------------------------------------------------------------- #
# SCA-EPSS-001 -- an unenriched scan is not a low-probability one
# --------------------------------------------------------------------------- #


def _osv_sarif(root: Path, results: list[dict[str, Any]]) -> None:
    _write(
        root,
        _OSV_SARIF,
        json.dumps({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "osv-scanner"}}, "results": results}]}),
    )


def test_a_scan_with_no_epss_data_at_all_cannot_confirm_low_probability(tmp_path: Path) -> None:
    """Zero high-EPSS findings over a scan that measured no EPSS is not evidence of anything."""

    _osv_sarif(tmp_path, [{"ruleId": "CVE-2026-1", "message": {"text": "vuln"}}])
    outcome = supply_chain.eval_sca_epss_001(_ctx(tmp_path))

    assert outcome.status is ControlStatus.MANUAL_REVIEW_REQUIRED
    assert "no EPSS enrichment" in outcome.reason


def test_an_enriched_scan_with_only_low_scores_passes(tmp_path: Path) -> None:
    """The counterpart: enrichment present and nothing above the threshold is a real answer."""

    _osv_sarif(
        tmp_path,
        [{"ruleId": "CVE-2026-1", "message": {"text": "vuln"}, "properties": {"epss_score": 0.01, "cvss_score": 3.1}}],
    )
    assert supply_chain.eval_sca_epss_001(_ctx(tmp_path)).status is ControlStatus.PASS


# --------------------------------------------------------------------------- #
# CONT-DISTROLESS-001 -- a Dockerfile with no base image
# --------------------------------------------------------------------------- #


def test_a_dockerfile_the_reader_found_no_base_image_in_asks_for_review(tmp_path: Path) -> None:
    """Silence here would report "not distroless" about a file nobody managed to read."""

    _write(tmp_path, "Dockerfile", "# a Dockerfile with no FROM line at all\nRUN echo hi\n")
    outcome = supply_chain.eval_cont_distroless_001(_ctx(tmp_path))

    assert outcome.status is ControlStatus.MANUAL_REVIEW_REQUIRED
    assert "no FROM line parsed" in outcome.reason


@pytest.mark.parametrize("base", ["gcr.io/distroless/static", "cgr.dev/chainguard/static", "scratch"])
def test_a_minimal_base_image_passes(base: str, tmp_path: Path) -> None:
    _write(tmp_path, "Dockerfile", f"FROM {base}\nCOPY app /app\n")
    assert supply_chain.eval_cont_distroless_001(_ctx(tmp_path)).status is ControlStatus.PASS


# --------------------------------------------------------------------------- #
# CONT-RUNTIME-005 -- apt layers that leave the package lists behind
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("label", "cleanup"),
    [
        ("removing the lists", "&& rm -rf /var/lib/apt/lists/*"),
        ("apt-get clean", "&& apt-get clean"),
    ],
)
def test_an_apt_layer_that_cleans_up_after_itself_is_not_reported(label: str, cleanup: str, tmp_path: Path) -> None:
    _write(tmp_path, "Dockerfile", f"FROM debian:12\nRUN apt-get update && apt-get install -y curl {cleanup}\n")
    assert containers.eval_cont_runtime_005(_ctx(tmp_path)).status is not ControlStatus.FAIL


def test_an_apt_layer_that_leaves_its_lists_behind_is_reported(tmp_path: Path) -> None:
    _write(tmp_path, "Dockerfile", "FROM debian:12\nRUN apt-get update && apt-get install -y curl\n")
    assert containers.eval_cont_runtime_005(_ctx(tmp_path)).status is ControlStatus.FAIL


def test_a_dockerfile_the_scanner_cannot_open_reads_as_empty_rather_than_crashing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Best-effort, and it resolves downwards: an unreadable file contributes no apt evidence."""

    _write(tmp_path, "Dockerfile", "FROM debian:12\nRUN apt-get install -y curl\n")
    original_text = Path.read_text
    original_bytes = Path.read_bytes

    # Both readers are refused, not just the one the evaluator happens to call today. These
    # readers moved from `read_text` to `read_bytes` when the UTF-16 false PASS was fixed, and
    # a test that intercepts only one of them stops testing anything the moment that choice
    # changes -- silently, because refusing nothing lets the file read fine and the assertion
    # then measures the ordinary path.
    def _refuse_text(self: Path, *args: object, **kwargs: object) -> str:
        if self.name == "Dockerfile":
            raise PermissionError("Access is denied")
        return original_text(self, *args, **kwargs)  # type: ignore[arg-type]

    def _refuse_bytes(self: Path, *args: object, **kwargs: object) -> bytes:
        if self.name == "Dockerfile":
            raise PermissionError("Access is denied")
        return original_bytes(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "read_text", _refuse_text)
    monkeypatch.setattr(Path, "read_bytes", _refuse_bytes)

    assert containers.eval_cont_runtime_005(_ctx(tmp_path)).status is ControlStatus.NOT_APPLICABLE


# --------------------------------------------------------------------------- #
# AIBOM-PRESENT-001 -- an ML-BOM found by its contents
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("marker", ["machine-learning-model", "modelCard", "ML-BOM"])
def test_a_cyclonedx_document_declaring_a_model_counts_as_an_aibom(marker: str, tmp_path: Path) -> None:
    """It need not live in the evidence directory; the marker is what makes it one."""

    _write(tmp_path, "artifacts/app.cdx.json", json.dumps({"bomFormat": "CycloneDX", "components": [{"type": marker}]}))
    assert supply_chain.eval_aibom_present_001(_ctx(tmp_path)).status is not ControlStatus.MANUAL_REVIEW_REQUIRED


def test_an_ordinary_sbom_is_not_mistaken_for_an_aibom(tmp_path: Path) -> None:
    """The counterpart: every repository with an SBOM would otherwise claim an AI BOM."""

    _write(
        tmp_path, "artifacts/app.cdx.json", json.dumps({"bomFormat": "CycloneDX", "components": [{"type": "library"}]})
    )
    assert supply_chain.eval_aibom_present_001(_ctx(tmp_path)).status is ControlStatus.MANUAL_REVIEW_REQUIRED
