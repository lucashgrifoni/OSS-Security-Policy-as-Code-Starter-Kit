"""Predicate + integration coverage for ``infrastructure.workflow_parser``."""

from __future__ import annotations

from pathlib import Path

from oss_policy_kit.infrastructure import workflow_parser as wp

# --------------------------------------------------------------------------- #
# pure predicates
# --------------------------------------------------------------------------- #


def test_reusable_workflow_pin_is_full_sha() -> None:
    sha = "a" * 40
    assert wp._reusable_workflow_pin_is_full_sha(f"org/repo/.github/workflows/x.yml@{sha}")
    assert wp._reusable_workflow_pin_is_full_sha("actions/checkout@v4")  # not reusable -> True
    assert not wp._reusable_workflow_pin_is_full_sha("org/repo/.github/workflows/x.yml")  # no @
    assert not wp._reusable_workflow_pin_is_full_sha("org/repo/.github/workflows/x.yml@v1")  # tag


def test_is_immutable_action_ref() -> None:
    assert wp._is_immutable_action_ref("actions/checkout@" + "a" * 40)
    assert wp._is_immutable_action_ref("./local/action")
    assert wp._is_immutable_action_ref("docker://image:tag")
    assert wp._is_immutable_action_ref("${{ env.X }}")
    assert wp._is_immutable_action_ref("noref")  # no @
    assert not wp._is_immutable_action_ref("actions/checkout@v4")  # version tag = mutable
    assert not wp._is_immutable_action_ref("actions/checkout@main")
    assert wp._is_immutable_action_ref("actions/checkout@abc1234")  # short sha


def test_contains_pr_event() -> None:
    assert wp._contains_pr_event({"on": "pull_request"}, "")
    assert wp._contains_pr_event({"on": ["push", "pull_request_target"]}, "")
    assert wp._contains_pr_event({"on": {"pull_request": {}}}, "")
    assert not wp._contains_pr_event({"on": {"push": {}}}, "no pr here")
    assert wp._contains_pr_event({}, "triggered on pull_request")


def test_is_self_hosted_runs_on() -> None:
    assert wp._is_self_hosted_runs_on("self-hosted")
    assert wp._is_self_hosted_runs_on(["self-hosted", "linux"])
    assert not wp._is_self_hosted_runs_on("ubuntu-latest")
    assert not wp._is_self_hosted_runs_on(42)


def test_detect_release_workflow() -> None:
    assert wp._detect_release_workflow({}, "this is a release pipeline")
    assert wp._detect_release_workflow({"on": {"release": {}}}, "x")
    assert wp._detect_release_workflow({"on": {"workflow_dispatch": {}}}, "x")
    assert wp._detect_release_workflow({}, "on:\n  push:\n    tags:\n")
    assert not wp._detect_release_workflow({"on": {"push": {}}}, "plain ci")


def test_step_and_job_oidc() -> None:
    assert wp._step_indicates_oidc(
        {"uses": "aws-actions/configure-aws-credentials@v4", "with": {"role-to-assume": "arn"}}
    )
    assert wp._step_indicates_oidc(
        {"uses": "google-github-actions/auth@v2", "with": {"workload_identity_provider": "x"}}
    )
    assert wp._step_indicates_oidc({"uses": "azure/login@v2", "with": {"client-id": "x"}})
    assert not wp._step_indicates_oidc({"uses": "azure/login@v2", "with": {"creds": "x"}})
    assert not wp._step_indicates_oidc("notdict")
    assert wp._job_indicates_oidc({"permissions": {"id-token": "write"}})
    assert wp._job_indicates_oidc(
        {"steps": [{"uses": "aws-actions/configure-aws-credentials@v4", "with": {"role-to-assume": "a"}}]}
    )
    assert not wp._job_indicates_oidc("notdict")


def test_workflow_has_oidc_posture() -> None:
    assert wp._workflow_has_oidc_posture("permissions:\n  id-token: write\n", {})
    assert wp._workflow_has_oidc_posture("", {"permissions": {"id-token": "write"}})
    assert wp._workflow_has_oidc_posture("", {"jobs": {"j": {"permissions": {"id-token": "write"}}}})
    assert not wp._workflow_has_oidc_posture("", {"jobs": {}})


# --------------------------------------------------------------------------- #
# analyze_workflows integration
# --------------------------------------------------------------------------- #


def test_analyze_workflows_rich(tmp_path: Path) -> None:
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "release.yml").write_text(
        "on:\n"
        "  pull_request:\n"
        "  release:\n"
        "    types: [published]\n"
        "permissions: write-all\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: [self-hosted, linux]\n"
        "    permissions:\n"
        "      contents: write\n"
        "      id-token: write\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - uses: aws-actions/configure-aws-credentials@v4\n"
        "        with:\n"
        "          role-to-assume: arn:aws:iam::1:role/x\n",
        encoding="utf-8",
    )
    result = wp.analyze_workflows(tmp_path)
    assert result.workflow_paths
    # PR + self-hosted -> recorded
    assert result.pr_self_hosted_runner_paths
    # broad permissions (write-all) -> recorded
    assert result.broad_job_permissions
    # release workflow detected
    assert result.release_workflow_paths


def test_analyze_workflows_empty(tmp_path: Path) -> None:
    assert wp.analyze_workflows(tmp_path).workflow_paths == []
