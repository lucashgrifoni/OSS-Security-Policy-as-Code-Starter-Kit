"""Predicate + integration coverage for ``infrastructure.workflow_parser``."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

from oss_policy_kit.infrastructure import workflow_parser as wp
from oss_policy_kit.infrastructure.yaml_io import load_yaml_file

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


def _on_true(triggers: dict[str, Any]) -> dict[str, Any]:
    """A workflow dict keyed the way PyYAML actually returns it.

    ``on:`` unquoted is a YAML 1.1 boolean, so the trigger block lands under ``True``.
    The cast is the point of the helper: the annotation says ``dict[str, Any]``
    everywhere in the parser, and this is the one key that isn't a string.
    """

    return cast(dict[str, Any], {True: triggers})


def test_contains_pr_event() -> None:
    assert wp._contains_pr_event({"on": "pull_request"})
    assert wp._contains_pr_event({"on": ["push", "pull_request_target"]})
    assert wp._contains_pr_event({"on": {"pull_request": {}}})
    assert not wp._contains_pr_event({"on": {"push": {}}})
    # The trigger block is read, not the file text. This used to fall through to a
    # substring scan of the raw workflow, so a workflow whose only mention of
    # `pull_request` was in a comment counted as PR-triggered.
    assert not wp._contains_pr_event({})
    # ...and the real key a parsed workflow carries is the YAML 1.1 boolean.
    assert wp._contains_pr_event(_on_true({"pull_request": {}}))
    assert not wp._contains_pr_event(_on_true({"push": {}}))


def test_is_self_hosted_runs_on() -> None:
    assert wp._is_self_hosted_runs_on("self-hosted")
    assert wp._is_self_hosted_runs_on(["self-hosted", "linux"])
    assert not wp._is_self_hosted_runs_on("ubuntu-latest")
    assert not wp._is_self_hosted_runs_on(42)


def test_detect_release_workflow_reads_triggers() -> None:
    assert wp._detect_release_workflow({"on": {"release": {"types": ["published"]}}})
    assert wp._detect_release_workflow({"on": "release"})
    assert wp._detect_release_workflow({"on": ["push", "release"]})
    assert wp._detect_release_workflow(_on_true({"push": {"tags": ["v*"]}}))
    assert not wp._detect_release_workflow({"on": {"push": {"branches": ["main"]}}})
    # A manual trigger is a manual trigger. Treating `workflow_dispatch` as a release
    # made every repo with a manual utility job answer for release concurrency.
    assert not wp._detect_release_workflow({"on": {"workflow_dispatch": {}}})


def test_detect_release_workflow_reads_jobs_not_prose() -> None:
    assert wp._detect_release_workflow({"jobs": {"publish-pypi": {"steps": []}}})
    assert wp._detect_release_workflow({"jobs": {"j": {"name": "Deploy to prod", "steps": []}}})
    assert wp._detect_release_workflow({"jobs": {"j": {"steps": [{"uses": "pypa/gh-action-pypi-publish@release/v1"}]}}})
    assert wp._detect_release_workflow({"jobs": {"j": {"steps": [{"run": "twine upload dist/*"}]}}})
    assert wp._detect_release_workflow({"jobs": {"j": {"steps": [{"run": "gh release create v1"}]}}})
    # Prose that merely mentions releasing is not a release workflow. This is the
    # defect: every workflow template the kit ships carries a comment explaining that
    # actions are pinned by SHA with the release tag alongside, and the bare substring
    # `release` in that comment classified all of them as release workflows.
    assert not wp._detect_release_workflow({"jobs": {"j": {"steps": [{"run": "echo release the hounds"}]}}})
    assert not wp._detect_release_workflow({"jobs": {"lint": {"steps": [{"uses": "actions/checkout@v4"}]}}})


def test_detect_release_workflow_survives_malformed_jobs() -> None:
    """Workflow YAML is adopter input, so every level of it can be the wrong type."""

    assert not wp._detect_release_workflow({"jobs": "not-a-mapping"})
    assert not wp._detect_release_workflow({"jobs": {"lint": "not-a-mapping"}})
    assert not wp._detect_release_workflow({"jobs": {"lint": {"steps": "not-a-list"}}})
    # A malformed step is skipped, not fatal, and the real step after it still counts.
    assert wp._detect_release_workflow({"jobs": {"lint": {"steps": [None, {"run": "twine upload dist/*"}]}}})
    assert not wp._detect_release_workflow({"jobs": {"lint": {"steps": ["just a string"]}}})


def test_detect_release_workflow_ignores_comments(tmp_path: Path) -> None:
    """The end-to-end property: the same file with and without comments answers the same.

    Written against ``analyze_workflows`` rather than the predicate because the defect
    only existed once the file's *text* reached the detector.
    """

    body = (
        "name: CI\n"
        "on:\n"
        "  push:\n"
        "    branches: [main]\n"
        "jobs:\n"
        "  quality:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n"
    )
    comment = "# Actions are pinned to immutable commit SHAs (release tag in the trailing comment).\n"

    plain = tmp_path / "plain" / ".github" / "workflows"
    plain.mkdir(parents=True)
    (plain / "ci.yml").write_text(body, encoding="utf-8")

    annotated = tmp_path / "annotated" / ".github" / "workflows"
    annotated.mkdir(parents=True)
    (annotated / "ci.yml").write_text(comment + body, encoding="utf-8")

    assert wp.analyze_workflows(tmp_path / "plain").release_workflow_paths == []
    assert wp.analyze_workflows(tmp_path / "annotated").release_workflow_paths == []


def test_shipped_workflow_templates_are_not_release_workflows() -> None:
    """The regression that shipped: `init --with-workflow` then `evaluate` self-failed.

    Every template the kit writes was classified as a release workflow and failed
    GH-REL-021 for missing `concurrency:` -- a finding the kit produced, about a file
    the kit wrote, for a control that does not apply to it.
    """

    templates = sorted((Path(wp.__file__).parents[1] / "data" / "templates" / "workflows").glob("*.yml"))
    assert templates, "no shipped workflow templates found -- this test would pass vacuously"

    for template in templates:
        data = load_yaml_file(template)
        assert isinstance(data, dict)
        assert not wp._detect_release_workflow(data), f"{template.name} is still read as a release workflow"


def test_declares_concurrency_accepts_job_level() -> None:
    """GH-REL-021's message says "workflow or job level"; the check only read the top."""

    assert wp._declares_concurrency({"concurrency": "release"})
    assert wp._declares_concurrency({"jobs": {"publish": {"concurrency": "release-${{ github.ref }}"}}})
    assert not wp._declares_concurrency({"jobs": {"publish": {"steps": []}}})
    assert not wp._declares_concurrency({})


def test_concurrency_must_protect_the_job_that_publishes() -> None:
    """Widening to *any* job silenced the control on the case it exists for.

    Adversarial review reproduced it before release: a group on a ``docs`` job and a bare
    ``publish`` job running ``twine upload`` reported PASS -- which is exactly the
    double-publish GH-REL-021 is there to prevent. A group somewhere in the file is not the
    same as a group where the publishing happens.
    """

    unprotected_publisher = {
        "jobs": {
            "docs": {"concurrency": "docs-${{ github.ref }}", "steps": [{"run": "mkdocs build"}]},
            "publish": {"steps": [{"run": "twine upload dist/*"}]},
        }
    }
    assert not wp._declares_concurrency(unprotected_publisher)

    protected_publisher = {
        "jobs": {
            "docs": {"steps": [{"run": "mkdocs build"}]},
            "publish": {"concurrency": "release-${{ github.ref }}", "steps": [{"run": "twine upload dist/*"}]},
        }
    }
    assert wp._declares_concurrency(protected_publisher)

    # Two publishers, one protected: protecting half of them is not protection.
    assert not wp._declares_concurrency(
        {
            "jobs": {
                "publish-pypi": {"concurrency": "a", "steps": [{"run": "twine upload dist/*"}]},
                "publish-npm": {"steps": [{"run": "npm publish"}]},
            }
        }
    )

    # Signal came from the trigger alone, so there is no job to attribute a group to.
    assert not wp._declares_concurrency(_on_true({"push": {"tags": ["v*"]}}) | {"jobs": {"build": {"steps": []}}})


@pytest.mark.parametrize(
    "command",
    [
        "./gradlew publishToSonatype",
        "./gradlew publishToMavenCentral --no-daemon",
        "./gradlew publishAllPublicationsToMavenRepository",
        "sbt publishSigned sonatypeBundleRelease",
        "sbt publish",
        "uv publish",
        "hatch publish",
        "maturin publish",
        "nuget push pkg.nupkg",
        "docker buildx build --platform linux/amd64 -t x --push .",
        "gh release upload v1 dist/app.zip",
        "pulumi up --yes",
        "serverless deploy --stage prod",
        "cdk deploy --require-approval never",
        "kubectl rollout restart deployment/api",
        "kubectl set image deployment/api api=x:1",
    ],
)
def test_publishing_commands_that_the_word_boundary_used_to_drop(command: str) -> None:
    """`\\bpublish\\b` needs a boundary after the verb, and a capital letter is not one.

    That silently dropped every namespaced Gradle and sbt task -- which is how essentially
    every JVM project publishes to Maven Central. Those workflows answered "No release or
    deploy workflow detected" with full confidence. The substring detector this replaced
    caught them, so it was a regression, not a pre-existing gap.
    """

    assert wp._job_publishes({"steps": [{"run": command}]}), command


def test_prose_still_does_not_count_as_publishing() -> None:
    """The looser regex must not undo the fix it sits next to."""

    for prose in ("echo release the hounds", "echo 'ready to publish soon'", "# deploy notes"):
        assert not wp._job_publishes({"steps": [{"run": prose}]}), prose


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
