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


def _analyze(tmp_path: Path, name: str, body: str) -> wp.WorkflowAnalysis:
    workflows = tmp_path / name / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(body, encoding="utf-8")
    return wp.analyze_workflows(tmp_path / name)


_DEPREV_STEP = (
    "name: CI\n"
    "on:\n"
    "  pull_request:\n"
    "jobs:\n"
    "  review:\n"
    "    runs-on: ubuntu-latest\n"
    "    steps:\n"
    "      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n"
    "{step}"
)
_DEPREV_ENABLED = "      - uses: actions/dependency-review-action@v4\n"
_DEPREV_COMMENTED = "      # - uses: actions/dependency-review-action@v4  # disabled, too noisy\n"


def test_dependency_review_must_be_a_step_not_a_comment(tmp_path: Path) -> None:
    """SEC-DEPREV-011 was granted by a substring match over the whole file.

    A workflow with the step **commented out** reported that pull requests were screened for
    vulnerable dependencies. Commenting a step out is the ordinary way to disable it, which
    makes this the worst possible input to answer wrongly -- the adopter turned the control
    off and the kit told them it was on.
    """

    assert _analyze(tmp_path, "enabled", _DEPREV_STEP.format(step=_DEPREV_ENABLED)).has_dependency_review
    assert not _analyze(tmp_path, "commented", _DEPREV_STEP.format(step=_DEPREV_COMMENTED)).has_dependency_review


def test_dependency_review_accepts_the_ghes_variant(tmp_path: Path) -> None:
    step = "      - uses: advanced-security/dependency-review-action@v4\n"
    assert _analyze(tmp_path, "ghes", _DEPREV_STEP.format(step=step)).has_dependency_review


def test_dependency_review_is_not_granted_by_a_mention_in_a_run_block(tmp_path: Path) -> None:
    """A shell line that talks about the action is not the action."""

    step = "      - run: echo 'we should add dependency-review-action here'\n"
    assert not _analyze(tmp_path, "runblock", _DEPREV_STEP.format(step=step)).has_dependency_review


def test_dependency_review_matcher_is_anchored(tmp_path: Path) -> None:
    """Only the action itself counts, not something whose name merely contains it.

    Mutation testing added this one: dropping the `$` from the pattern changed nothing that
    any test could see. The line still executed and coverage still read 100% -- executing a
    line is not the same as checking what it decides.
    """

    fork = "      - uses: someone/dependency-review-action-fork@v1\n"
    assert not _analyze(tmp_path, "fork", _DEPREV_STEP.format(step=fork)).has_dependency_review

    prefixed = "      - uses: someone/not-dependency-review-action@v1\n"
    assert not _analyze(tmp_path, "prefixed", _DEPREV_STEP.format(step=prefixed)).has_dependency_review


def test_iter_step_uses_reads_job_level_reusable_workflow_calls() -> None:
    """A job that calls a reusable workflow has a `uses:` and no `steps:` at all.

    Also from mutation testing: deleting this branch broke nothing, because the only
    consumer today -- dependency-review -- is a step action and can never appear here. It
    stays because it is the helper's contract and because the deferred CI-PIN-008 fix needs
    exactly this shape, but it needs a test of its own to be worth keeping.
    """

    data: dict[str, Any] = {
        "jobs": {
            "call": {"uses": "org/repo/.github/workflows/release.yml@v1"},
            "build": {"steps": [{"uses": "actions/checkout@v4"}, {"run": "make"}]},
            "broken": {"steps": "not-a-list"},
            "alsobroken": "not-a-mapping",
        }
    }

    assert sorted(wp._iter_step_uses(data)) == [
        "actions/checkout@v4",
        "org/repo/.github/workflows/release.yml@v1",
    ]
    assert list(wp._iter_step_uses({"jobs": "not-a-mapping"})) == []
    assert list(wp._iter_step_uses({})) == []


_OIDC_DEPLOY = (
    "name: deploy\n"
    "on:\n"
    "  push:\n"
    "    branches: [main]\n"
    "{perms}"
    "jobs:\n"
    "  deploy:\n"
    "    runs-on: ubuntu-latest\n"
    "    steps:\n"
    "      - uses: azure/login@v2\n"
    "        with:\n"
    "          creds: ${{ secrets.AZURE_CREDENTIALS }}\n"
)


def test_oidc_posture_must_be_declared_not_mentioned(tmp_path: Path) -> None:
    """GH-DEPLOY-022 read `"id-token: write" in raw`, so a TODO about OIDC counted as OIDC.

    The workflow below authenticates with a long-lived secret -- the exact posture the
    control exists to flag -- and its only mention of `id-token: write` is a comment saying
    the migration has not happened. It reported that OIDC federation was in use.
    """

    comment_only = _OIDC_DEPLOY.format(perms="# TODO: switch to OIDC, needs id-token: write\n")
    declared = _OIDC_DEPLOY.format(perms="permissions:\n  id-token: write\n  contents: read\n")

    assert _analyze(tmp_path, "todo", comment_only).cloud_deploy_workflow_paths, "fixture must be a deploy workflow"
    assert not _analyze(tmp_path, "todo2", comment_only).cloud_deploy_with_oidc_paths
    assert _analyze(tmp_path, "declared", declared).cloud_deploy_with_oidc_paths


def test_oidc_posture_still_reads_job_level_and_federation_steps() -> None:
    """Removing the raw branch must not cost the two parsed paths."""

    assert wp._workflow_has_oidc_posture({"permissions": {"id-token": "write"}})
    assert wp._workflow_has_oidc_posture({"jobs": {"d": {"permissions": {"id-token": "write"}}}})
    assert wp._workflow_has_oidc_posture(
        {
            "jobs": {
                "d": {"steps": [{"uses": "aws-actions/configure-aws-credentials@v4", "with": {"role-to-assume": "a"}}]}
            }
        }
    )
    assert not wp._workflow_has_oidc_posture({"jobs": {"d": {"steps": [{"uses": "azure/login@v2"}]}}})


_SHA_PINNED = (
    "name: CI\n"
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
    "{extra}"
)


def test_a_commented_out_step_does_not_make_a_pinned_workflow_unpinned(tmp_path: Path) -> None:
    """CI-PIN-008. The pattern had no line anchor, so it matched `uses:` after a `#`.

    A workflow pinned entirely to commit SHAs failed the control because of one step the
    adopter had commented out and annotated. They did the work, left a note about what they
    removed, and the note failed them.
    """

    commented = "      # - uses: actions/setup-node@v4  # disabled, too slow\n"
    assert _analyze(tmp_path, "commented", _SHA_PINNED.format(extra=commented)).mutable_action_refs == []

    # A block scalar, so the shell text stays opaque to YAML. Written as a plain scalar the
    # `: ` makes the document invalid, which sends the file down the parse-failure path where
    # scanning the text IS correct -- see the test below.
    quoted_in_run = "      - run: |\n          echo 'put uses: actions/setup-node@v4 in your workflow'\n"
    assert _analyze(tmp_path, "inrun", _SHA_PINNED.format(extra=quoted_in_run)).mutable_action_refs == []


def test_an_unparseable_workflow_still_falls_back_to_scanning_the_text(tmp_path: Path) -> None:
    """The degraded path is the one place the raw scan belongs, and it must stay.

    There is no structure to read, so a text scan is the only signal available -- better an
    over-broad answer than silently reporting a broken workflow as fully pinned.
    """

    broken = "name: CI\njobs:\n  build:\n    steps:\n      - uses: actions/setup-node@v4\n  : : :\n"
    analysis = _analyze(tmp_path, "broken", broken)

    assert analysis.parse_errors, "fixture must actually fail to parse, or this proves nothing"
    assert [ref for _p, ref in analysis.mutable_action_refs] == ["actions/setup-node@v4"]


def test_a_real_moving_tag_is_still_flagged(tmp_path: Path) -> None:
    """The counterpart, so the test above cannot pass by never flagging anything."""

    real = "      - uses: actions/setup-node@v4\n"
    refs = [ref for _p, ref in _analyze(tmp_path, "real", _SHA_PINNED.format(extra=real)).mutable_action_refs]
    assert refs == ["actions/setup-node@v4"]


_PROV = "name: CI\non:\n  push:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n{step}"


@pytest.mark.parametrize(
    ("label", "step"),
    [
        ("comment", "      # TODO: add SLSA provenance and cosign signing some day\n"),
        ("step_name", "      - name: check attestation docs\n        run: echo hi\n"),
        ("run_prose", "      - run: echo 'provenance and slsa are on the roadmap'\n"),
        ("installer_only", "      - uses: sigstore/cosign-installer@v3\n"),
        ("cosign_version", "      - run: cosign version\n"),
        ("cosign_verify", "      - run: cosign verify $IMAGE\n"),
    ],
)
def test_attestation_is_not_granted_by_the_word_alone(label: str, step: str, tmp_path: Path) -> None:
    """GH-PROV-023 matched bare `slsa`/`provenance`/`attestation` and then returned PASS
    **citing the workflow as its evidence** -- a plan to add provenance became proof of it,
    with a file reference attached to make it look substantiated.

    `installer_only` is the judgement call in this fix: installing cosign is not signing with
    it. A workflow that installs and then signs is caught by `cosign sign` in the run text.
    """

    assert not _analyze(tmp_path, label, _PROV.format(step=step)).has_artifact_attestation


@pytest.mark.parametrize(
    ("label", "step"),
    [
        ("attest_action", "      - uses: actions/attest-build-provenance@v1\n"),
        ("attest_sbom", "      - uses: actions/attest-sbom@v1\n"),
        ("cosign_sign", "      - run: cosign sign --yes $IMAGE\n"),
        ("cosign_attest", "      - run: cosign attest --predicate sbom.json $IMAGE\n"),
    ],
)
def test_attestation_is_granted_by_a_real_step(label: str, step: str, tmp_path: Path) -> None:
    assert _analyze(tmp_path, label, _PROV.format(step=step)).has_artifact_attestation


def test_attestation_reads_the_slsa_generator_called_as_a_reusable_workflow(tmp_path: Path) -> None:
    """The SLSA generator is a job-level `uses:`, so it has no `steps:` to walk."""

    body = (
        "name: CI\non:\n  push:\njobs:\n"
        "  provenance:\n"
        "    uses: slsa-framework/slsa-github-generator/.github/workflows/"
        "generator_generic_slsa3.yml@v2.0.0\n"
    )
    assert _analyze(tmp_path, "slsagen", body).has_artifact_attestation


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
    # The first case here used to be `_workflow_has_oidc_posture("permissions:\n  id-token:
    # write\n", {})` -- raw text granting OIDC over an EMPTY parsed workflow. It pinned the
    # defect rather than the requirement: the function no longer takes the text at all.
    assert wp._workflow_has_oidc_posture({"permissions": {"id-token": "write"}})
    assert wp._workflow_has_oidc_posture({"jobs": {"j": {"permissions": {"id-token": "write"}}}})
    assert not wp._workflow_has_oidc_posture({"jobs": {}})
    assert not wp._workflow_has_oidc_posture({})


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
