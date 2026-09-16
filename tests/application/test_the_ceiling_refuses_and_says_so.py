"""Every refusal branch the ceiling added, exercised rather than assumed.

The readers introduced with the ceiling each have two arms nothing reached: the file is over
``MAX_CI_CONFIG_BYTES`` (or ``MAX_EVIDENCE_BYTES``), or it cannot be opened at all. Both are the
arms that matter -- they are what a repository writes when it wants the audit to stop looking --
and a branch that never executes is documentation, not behaviour.

Each test builds the real condition rather than patching the ceiling down, except where building
a megabyte would make the suite pay for it on every run; there the constant is lowered and the
comment says so.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from oss_policy_kit.application import evaluators_common, evaluators_containers, profile_hints
from oss_policy_kit.application.evaluators import _shared as sh
from oss_policy_kit.application.evaluators import aws as aws_eval
from oss_policy_kit.application.input_limits import MAX_CI_CONFIG_BYTES
from oss_policy_kit.cli import emit_insights
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure import git_remote
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis, analyze_aws_ci
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.iac import hcl_loader
from oss_policy_kit.infrastructure.iac.bicep import scanner as bicep_scanner
from oss_policy_kit.infrastructure.iac.cfn import scanner as cfn_scanner
from oss_policy_kit.infrastructure.iac.pulumi import scanner as pulumi_scanner
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis

#: One byte over the ceiling is the whole condition, and a megabyte per test is a cost the suite
#: pays on every run forever. Written once, reused, and still a real file on a real filesystem.
OVERSIZE = "# pad\n" * ((MAX_CI_CONFIG_BYTES // 6) + 2)


def _oversize(path: Path, body: str = OVERSIZE) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    assert path.stat().st_size > MAX_CI_CONFIG_BYTES, "fixture does not reach the branch under test"
    return path


def _refuse_reads(monkeypatch: pytest.MonkeyPatch, target: Path) -> None:
    """Refuse BOTH readers: a patch covering one of them refuses nothing once the other is used."""

    wanted = target.resolve()
    real_text, real_bytes = Path.read_text, Path.read_bytes

    def _text(self: Path, *a: object, **k: object) -> str:
        if self.resolve() == wanted:
            raise OSError(13, "Permission denied")
        return real_text(self, *a, **k)  # type: ignore[arg-type]

    def _bytes(self: Path, *a: object, **k: object) -> bytes:
        if self.resolve() == wanted:
            raise OSError(13, "Permission denied")
        return real_bytes(self, *a, **k)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "read_text", _text)
    monkeypatch.setattr(Path, "read_bytes", _bytes)


# --- the three readers ---------------------------------------------------------------------- #


def test_read_repo_text_reports_the_ceiling(tmp_path: Path) -> None:
    read = sh.read_repo_text(_oversize(tmp_path / "big.yml"), label="Workflow")

    assert read.unread is True
    assert read.text == ""
    assert "Workflow" in read.why


def test_read_repo_text_reports_a_file_it_cannot_open(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "locked.yml"
    target.write_text("name: x\n", encoding="utf-8")
    _refuse_reads(monkeypatch, target)

    read = sh.read_repo_text(target)

    assert read.unread is True
    assert read.why


def test_capped_repo_text_returns_empty_past_the_ceiling(tmp_path: Path) -> None:
    assert sh.capped_repo_text(_oversize(tmp_path / "big.md")) == ""


def test_capped_repo_text_still_raises_what_read_text_raised(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The contract that made this reader separate from read_repo_text."""

    target = tmp_path / "locked.md"
    target.write_text("x", encoding="utf-8")
    _refuse_reads(monkeypatch, target)

    with pytest.raises(OSError):
        sh.capped_repo_text(target)


def test_capped_repo_bytes_returns_empty_past_the_ceiling(tmp_path: Path) -> None:
    assert sh.capped_repo_bytes(_oversize(tmp_path / "big.txt")) == b""


def test_capped_evidence_text_returns_empty_past_the_ceiling(tmp_path: Path) -> None:
    big = tmp_path / "evidence.json"
    big.write_text(json.dumps({"pad": "x" * (6 * 1024 * 1024)}), encoding="utf-8")

    assert evaluators_common.capped_evidence_text(big) == ""


# --- the signal helpers --------------------------------------------------------------------- #


def test_a_signal_document_over_the_ceiling_signals_nothing(tmp_path: Path) -> None:
    _oversize(tmp_path / "RELEASE_ARCHIVAL.md", "retention policy: 7 years\n" + OVERSIZE)

    assert sh._release_archive_signal_match(tmp_path) is None


def test_a_workflow_over_the_ceiling_is_not_a_self_hosted_absence(tmp_path: Path) -> None:
    _oversize(tmp_path / ".github" / "workflows" / "big.yml", "runs-on: [self-hosted]\n" + OVERSIZE)

    all_self, _marked, unread = sh._self_hosted_workflow_paths(tmp_path)

    assert all_self == []
    assert [p.name for p in unread] == ["big.yml"]


# --- the evaluators ------------------------------------------------------------------------- #


def _ctx(root: Path, **over: object) -> sh.EvalContext:
    kwargs: dict[str, object] = {
        "repo_root": root,
        "profile_id": "github-level-1",
        "workflows": WorkflowAnalysis(),
        "azure_pipelines": AzurePipelineAnalysis(),
        "aws_ci": AwsCiAnalysis(),
        "scorecard": None,
    }
    kwargs.update(over)
    return sh.EvalContext(**kwargs)  # type: ignore[arg-type]


def test_an_oversize_buildspec_withdraws_every_aws_content_control(tmp_path: Path) -> None:
    """AWS-CI-037 is not the control to ask: the buildspec DOES exist, so its PASS is right.

    The defect is downstream, in the controls that scan the file's contents and would otherwise
    find a blank page where the parser refused to read one.
    """

    _oversize(tmp_path / "buildspec.yml", "version: 0.2\n" + OVERSIZE)
    ctx = _ctx(tmp_path, aws_ci=analyze_aws_ci(tmp_path))

    assert aws_eval.eval_aws_ci_037(ctx).status is ControlStatus.PASS

    outcome = aws_eval.eval_aws_secret_038(ctx)

    assert outcome.status is ControlStatus.MANUAL_REVIEW_REQUIRED
    assert "could not be read" in outcome.reason


def test_an_unreadable_dockerfile_joins_the_unread_list(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    df = tmp_path / "Dockerfile"
    df.write_text("FROM debian:12\nRUN apt-get install -y curl\n", encoding="utf-8")
    _refuse_reads(monkeypatch, df)

    outcome = evaluators_containers.eval_cont_runtime_005(_ctx(tmp_path))

    assert outcome.status is ControlStatus.MANUAL_REVIEW_REQUIRED
    assert "could not be read" in outcome.reason


def test_an_unreadable_dockerfile_reaches_the_pinning_control(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    df = tmp_path / "Dockerfile"
    df.write_text("FROM debian:12\nRUN apt-get install -y curl\n", encoding="utf-8")
    _refuse_reads(monkeypatch, df)

    outcome = evaluators_containers.eval_cont_runtime_006(_ctx(tmp_path))

    assert outcome.status is ControlStatus.MANUAL_REVIEW_REQUIRED


# --- the scanners --------------------------------------------------------------------------- #


def test_an_oversize_terraform_file_raises_rather_than_vanishing(tmp_path: Path) -> None:
    """HclLoadError is the channel every Terraform control consults; silence is not."""

    big = _oversize(tmp_path / "main.tf", 'resource "aws_s3_bucket" "b" {}\n' + OVERSIZE)

    with pytest.raises(hcl_loader.HclLoadError):
        hcl_loader.load_hcl_file(big)


def test_an_oversize_bicep_file_is_recorded_as_unread(tmp_path: Path) -> None:
    _oversize(tmp_path / "main.bicep", "param x string\n" + OVERSIZE)

    result = bicep_scanner.run_scan(tmp_path)

    assert result.parse_errors, "an unread candidate must not vanish from the scan"


def test_an_oversize_pulumi_candidate_is_marked_as_resembling(tmp_path: Path) -> None:
    _oversize(tmp_path / "__main__.py", "import pulumi\n" + OVERSIZE)

    result = pulumi_scanner.run_scan(tmp_path)

    assert any(e.get("resembles") for e in result.parse_errors)


def test_an_oversize_cfn_template_is_refused_as_a_template(tmp_path: Path) -> None:
    big = _oversize(tmp_path / "template.yaml", "AWSTemplateFormatVersion: '2010-09-09'\n" + OVERSIZE)

    with pytest.raises(cfn_scanner.CfnParseError):
        cfn_scanner._load_cfn(big)


# --- the three readers outside the evaluator layer ------------------------------------------- #


def test_an_oversize_pyproject_contributes_no_tooling_notes(tmp_path: Path) -> None:
    notes: list[str] = []
    profile_hints._append_pyproject_tooling_notes(_oversize(tmp_path / "pyproject.toml"), notes)

    assert notes == []


def test_an_oversize_security_md_yields_no_contact(tmp_path: Path) -> None:
    assert emit_insights._security_md_email(_oversize(tmp_path / "SECURITY.md")) is None


def test_an_oversize_git_config_yields_no_slug(tmp_path: Path) -> None:
    _oversize(tmp_path / ".git" / "config", '[remote "origin"]\n\turl = https://github.com/a/b.git\n' + OVERSIZE)

    assert git_remote.read_github_repo_slug_from_git_config(tmp_path) is None


# --- the arms a hollow repository cannot reach ------------------------------------------------ #


@pytest.mark.parametrize(
    ("helper", "relative", "body"),
    [
        (sh._audit_stream_signal_match, "RELEASE_OPERATIONS.md", "audit log streaming is enabled"),
        (sh._release_archive_signal_match, "RELEASE_ARCHIVAL.md", "retention policy: 7 years"),
    ],
)
def test_a_signal_document_that_cannot_be_opened_signals_nothing(
    helper: object, relative: str, body: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Between "has content" and "over the ceiling" sits the file that simply will not open."""

    doc = tmp_path / relative
    doc.write_text(body, encoding="utf-8")
    assert helper(tmp_path) is not None, "fixture does not reach the branch under test"  # type: ignore[operator]

    _refuse_reads(monkeypatch, doc)

    assert helper(tmp_path) is None  # type: ignore[operator]


def test_the_parser_records_a_candidate_it_refused(tmp_path: Path) -> None:
    """Why AWS-CI-037 carries no withdrawal: its "nothing found" branch cannot be reached.

    The parser keeps the path alongside the error, so a refused candidate never looks like an
    absent one to that control. The withdrawal belongs to the controls that read the contents,
    and putting one here as well would be a guard that can never fire.
    """

    big = tmp_path / "pipelines" / "aws" / "codepipeline.json"
    _oversize(big, '{"pipeline": {"name": "x"}}\n' + OVERSIZE)

    analysis = analyze_aws_ci(tmp_path)

    assert analysis.parse_errors
    assert analysis.codepipeline_paths, "the path survives the refusal, so 'none found' is never true"


def test_an_empty_renovate_config_fails_rather_than_passing(tmp_path: Path) -> None:
    """The hollow-repo sweep cannot reach this: its dependabot.yml answers first.

    DEP-UPDATE-001 is catalogued `assurance: deterministic`, and a zero-byte `renovate.json`
    configures no Renovate run at all.
    """

    from oss_policy_kit.application.evaluators import governance as gov

    (tmp_path / "renovate.json").write_bytes(b"")

    outcome = gov.eval_dep_update_001(_ctx(tmp_path))

    assert outcome.status is ControlStatus.FAIL
    assert "empty" in outcome.reason


def test_an_oversize_manifest_is_marked_rather_than_skipped(tmp_path: Path) -> None:
    """`**/*.yaml` is mostly not Kubernetes, so a refused candidate must carry the mark.

    Without it the scanner records an error nobody acts on; with it, the controls that would
    otherwise report a clean cluster withdraw.
    """

    from oss_policy_kit.infrastructure.k8s import scanner as k8s_scanner

    _oversize(tmp_path / "pod.yaml", "apiVersion: v1\nkind: Pod\n" + OVERSIZE)

    result = k8s_scanner.run_scan(tmp_path)

    marked = [e for e in result.parse_errors if e.get("resembles")]
    assert marked, "an unread manifest candidate must be marked so a control can withdraw"
