"""A file the kit could not read must not put its absolute path into what the kit writes.

`str(OSError)` ends with the filename the caller opened, and the parsers and scanners open
paths under the RESOLVED repository root. So one unreadable file put the auditor's home
directory and OS username into shareable output: M-002, the leak the rest of the package
redacts with care. Measured on the published 10.0.26 by holding each file open exclusively
on Windows, with every path on the command line relative:

    GitLab CI parse issue .gitlab-ci.yml: [Errno 13] Permission denied: 'C:\\...\\.gitlab-ci.yml'

in the evaluation report, and the same shape for a composite action and a CodePipeline export,
in the Kubernetes, CloudFormation, Bicep and Pulumi evidence files, and in findings/1.0
(`correlate-findings --waivers`).

The suite already refused reads in these places and never saw it, because its fake error
carried no filename: `PermissionError(13, "Permission denied")` prints without a path, the
real one does not. So the fake here raises the real shape, and every case checks that the
fake actually fired before it trusts a clean result.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

from oss_policy_kit.application.input_limits import path_free_error_text
from oss_policy_kit.application.vuln_waivers import load_vuln_waivers
from oss_policy_kit.infrastructure import aws_ci_parser, azure_pipeline_parser, workflow_parser
from oss_policy_kit.infrastructure.gitlab_ci_parser import analyze_gitlab_ci
from oss_policy_kit.infrastructure.iac.bicep import scanner as bicep
from oss_policy_kit.infrastructure.iac.cfn import scanner as cfn
from oss_policy_kit.infrastructure.iac.pulumi import scanner as pulumi
from oss_policy_kit.infrastructure.k8s import helm_renderer
from oss_policy_kit.infrastructure.k8s import scanner as k8s

WORKFLOW = (
    "name: ci\non: [push]\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n"
)
ACTION = "name: setup\ndescription: x\nruns:\n  using: composite\n  steps:\n    - uses: actions/setup-python@v5\n"
GITLAB = "stages: [test]\ntest:\n  script:\n    - pytest\n"
CODEPIPELINE = '{"pipeline": {"name": "p", "roleArn": "arn:aws:iam::1:role/r", "stages": []}}'
BUILDSPEC = "version: 0.2\nphases:\n  build:\n    commands:\n      - echo hi\n"
AZURE = "trigger:\n  - main\nsteps:\n  - script: echo hi\n"
POD = "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n  containers:\n    - name: c\n      image: nginx:1.27\n"
CFN = "AWSTemplateFormatVersion: '2010-09-09'\nResources:\n  B:\n    Type: AWS::S3::Bucket\n"
BICEP = "resource sa 'Microsoft.Storage/storageAccounts@2023-01-01' = {\n  name: 'demo'\n}\n"
PULUMI = "import pulumi\nimport pulumi_aws as aws\nbucket = aws.s3.Bucket('b')\n"


def _ci_reasons(result: object) -> list[str]:
    return [reason for _, reason in result.parse_errors]  # type: ignore[attr-defined]


def _scan_reasons(outcome: object) -> list[str]:
    return [entry["error"] for entry in outcome.parse_errors]  # type: ignore[attr-defined]


#: (files the repository holds, the one that cannot be read, what reads the repository)
READ_CASES: dict[str, tuple[dict[str, str], str, Callable[[Path], list[str]]]] = {
    "gitlab-ci": ({".gitlab-ci.yml": GITLAB}, ".gitlab-ci.yml", lambda r: _ci_reasons(analyze_gitlab_ci(r))),
    "composite-action": (
        {".github/workflows/ci.yml": WORKFLOW, ".github/actions/setup/action.yml": ACTION},
        ".github/actions/setup/action.yml",
        lambda r: _ci_reasons(workflow_parser.analyze_workflows(r)),
    ),
    "codepipeline-export": (
        {"pipelines/aws/codepipeline.json": CODEPIPELINE},
        "pipelines/aws/codepipeline.json",
        lambda r: _ci_reasons(aws_ci_parser.analyze_aws_ci(r)),
    ),
    "k8s-manifest": ({"k8s/pod.yaml": POD}, "k8s/pod.yaml", lambda r: _scan_reasons(k8s.run_scan(r))),
    "cfn-template": ({"cfn/template.yaml": CFN}, "cfn/template.yaml", lambda r: _scan_reasons(cfn.run_scan(r))),
    "bicep-file": ({"main.bicep": BICEP}, "main.bicep", lambda r: _scan_reasons(bicep.run_scan(r))),
    "pulumi-program": (
        {"Pulumi.yaml": "name: demo\nruntime: python\n", "__main__.py": PULUMI},
        "__main__.py",
        lambda r: _scan_reasons(pulumi.run_scan(r)),
    ),
    "vuln-waivers": (
        {"waivers.yaml": "waivers: []\n"},
        "waivers.yaml",
        lambda r: load_vuln_waivers(r / "waivers.yaml")[1],
    ),
}

#: The parsers read a pipeline twice: once raw, then through `load_yaml_file`. The first read is
#: already path-free; these cases let it succeed and fail only the second.
REREAD_CASES: dict[str, tuple[object, str, str, Callable[[Path], list[str]]]] = {
    "workflow": (
        workflow_parser,
        ".github/workflows/ci.yml",
        WORKFLOW,
        lambda r: _ci_reasons(workflow_parser.analyze_workflows(r)),
    ),
    "buildspec": (aws_ci_parser, "buildspec.yml", BUILDSPEC, lambda r: _ci_reasons(aws_ci_parser.analyze_aws_ci(r))),
    "azure-pipeline": (
        azure_pipeline_parser,
        "azure-pipelines.yml",
        AZURE,
        lambda r: _ci_reasons(azure_pipeline_parser.analyze_azure_pipelines(r)),
    ),
}


def _write(repo: Path, files: dict[str, str]) -> None:
    for rel, body in files.items():
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_text(body, encoding="utf-8")


def _refusal(filename: str) -> PermissionError:
    """The error the operating system raises: errno, message, AND the filename it was given."""

    return PermissionError(13, "Permission denied", filename)


def _deny_read(monkeypatch: pytest.MonkeyPatch, target: Path) -> list[str]:
    """Make one file refuse both Path readers; return the filenames the refusals carried."""

    raised: list[str] = []
    real_text, real_bytes = Path.read_text, Path.read_bytes
    denied = target.resolve()

    def refuse_text(self: Path, *args: object, **kwargs: object) -> str:
        if self.resolve() == denied:
            raised.append(str(self))
            raise _refusal(str(self))
        return real_text(self, *args, **kwargs)  # type: ignore[arg-type]

    def refuse_bytes(self: Path) -> bytes:
        if self.resolve() == denied:
            raised.append(str(self))
            raise _refusal(str(self))
        return real_bytes(self)

    monkeypatch.setattr(Path, "read_text", refuse_text)
    monkeypatch.setattr(Path, "read_bytes", refuse_bytes)
    return raised


def _assert_reported_without_the_path(reasons: list[str], raised: list[str]) -> None:
    assert raised, "the refusal never fired, so a clean result here would prove nothing"
    assert reasons, "the unreadable file was not reported at all"
    joined = "\n".join(reasons)
    assert "Permission denied" in joined, joined
    for filename in raised:
        assert filename not in joined, joined
    assert os.sep not in joined, joined


@pytest.mark.parametrize("case", sorted(READ_CASES))
def test_an_unreadable_file_is_reported_without_its_path(
    case: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    files, locked, read = READ_CASES[case]
    _write(tmp_path, files)
    raised = _deny_read(monkeypatch, tmp_path / locked)

    reasons = read(tmp_path)

    _assert_reported_without_the_path(reasons, raised)


@pytest.mark.parametrize("case", sorted(READ_CASES))
def test_a_readable_repository_reports_no_read_failure(case: str, tmp_path: Path) -> None:
    """The baseline: without it, a reader that reports everything would pass the test above."""

    files, _, read = READ_CASES[case]
    _write(tmp_path, files)

    assert not any("Permission denied" in reason for reason in read(tmp_path))


@pytest.mark.parametrize("case", sorted(REREAD_CASES))
def test_a_second_read_that_fails_is_reported_without_its_path(
    case: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module, rel, body, read = REREAD_CASES[case]
    _write(tmp_path, {rel: body})
    denied = (tmp_path / rel).resolve()
    raised: list[str] = []
    real_load = module.load_yaml_file  # type: ignore[attr-defined]

    def refuse_second_read(path: Path, *args: object, **kwargs: object) -> object:
        if Path(path).resolve() == denied:
            raised.append(str(path))
            raise _refusal(str(path))
        return real_load(path, *args, **kwargs)

    monkeypatch.setattr(module, "load_yaml_file", refuse_second_read)

    _assert_reported_without_the_path(read(tmp_path), raised)


def test_a_helm_that_cannot_be_run_is_reported_without_its_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`subprocess.run` raises with the executable as its filename, often under the user's home."""

    chart = tmp_path / "repo" / "chart"
    chart.mkdir(parents=True)
    (chart / "Chart.yaml").write_text("apiVersion: v2\nname: chart\nversion: 0.1.0\n", encoding="utf-8")
    helm_bin = str(tmp_path / "home" / "someone" / "bin" / "helm")

    def cannot_start(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        raise FileNotFoundError(2, "No such file or directory", helm_bin)

    monkeypatch.setattr(helm_renderer.subprocess, "run", cannot_start)
    outcome = helm_renderer.HelmRenderOutcome(available=True)

    helm_renderer._render_one_chart(
        chart.resolve(), (tmp_path / "repo").resolve(), tmp_path / "out", helm_bin, 5, outcome
    )

    reasons = [entry["error"] for entry in outcome.render_errors]
    assert reasons == ["helm could not be run (No such file or directory)"]
    assert helm_bin not in reasons[0]


def test_every_other_exception_keeps_its_own_words() -> None:
    """Only the OSError loses anything: a YAML error's line and column are the useful part."""

    class NotAnOSError(ValueError):
        pass

    assert path_free_error_text(NotAnOSError("line 3, column 7: mapping values are not allowed")) == (
        "line 3, column 7: mapping values are not allowed"
    )
    assert (
        path_free_error_text(_refusal("/home/someone/repo/.gitlab-ci.yml"))
        == "it could not be read (Permission denied)"
    )


@pytest.mark.skipif(sys.platform == "win32", reason="chmod does not deny read on Windows; ACLs do")
def test_the_report_itself_carries_no_path_for_a_real_unreadable_file(tmp_path: Path) -> None:
    """End to end, with the operating system doing the refusing and the report as the surface.

    The cases above prove each handler. This proves the text that reaches evaluation-report.json
    and evaluation-report.md, which is where the path was measured.
    """

    target = tmp_path / "repo"
    target.mkdir()
    pipeline = target / ".gitlab-ci.yml"
    pipeline.write_text(GITLAB, encoding="utf-8")
    pipeline.chmod(0o000)
    if os.access(pipeline, os.R_OK):  # pragma: no cover - running as root, where chmod denies nothing
        pytest.skip("this user can read a 000 file, so the denial did not take")

    out = tmp_path / "out"
    proc = subprocess.run(
        [
            sys.executable,
            "-P",
            "-m",
            "oss_policy_kit",
            "evaluate",
            "--target",
            str(target),
            "--profile",
            "gitlab-level-1",
            "--output-dir",
            str(out),
            "--quiet",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=300,
        check=False,
    )
    pipeline.chmod(0o644)

    assert proc.returncode in (0, 1), f"exit {proc.returncode}: {proc.stderr[-400:]}"
    report = (out / "evaluation-report.json").read_text(encoding="utf-8")
    markdown = (out / "evaluation-report.md").read_text(encoding="utf-8")
    assert "could not be read (Permission denied)" in report
    assert json.loads(report)["controls"], "report carries no controls"
    for text in (report, markdown):
        assert str(target) not in text
        assert str(target.resolve()) not in text
