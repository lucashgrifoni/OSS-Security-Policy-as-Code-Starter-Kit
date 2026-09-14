"""Fifteen Kubernetes controls scored 95% over a pod declaring `privileged: true`.

Measured against the built wheel:

    deploy/ok.yaml    a hardened Pod                     parses
    deploy/pod.yaml   tab-indented, `privileged: true`   does not parse

    evaluate --profile kubernetes-baseline-1 --fail-on fail
      Summary: fail=1  pass=16 | Controls: 17
      weighted_score  earned 38, possible 40, percent 95.0

Tabs are illegal for YAML indentation, so the file is broken and `kubectl apply` would refuse
it too. That is not the point. The point is that fifteen controls reported clean over it.

Alone, that same file already withdrew every verdict: `files_read == 0` is "nothing legible
here", which `absent_technology_outcome` has covered since the UTF-16 round. One readable
manifest beside it turns that off, and the partial scan is reported as a complete one.

`scan-iac` and `scan-bicep` were fixed by withdrawing the clean verdict over ANY unread
candidate, because every `.tf` is Terraform and every `.bicep` is Bicep. That reasoning does
not reach here. `scan-k8s` globs `**/*.yaml` and `**/*.yml` across the whole tree, most of what
it meets is not a manifest, and a guard that fired on all of it withdrew all 16 Kubernetes
controls on this kit's own repository, over scratch files and a fixture that is malformed on
purpose.

So the scanner now says something it already knew and was discarding: whether the text it
could not parse still read as its technology. `scan-cfn` has done this since it was written,
which is what `CfnParseError` means. `scan-k8s` and `scan-pulumi` recorded every failure
undifferentiated. Each parse-error entry gains a `resembles` key, and only a marked entry
withdraws a verdict.

The direction is what makes a raw-text sniff safe here. It can only make a verdict MORE
cautious: a commented-out `apiVersion:` over-withdraws, which is visible and actionable, and
it can never buy a PASS. That inverse is the failure `workflow_parser` shipped, where a
commented-out step earned one.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from oss_policy_kit.domain.models import ControlStatus

# --- the fixtures, all of them files a person would really commit -------------------------------

#: The reproduction. Tab indentation, which YAML forbids, in a Pod that runs privileged.
TAB_INDENTED_POD = (
    "apiVersion: v1\nkind: Pod\nmetadata:\n\tname: bad\n"
    "spec:\n\tcontainers:\n\t\t- name: c\n\t\t  image: nginx\n"
    "\t\t  securityContext:\n\t\t\tprivileged: true\n"
)

#: A GitHub Actions workflow with the same mistake. Same extension, same parser, not a manifest
#: -- and this is the shape that made the previous guard withdraw 16 controls on this repository.
TAB_INDENTED_WORKFLOW = "name: CI\non: push\njobs:\n\tbuild:\n\t\truns-on: ubuntu-latest\n"

HARDENED_POD = """apiVersion: v1
kind: Pod
metadata:
  name: good
  namespace: apps
spec:
  automountServiceAccountToken: false
  containers:
    - name: c
      image: nginx@sha256:aaaabbbbccccddddeeeeffff00001111222233334444555566667777888899990
      imagePullPolicy: Always
      securityContext:
        privileged: false
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        runAsNonRoot: true
        runAsUser: 1000
        capabilities:
          drop: ["ALL"]
      resources:
        limits: {cpu: "500m", memory: "256Mi"}
        requests: {cpu: "100m", memory: "128Mi"}
"""

BROKEN_PULUMI = "import pulumi_aws as aws\n\nb = aws.s3.Bucket('b', acl='public-read'\n"
BROKEN_PLAIN_PYTHON = "def f(:\n    pass\n"
GOOD_PULUMI = "import pulumi_aws as aws\n\nb = aws.s3.Bucket('b', acl='private')\n"

TAB_INDENTED_TEMPLATE = "AWSTemplateFormatVersion: '2010-09-09'\nResources:\n\tBucket:\n\t\tType: AWS::S3::Bucket\n"
GOOD_TEMPLATE = (
    "AWSTemplateFormatVersion: '2010-09-09'\n"
    "Resources:\n"
    "  Bucket:\n"
    "    Type: AWS::S3::Bucket\n"
    "    Properties:\n"
    "      BucketName: demo\n"
)


def _scan(root: Path, module_path: str) -> dict[str, Any]:
    """Drive the real scanner the way the `scan-*` command does, and return its evidence."""

    module = __import__(f"oss_policy_kit.infrastructure.{module_path}", fromlist=["_"])
    outcome = module.run_scan(root)
    payload = module.render_evidence_payload(outcome, target=root)
    module.write_evidence(payload, repo_root=root, filename=module.EVIDENCE_FILENAME)
    return payload


def _verdicts(root: Path, module_name: str, builder: str) -> dict[str, Any]:
    module = __import__(f"oss_policy_kit.application.{module_name}", fromlist=["_"])
    ctx = SimpleNamespace(repo_root=root)
    return {cid: fn(ctx) for cid, fn in getattr(module, builder)().items()}


# --- the mark itself ------------------------------------------------------------------------------


def test_the_scanner_separates_an_unparseable_manifest_from_any_other_unparseable_yaml(
    tmp_path: Path,
) -> None:
    """Both files break in exactly the same way. Only one of them is Kubernetes."""

    (tmp_path / "pod.yaml").write_text(TAB_INDENTED_POD, encoding="utf-8")
    (tmp_path / "ci.yaml").write_text(TAB_INDENTED_WORKFLOW, encoding="utf-8")
    (tmp_path / "ok.yaml").write_text(HARDENED_POD, encoding="utf-8")

    marks = {e["file"]: e.get("resembles") for e in _scan(tmp_path, "k8s.scanner")["diagnostics"]["parse_errors"]}

    assert marks == {"pod.yaml": "kubernetes-manifest", "ci.yaml": None}


def test_the_pulumi_scanner_separates_a_program_from_an_ordinary_broken_module(tmp_path: Path) -> None:
    (tmp_path / "__main__.py").write_text(BROKEN_PULUMI, encoding="utf-8")
    (tmp_path / "util.py").write_text(BROKEN_PLAIN_PYTHON, encoding="utf-8")

    marks = {
        e["file"]: e.get("resembles") for e in _scan(tmp_path, "iac.pulumi.scanner")["diagnostics"]["parse_errors"]
    }

    assert marks == {"__main__.py": "pulumi-program", "util.py": None}


def test_the_cfn_scanner_writes_down_the_distinction_it_already_made(tmp_path: Path) -> None:
    """`CfnParseError` has always meant "a template I could not read". It just never said so."""

    (tmp_path / "tpl.yaml").write_text(TAB_INDENTED_TEMPLATE, encoding="utf-8")
    (tmp_path / "ci.yaml").write_text(TAB_INDENTED_WORKFLOW, encoding="utf-8")

    errors = _scan(tmp_path, "iac.cfn.scanner")["diagnostics"]["parse_errors"]

    assert {e["file"]: e.get("resembles") for e in errors} == {"tpl.yaml": "cloudformation-template"}
    assert "ci.yaml" not in {e["file"] for e in errors}, "a non-template was never an error here"


# --- and what the evaluators do with it ------------------------------------------------------------


def test_a_privileged_pod_the_parser_refused_is_not_a_clean_cluster(tmp_path: Path) -> None:
    """The reproduction, end to end. Fifteen controls said PASS and the score said 95%."""

    deploy = tmp_path / "deploy"
    deploy.mkdir()
    (deploy / "pod.yaml").write_text(TAB_INDENTED_POD, encoding="utf-8")
    (deploy / "ok.yaml").write_text(HARDENED_POD, encoding="utf-8")
    _scan(tmp_path, "k8s.scanner")

    outcomes = _verdicts(tmp_path, "evaluators_k8s", "build_k8s_evaluators")
    states = Counter(o.status for o in outcomes.values())

    assert states[ControlStatus.PASS] == 0, f"a control still reported clean: {dict(states)}"
    assert "deploy/pod.yaml" in outcomes["K8S-PSS-001"].reason


def test_a_broken_workflow_beside_a_manifest_changes_nothing(tmp_path: Path) -> None:
    """The false positive that got the previous attempt reverted, in its exact shape.

    A `.yaml` that fails to parse and is not a manifest is an ordinary thing for a repository
    to contain. This one is a workflow; on the kit's own tree it is a fixture that is malformed
    on purpose. Either way the Kubernetes controls have nothing to withdraw.
    """

    deploy = tmp_path / "deploy"
    deploy.mkdir()
    (deploy / "ok.yaml").write_text(HARDENED_POD, encoding="utf-8")
    (tmp_path / "ci.yaml").write_text(TAB_INDENTED_WORKFLOW, encoding="utf-8")
    data = _scan(tmp_path, "k8s.scanner")

    assert data["diagnostics"]["parse_errors"], "the harness is wrong: that file was meant to fail"

    states = Counter(o.status for o in _verdicts(tmp_path, "evaluators_k8s", "build_k8s_evaluators").values())

    assert states[ControlStatus.MANUAL_REVIEW_REQUIRED] == 0, (
        f"an unparseable file that is not a manifest withdrew Kubernetes verdicts: {dict(states)}"
    )


def test_this_repository_keeps_every_kubernetes_verdict_it_has(tmp_path: Path) -> None:
    """The fence around the regression that made attempt two worse than the bug.

    The kit's own tree holds exactly one unparseable YAML file, a deliberately-broken workflow
    fixture, and every Kubernetes control has to keep its verdict over it. Measured on the real
    tree rather than argued, because this is the case that was got wrong before.

    The evidence is written into `tmp_path` instead of the repository, so running the suite
    never leaves a scan behind in the tree it just scanned.
    """

    repo_root = Path(__file__).resolve().parents[2]
    from oss_policy_kit.infrastructure.k8s import scanner as k8s

    payload = k8s.render_evidence_payload(k8s.run_scan(repo_root), target=repo_root)
    k8s.write_evidence(payload, repo_root=tmp_path, filename=k8s.EVIDENCE_FILENAME)

    states = Counter(o.status for o in _verdicts(tmp_path, "evaluators_k8s", "build_k8s_evaluators").values())
    assert states[ControlStatus.MANUAL_REVIEW_REQUIRED] == 0, (
        f"this repository had Kubernetes verdicts withdrawn over its own broken fixture: {dict(states)}"
    )

    marked = [e["file"] for e in payload["diagnostics"]["parse_errors"] if e.get("resembles")]

    assert marked == [], f"a file in this repository was read as an unchecked manifest: {marked}"


def test_a_real_finding_survives_an_unread_manifest(tmp_path: Path) -> None:
    """A withdrawal may replace a PASS and never a FAIL.

    `manual-review-required` does not trip `--fail-on fail`, so turning a red control into one
    would take a failing pipeline green. Unread sources can only add violations, never subtract
    them, so an existing FAIL is never less true.
    """

    deploy = tmp_path / "deploy"
    deploy.mkdir()
    (deploy / "pod.yaml").write_text(TAB_INDENTED_POD, encoding="utf-8")
    (deploy / "ok.yaml").write_text(HARDENED_POD, encoding="utf-8")
    _scan(tmp_path, "k8s.scanner")

    outcomes = _verdicts(tmp_path, "evaluators_k8s", "build_k8s_evaluators")

    assert outcomes["K8S-NETPOL-001"].status == ControlStatus.FAIL, (
        f"the namespace-without-NetworkPolicy finding was withdrawn: {outcomes['K8S-NETPOL-001'].status.value}"
    )


def test_an_unread_pulumi_program_withdraws_and_a_broken_script_does_not(tmp_path: Path) -> None:
    """Both halves in one test, because one without the other is the wrong fix."""

    (tmp_path / "__main__.py").write_text(GOOD_PULUMI, encoding="utf-8")
    (tmp_path / "util.py").write_text(BROKEN_PLAIN_PYTHON, encoding="utf-8")
    _scan(tmp_path, "iac.pulumi.scanner")
    states = Counter(
        o.status for o in _verdicts(tmp_path, "evaluators_iac_pulumi", "build_iac_pulumi_evaluators").values()
    )
    assert states[ControlStatus.MANUAL_REVIEW_REQUIRED] == 0, (
        f"a broken script withdrew Pulumi verdicts: {dict(states)}"
    )

    (tmp_path / "stack.py").write_text(BROKEN_PULUMI, encoding="utf-8")
    _scan(tmp_path, "iac.pulumi.scanner")
    states = Counter(
        o.status for o in _verdicts(tmp_path, "evaluators_iac_pulumi", "build_iac_pulumi_evaluators").values()
    )
    assert states[ControlStatus.PASS] == 0, f"a control reported clean over an unread program: {dict(states)}"


def test_an_unread_cloudformation_template_withdraws_the_clean_verdict(tmp_path: Path) -> None:
    (tmp_path / "good.yaml").write_text(GOOD_TEMPLATE, encoding="utf-8")
    (tmp_path / "bad.yaml").write_text(TAB_INDENTED_TEMPLATE, encoding="utf-8")
    _scan(tmp_path, "iac.cfn.scanner")

    outcomes = _verdicts(tmp_path, "evaluators_iac_cfn", "build_iac_cfn_evaluators")
    states = Counter(o.status for o in outcomes.values())

    assert states[ControlStatus.PASS] == 0, f"a control reported clean over an unread template: {dict(states)}"


def test_every_withdrawal_points_at_the_escape_hatch(tmp_path: Path) -> None:
    """ADR-045: this state is not a verdict, and an operator has to be able to gate on it."""

    deploy = tmp_path / "deploy"
    deploy.mkdir()
    (deploy / "pod.yaml").write_text(TAB_INDENTED_POD, encoding="utf-8")
    (deploy / "ok.yaml").write_text(HARDENED_POD, encoding="utf-8")
    _scan(tmp_path, "k8s.scanner")

    assert (
        "--fail-on degraded" in _verdicts(tmp_path, "evaluators_k8s", "build_k8s_evaluators")["K8S-PSS-001"].remediation
    )


# --- the sniff itself, at its edges ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("label", "text", "expected"),
    [
        ("both markers", "apiVersion: v1\nkind: Pod\n{", True),
        ("indented markers", "  apiVersion: v1\n  kind: Pod\n{", True),
        ("tab-indented markers", "\tapiVersion: v1\n\tkind: Pod\n{", True),
        ("no space before colon", "apiVersion:v1\nkind:Pod\n{", True),
        ("apiVersion only", "apiVersion: v1\nfoo: bar\n{", False),
        ("kind only", "kind: Pod\nfoo: bar\n{", False),
        ("neither", "name: CI\non: push\n{", False),
        # Mid-line is a value, not a key. `image: apiVersion:kind:` is not a manifest.
        ("markers only mid-line", "image: apiVersion kind\n{", False),
    ],
)
def test_the_manifest_sniff_at_its_edges(label: str, text: str, expected: bool) -> None:
    from oss_policy_kit.infrastructure.k8s.scanner import _resembles_manifest

    assert _resembles_manifest(text) is expected, label


def test_the_pulumi_sniff_reads_bytes_the_way_the_interpreter_would() -> None:
    """A PEP 263 latin-1 module is legal Python, so its import line has to be found in it.

    Arbitrary bytes answer False because nothing in them reads as an import, not because the
    decode failed. `decode_source` returns text for any input by contract, which is why the
    sniff carries no exception handler: coverage flagged the one this arrived with as a branch
    no input can reach.
    """

    from oss_policy_kit.infrastructure.iac.pulumi.scanner import _resembles_pulumi_program

    assert _resembles_pulumi_program(b"import pulumi\n") is True
    assert _resembles_pulumi_program("from pulumi_aws import s3\n") is True
    assert _resembles_pulumi_program(b"# -*- coding: latin-1 -*-\n# caf\xe9\nimport pulumi\n") is True
    assert _resembles_pulumi_program("import boto3\n") is False
    assert _resembles_pulumi_program(b"\xff\xfe\x00" * 8) is False


def test_evidence_written_before_the_key_existed_still_reads() -> None:
    """No migration, and no silent change of meaning for an old file.

    A parse-error entry with no `resembles` key is what every scanner wrote until now. Under a
    filter it counts for nothing, which restores exactly the previous behaviour rather than
    withdrawing verdicts across a fleet the moment this ships.
    """

    from oss_policy_kit.application._evidence_rules import unread_sources

    data = {"diagnostics": {"parse_errors": [{"file": "old.yaml", "error": "boom"}]}}

    assert unread_sources(data) == (["old.yaml"], 1), "unfiltered, an old entry still counts"
    assert unread_sources(data, only_resembling="kubernetes-manifest") == ([], 0)


def test_the_withdrawal_does_not_pass_off_a_truncated_list_as_a_complete_one(tmp_path: Path) -> None:
    """Five unread manifests must not be reported as the three the message has room for."""

    deploy = tmp_path / "deploy"
    deploy.mkdir()
    (deploy / "ok.yaml").write_text(HARDENED_POD, encoding="utf-8")
    for n in range(5):
        (deploy / f"bad{n}.yaml").write_text(TAB_INDENTED_POD, encoding="utf-8")
    _scan(tmp_path, "k8s.scanner")

    reason = _verdicts(tmp_path, "evaluators_k8s", "build_k8s_evaluators")["K8S-PSS-002"].reason

    assert "and 2 more" in reason, reason


def test_the_evidence_json_is_where_a_ci_consumer_can_see_it(tmp_path: Path) -> None:
    """The mark has to survive the round trip to disk, or the evaluator is reading its own memory."""

    deploy = tmp_path / "deploy"
    deploy.mkdir()
    (deploy / "pod.yaml").write_text(TAB_INDENTED_POD, encoding="utf-8")
    (deploy / "ok.yaml").write_text(HARDENED_POD, encoding="utf-8")
    _scan(tmp_path, "k8s.scanner")

    written = json.loads((tmp_path / ".oss-policy-kit" / "evidence" / "k8s-baseline.json").read_text(encoding="utf-8"))

    assert [e.get("resembles") for e in written["diagnostics"]["parse_errors"]] == ["kubernetes-manifest"]
