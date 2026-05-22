"""Coverage for the ``run_scan`` rule-engine error path in each IaC scanner.

When a rule helper raises, ``run_scan`` must catch it and return a structured
``status='error'`` outcome (never crash the caller). Monkeypatching ``_RULES``
to a raising rule exercises that defensive branch deterministically.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from oss_policy_kit.infrastructure.iac import scanner as tf
from oss_policy_kit.infrastructure.iac.bicep import scanner as bicep
from oss_policy_kit.infrastructure.iac.cfn import scanner as cfn
from oss_policy_kit.infrastructure.iac.pulumi import scanner as pulumi


def _raising_rule(*_args: object) -> list:
    raise RuntimeError("synthetic rule failure")


_RAISING_RULES = (("X-RAISE", _raising_rule),)


def test_cfn_run_scan_error_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "stack.json").write_text('{"Resources": {"B": {"Type": "AWS::S3::Bucket"}}}', encoding="utf-8")
    monkeypatch.setattr(cfn, "_RULES", _RAISING_RULES)
    outcome = cfn.run_scan(tmp_path)
    assert outcome.status == "error"
    assert "RuntimeError" in (outcome.diagnostics or "")


def test_pulumi_run_scan_error_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "infra.py").write_text("import pulumi_aws as aws\naws.s3.Bucket('b')\n", encoding="utf-8")
    monkeypatch.setattr(pulumi, "_RULES", _RAISING_RULES)
    outcome = pulumi.run_scan(tmp_path)
    assert outcome.status == "error"
    assert "RuntimeError" in (outcome.diagnostics or "")


def test_bicep_run_scan_error_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "main.bicep").write_text(
        "resource sa 'Microsoft.Storage/storageAccounts@2023-01-01' = {\n  name: 'x'\n}\n", encoding="utf-8"
    )
    monkeypatch.setattr(bicep, "_RULES", _RAISING_RULES)
    outcome = bicep.run_scan(tmp_path)
    assert outcome.status == "error"
    assert "RuntimeError" in (outcome.diagnostics or "")


def test_tf_run_scan_error_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "x" {}\n', encoding="utf-8")
    monkeypatch.setattr(tf, "_RULES", _RAISING_RULES)
    outcome = tf.run_scan(tmp_path)
    assert outcome.status == "error"
    assert "RuntimeError" in (outcome.diagnostics or "")
