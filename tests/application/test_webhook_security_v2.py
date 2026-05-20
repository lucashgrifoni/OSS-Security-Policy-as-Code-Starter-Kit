"""SEC-WEBHOOK-HMAC-001..ROTATE-006 family (PR-5, ADR-004) coverage."""

from __future__ import annotations

from pathlib import Path

import pytest

from oss_policy_kit.application.evaluators_webhook import (
    eval_sec_webhook_body_004,
    eval_sec_webhook_hmac_001,
    eval_sec_webhook_idemp_005,
    eval_sec_webhook_replay_003,
    eval_sec_webhook_rotate_006,
    eval_sec_webhook_timing_002,
)
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis


class _Ctx:
    """Minimal duck-typed context exposing ``repo_root`` (which is all _scan_signals needs)."""

    def __init__(self, repo_root: Path) -> None:
        self.repo_root = repo_root
        self.workflows = WorkflowAnalysis()
        self.azure_pipelines = AzurePipelineAnalysis()
        self.aws_ci = AwsCiAnalysis()
        self.scorecard = None


def _write_py(tmp_path: Path, name: str, body: str) -> Path:
    p = tmp_path / name
    p.write_text(body, encoding="utf-8")
    return p


_WEBHOOK_ROUTE_PY = (
    "from fastapi import FastAPI, Request\n"
    "app = FastAPI()\n\n"
    "@app.post('/webhook')\n"
    "async def handle_webhook(request: Request):\n"
    "    ...\n"
)


_ALL_EVALUATORS = [
    eval_sec_webhook_hmac_001,
    eval_sec_webhook_timing_002,
    eval_sec_webhook_replay_003,
    eval_sec_webhook_body_004,
    eval_sec_webhook_idemp_005,
    eval_sec_webhook_rotate_006,
]


@pytest.mark.parametrize("fn", _ALL_EVALUATORS, ids=lambda x: x.__name__)
def test_not_applicable_when_no_webhook_route(fn, tmp_path: Path) -> None:
    """Without any webhook route, every v6 SEC-WEBHOOK-* control returns NOT_APPLICABLE."""
    _write_py(tmp_path, "main.py", "def add(a, b): return a + b\n")
    out = fn(_Ctx(tmp_path))
    assert out.status == ControlStatus.NOT_APPLICABLE


@pytest.mark.parametrize("fn", _ALL_EVALUATORS, ids=lambda x: x.__name__)
def test_manual_review_when_route_present_but_primitive_missing(fn, tmp_path: Path) -> None:
    """A webhook route with no security primitive → MANUAL_REVIEW_REQUIRED."""
    _write_py(tmp_path, "main.py", _WEBHOOK_ROUTE_PY)
    out = fn(_Ctx(tmp_path))
    assert out.status == ControlStatus.MANUAL_REVIEW_REQUIRED


def test_hmac_pass_when_hmac_helper_present(tmp_path: Path) -> None:
    _write_py(
        tmp_path,
        "main.py",
        _WEBHOOK_ROUTE_PY
        + "\nimport hmac\n"
        + "def verify_signature(payload, sig, secret):\n"
        + "    expected = hmac.new(secret, payload, 'sha256').hexdigest()\n"
        + "    return hmac.compare_digest(expected, sig)\n",
    )
    out = eval_sec_webhook_hmac_001(_Ctx(tmp_path))
    assert out.status == ControlStatus.PASS
    assert "HMAC verification" in out.reason


def test_timing_pass_when_timing_safe_primitive_present(tmp_path: Path) -> None:
    _write_py(
        tmp_path,
        "main.py",
        _WEBHOOK_ROUTE_PY + "\nimport hmac\n" + "ok = hmac.compare_digest(a, b)\n",
    )
    out = eval_sec_webhook_timing_002(_Ctx(tmp_path))
    assert out.status == ControlStatus.PASS
    assert "timing-safe" in out.reason


def test_replay_pass_when_timestamp_check_present(tmp_path: Path) -> None:
    _write_py(
        tmp_path,
        "main.py",
        _WEBHOOK_ROUTE_PY
        + "\nimport time\n"
        + "def is_fresh(headers):\n"
        + "    ts = int(headers.get('X-Webhook-Timestamp', 0))\n"
        + "    return abs(time.time() - ts) < 300  # tolerance\n",
    )
    out = eval_sec_webhook_replay_003(_Ctx(tmp_path))
    assert out.status == ControlStatus.PASS


def test_body_pass_when_framework_cap_present(tmp_path: Path) -> None:
    _write_py(
        tmp_path,
        "server.js",
        "const express = require('express');\n"
        + "const app = express();\n"
        + "app.use(express.json({ limit: '1mb' }));\n"
        + "app.post('/webhook', (req, res) => res.sendStatus(200));\n",
    )
    out = eval_sec_webhook_body_004(_Ctx(tmp_path))
    assert out.status == ControlStatus.PASS


def test_idemp_pass_when_idempotency_key_extracted(tmp_path: Path) -> None:
    _write_py(
        tmp_path,
        "main.py",
        _WEBHOOK_ROUTE_PY
        + "\ndef handle(request):\n"
        + "    delivery_id = request.headers.get('X-GitHub-Delivery')\n"
        + "    if redis.set(f'evt:{delivery_id}', '1', nx=True, ex=86400):\n"
        + "        ...\n",
    )
    out = eval_sec_webhook_idemp_005(_Ctx(tmp_path))
    assert out.status == ControlStatus.PASS


def test_rotate_pass_when_env_sourced_and_rotation_pattern(tmp_path: Path) -> None:
    _write_py(
        tmp_path,
        "main.py",
        _WEBHOOK_ROUTE_PY
        + "\nimport os\n"
        + "current_secret = os.environ['WEBHOOK_SECRET']\n"
        + "previous_secret = os.environ.get('WEBHOOK_SECRET_PREVIOUS')\n"
        + "def verify(sig, body):\n"
        + "    return any(verify_with(s, sig, body) for s in (current_secret, previous_secret) if s)\n",
    )
    out = eval_sec_webhook_rotate_006(_Ctx(tmp_path))
    assert out.status == ControlStatus.PASS


def test_rotate_manual_review_when_env_only_without_rotation(tmp_path: Path) -> None:
    _write_py(
        tmp_path,
        "main.py",
        _WEBHOOK_ROUTE_PY + "\nimport os\nsecret = os.environ['WEBHOOK_SECRET']\n",
    )
    out = eval_sec_webhook_rotate_006(_Ctx(tmp_path))
    assert out.status == ControlStatus.MANUAL_REVIEW_REQUIRED
    assert "rotation" in out.reason.lower()
