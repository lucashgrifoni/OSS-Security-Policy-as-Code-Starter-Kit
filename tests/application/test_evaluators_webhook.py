"""Tests for the v5.7.0 ``SEC-WEBHOOK-*`` controls."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from oss_policy_kit.application.evaluators import EVALUATOR_REGISTRY
from oss_policy_kit.application.evaluators_webhook import (
    eval_sec_webhook_001,
    eval_sec_webhook_002,
)
from oss_policy_kit.application.loader import bundled_kit_root, load_catalog, load_profile_by_id
from oss_policy_kit.domain.models import ControlStatus


def test_webhook_controls_present_in_catalog() -> None:
    catalog = load_catalog(bundled_kit_root() / "controls" / "catalog.yaml")
    for rid in ("SEC-WEBHOOK-001", "SEC-WEBHOOK-002"):
        assert rid in catalog
        spec = catalog[rid]
        assert spec.lifecycle == "experimental"
        assert spec.assurance == "signal"
        assert spec.category == "secure_development"


def test_webhook_controls_have_evaluators() -> None:
    for rid in ("SEC-WEBHOOK-001", "SEC-WEBHOOK-002"):
        assert rid in EVALUATOR_REGISTRY


def test_webhook_security_1_profile_loads() -> None:
    spec = load_profile_by_id(bundled_kit_root(), "webhook-security-1")
    assert spec.id == "webhook-security-1"
    assert "SEC-WEBHOOK-001" in spec.control_ids
    assert "SEC-WEBHOOK-002" in spec.control_ids


def test_no_webhook_route_returns_not_applicable(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text("def hello():\n    return 'world'\n", encoding="utf-8")
    out = eval_sec_webhook_001(SimpleNamespace(repo_root=tmp_path))
    assert out.status is ControlStatus.NOT_APPLICABLE
    out2 = eval_sec_webhook_002(SimpleNamespace(repo_root=tmp_path))
    assert out2.status is ControlStatus.NOT_APPLICABLE


def test_webhook_with_signature_passes_001(tmp_path: Path) -> None:
    (tmp_path / "server.py").write_text(
        "from fastapi import FastAPI, Request, HTTPException\n"
        "import hmac, hashlib\n"
        "app = FastAPI()\n"
        "@app.post('/webhook')\n"
        "async def handler(request: Request):\n"
        "    sig = request.headers.get('X-Hub-Signature-256')\n"
        "    body = await request.body()\n"
        "    expected = 'sha256=' + hmac.new(b'secret', body, hashlib.sha256).hexdigest()\n"
        "    if not hmac.compare_digest(sig or '', expected):\n"
        "        raise HTTPException(status_code=401)\n",
        encoding="utf-8",
    )
    out = eval_sec_webhook_001(SimpleNamespace(repo_root=tmp_path))
    assert out.status is ControlStatus.PASS


def test_webhook_without_signature_returns_mrr_001(tmp_path: Path) -> None:
    (tmp_path / "server.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n@app.post('/webhook')\nasync def handler():\n    return {}\n",
        encoding="utf-8",
    )
    out = eval_sec_webhook_001(SimpleNamespace(repo_root=tmp_path))
    assert out.status is ControlStatus.MANUAL_REVIEW_REQUIRED


def test_webhook_with_replay_defense_passes_002(tmp_path: Path) -> None:
    (tmp_path / "server.py").write_text(
        "from fastapi import FastAPI, Request, HTTPException\n"
        "app = FastAPI()\n"
        "SEEN: set[str] = set()\n"
        "@app.post('/webhook')\n"
        "async def handler(request: Request):\n"
        "    delivery_id = request.headers.get('X-GitHub-Delivery')\n"
        "    if delivery_id in SEEN:\n"
        "        raise HTTPException(status_code=409)\n"
        "    SEEN.add(delivery_id)\n",
        encoding="utf-8",
    )
    out = eval_sec_webhook_002(SimpleNamespace(repo_root=tmp_path))
    assert out.status is ControlStatus.PASS


def test_webhook_without_replay_returns_mrr_002(tmp_path: Path) -> None:
    (tmp_path / "server.py").write_text(
        "import hmac\n"
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@app.post('/webhook')\n"
        "async def handler():\n"
        "    return {}\n",
        encoding="utf-8",
    )
    out = eval_sec_webhook_002(SimpleNamespace(repo_root=tmp_path))
    assert out.status is ControlStatus.MANUAL_REVIEW_REQUIRED
