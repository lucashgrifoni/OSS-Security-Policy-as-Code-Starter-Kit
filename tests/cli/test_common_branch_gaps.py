"""Branch-coverage gaps for cli.common helper functions and error dispatch."""

from __future__ import annotations

from pathlib import Path

import pytest
import typer

from oss_policy_kit.cli import common
from oss_policy_kit.domain.errors import InvalidInputError


def _req(tmp_path: Path, **overrides) -> common.EvaluateRequest:
    base = dict(
        target_pos=None,
        target_opt=str(tmp_path),
        profile="github-level-2",
        output_dir=tmp_path / "out",
        waivers=None,
        scorecard_json=None,
        kit_root=None,
        output_format="table",
        summary_only=False,
        fail_on="none",
    )
    base.update(overrides)
    return common.EvaluateRequest(**base)


# --------------------------------------------------------------------------- #
# write_stdout_text UnicodeEncodeError fallback (lines 102-107)
# --------------------------------------------------------------------------- #


def test_write_stdout_text_unicode_fallback(monkeypatch) -> None:
    class _FakeBuffer:
        def __init__(self) -> None:
            self.data = b""

        def write(self, b: bytes) -> None:
            self.data += b

        def flush(self) -> None:
            pass

    class _FakeStdout:
        def __init__(self) -> None:
            self.buffer = _FakeBuffer()

        def write(self, _text: str) -> None:
            raise UnicodeEncodeError("utf-8", "x", 0, 1, "boom")

    fake = _FakeStdout()
    monkeypatch.setattr(common.sys, "stdout", fake)
    common.write_stdout_text("héllo ✓")
    assert fake.buffer.data  # bytes were written via the fallback path


# --------------------------------------------------------------------------- #
# _resolve_eval_target missing target (line 306)
# --------------------------------------------------------------------------- #


def test_resolve_eval_target_missing(tmp_path: Path) -> None:
    req = _req(tmp_path, target_opt=None, target_pos=None)
    with pytest.raises(InvalidInputError):
        common._resolve_eval_target(req)


# --------------------------------------------------------------------------- #
# _load_eval_waivers parse path (line 333) + not-found (line 332)
# --------------------------------------------------------------------------- #


def test_load_eval_waivers_parses_existing(tmp_path: Path) -> None:
    wf = tmp_path / "waivers.yaml"
    wf.write_text(
        "version: 1\nwaivers:\n  - control_id: GOV-SEC-001\n"
        '    justification: "reviewed and accepted by appsec"\n'
        '    owner: "a@b.com"\n    status: approved\n',
        encoding="utf-8",
    )
    out = common._load_eval_waivers(wf)
    assert out is not None


def test_load_eval_waivers_not_found(tmp_path: Path) -> None:
    with pytest.raises(InvalidInputError):
        common._load_eval_waivers(tmp_path / "missing.yaml")


# --------------------------------------------------------------------------- #
# _run_evaluate invalid --fail-on (line 436)
# --------------------------------------------------------------------------- #


def test_run_evaluate_invalid_fail_on(tmp_path: Path) -> None:
    req = _req(tmp_path, fail_on="bogus")
    with pytest.raises(InvalidInputError):
        common._run_evaluate(req)


# --------------------------------------------------------------------------- #
# execute_evaluate unexpected-error dispatch (lines 484-486)
# --------------------------------------------------------------------------- #


def test_execute_evaluate_unexpected_error(tmp_path: Path, monkeypatch) -> None:
    def _boom(_req) -> None:
        raise RuntimeError("kaboom")

    monkeypatch.setattr(common, "_run_evaluate", _boom)
    with pytest.raises(typer.Exit) as exc:
        common.execute_evaluate(_req(tmp_path))
    assert exc.value.exit_code == 3
