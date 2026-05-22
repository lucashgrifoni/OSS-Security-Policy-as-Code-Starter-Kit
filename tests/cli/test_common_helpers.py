"""Unit tests for pure helpers in ``cli.common`` (format normalization, warnings, argv prep)."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from oss_policy_kit.cli import common
from oss_policy_kit.domain.errors import InvalidInputError


# --------------------------------------------------------------------------- #
# format normalization
# --------------------------------------------------------------------------- #


def test_normalize_evaluate_format() -> None:
    assert common.normalize_evaluate_format("json") == "json"
    for alias in ("human", "table", "compact", "detailed", "HUMAN"):
        assert common.normalize_evaluate_format(alias) == "human"
    with pytest.raises(InvalidInputError):
        common.normalize_evaluate_format("xml")


def test_normalize_profiles_format() -> None:
    assert common.normalize_profiles_format("human") == "compact"
    assert common.normalize_profiles_format("verbose") == "detailed"
    for v in ("detailed", "compact", "table", "json"):
        assert common.normalize_profiles_format(v) == v
    with pytest.raises(InvalidInputError):
        common.normalize_profiles_format("yaml")


def test_normalize_recommend_format() -> None:
    for v in ("human", "table", "compact"):
        assert common.normalize_recommend_format(v) == "human"
    assert common.normalize_recommend_format("json") == "json"
    with pytest.raises(InvalidInputError):
        common.normalize_recommend_format("xml")


# --------------------------------------------------------------------------- #
# debug logging + stdout writers
# --------------------------------------------------------------------------- #


def test_enable_debug_logging_idempotent() -> None:
    logger = logging.getLogger("oss_policy_kit")
    before = len(logger.handlers)
    common.enable_debug_logging()
    common.enable_debug_logging()  # second call must not add a duplicate handler
    debug_handlers = [h for h in logger.handlers if getattr(h, "_oss_policy_kit_debug", False)]
    assert len(debug_handlers) == 1
    assert logger.level == logging.DEBUG
    assert len(logger.handlers) >= before


def test_write_stdout_text(capsys: pytest.CaptureFixture[str]) -> None:
    common.write_stdout_text("hello\n")
    assert "hello" in capsys.readouterr().out


def test_write_wrapped_stdout_block(capsys: pytest.CaptureFixture[str]) -> None:
    common.write_wrapped_stdout_block("> ", "word " * 60, "  ")
    out = capsys.readouterr().out
    assert out.startswith("> ")
    assert out.count("\n") >= 1


def test_write_wrapped_stdout_block_empty(capsys: pytest.CaptureFixture[str]) -> None:
    common.write_wrapped_stdout_block("> ", "", "  ")
    assert capsys.readouterr().out == ""


# --------------------------------------------------------------------------- #
# batch / operational warnings
# --------------------------------------------------------------------------- #


def test_warn_if_batch_skipped_directories(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    p = tmp_path / "batch.json"
    p.write_text(json.dumps({"skipped_directories": ["a", "b"]}), encoding="utf-8")
    common.warn_if_batch_skipped_directories(p)
    assert "Skipped 2 directories" in capsys.readouterr().err


def test_warn_if_batch_skipped_singular(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    p = tmp_path / "batch.json"
    p.write_text(json.dumps({"skipped_directories": ["a"]}), encoding="utf-8")
    common.warn_if_batch_skipped_directories(p)
    assert "Skipped 1 directory" in capsys.readouterr().err


def test_warn_if_batch_skipped_none_and_missing(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    common.warn_if_batch_skipped_directories(tmp_path / "missing.json")  # silent
    p = tmp_path / "batch.json"
    p.write_text(json.dumps({"skipped_directories": []}), encoding="utf-8")
    common.warn_if_batch_skipped_directories(p)
    assert capsys.readouterr().err == ""


def test_print_operational_warning_summary(capsys: pytest.CaptureFixture[str]) -> None:
    common.print_operational_warning_summary([])
    assert capsys.readouterr().err == ""
    common.print_operational_warning_summary(["w1 " * 40, "w2", "w3", "w4"])
    assert "Operational warnings" in capsys.readouterr().err


# --------------------------------------------------------------------------- #
# argv preparation + scan-evidence warning
# --------------------------------------------------------------------------- #


def test_prepare_cli_args() -> None:
    assert common.prepare_cli_args([]) == []
    assert common.prepare_cli_args(["evaluate", "x"]) == ["evaluate", "x"]
    assert common.prepare_cli_args(["--help"]) == ["--help"]
    assert common.prepare_cli_args(["--profile", "p"]) == ["--profile", "p"]
    assert common.prepare_cli_args(["./repo", "-p", "x"]) == ["evaluate", "./repo", "-p", "x"]


def test_warn_missing_scan_evidence(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # machine_stdout -> silent.
    common._warn_missing_scan_evidence(tmp_path, {"K8S-001"}, True)
    assert capsys.readouterr().err == ""
    # Missing evidence for a bundled scan control -> banner.
    common._warn_missing_scan_evidence(tmp_path, {"K8S-001"}, False)
    assert "scan-k8s" in capsys.readouterr().err
    # Evidence present -> no banner.
    ev = tmp_path / ".oss-policy-kit" / "evidence"
    ev.mkdir(parents=True)
    (ev / "k8s-baseline.json").write_text("{}", encoding="utf-8")
    common._warn_missing_scan_evidence(tmp_path, {"K8S-001"}, False)
    assert capsys.readouterr().err == ""
