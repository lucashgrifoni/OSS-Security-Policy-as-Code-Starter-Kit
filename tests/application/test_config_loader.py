"""Tests for application/config_loader.py.

Coverage targets:

- Valid v1 config round-trips through ``load_project_config``.
- Missing file -> ``find_project_config`` returns None and the convenience
  loader yields None (rather than raising).
- Invalid YAML, wrong schema, missing required fields, and bad fail_on
  values all raise ``InvalidInputError`` with a helpful message.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from oss_policy_kit.application.config_loader import (
    CONFIG_FILENAME,
    SUPPORTED_SCHEMA_VERSIONS,
    find_project_config,
    load_project_config,
    load_project_config_for_target,
)
from oss_policy_kit.domain.errors import InvalidInputError


def _write(path: Path, body: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path


VALID_BODY = """\
schema_version: oss-policy-kit/config/v1
profile: github-level-1
profile_source: recommended
fail_on: fail
output_dir: "./oss-policy-reports"
report_json_contract: "1.0"
detected:
  platform: github
  primary_stack: "Python"
  signals:
    - github_actions_workflows
"""


def test_find_project_config_returns_none_when_missing(tmp_path: Path) -> None:
    assert find_project_config(tmp_path) is None


def test_find_project_config_returns_path_when_present(tmp_path: Path) -> None:
    cfg = _write(tmp_path / CONFIG_FILENAME, VALID_BODY)
    assert find_project_config(tmp_path) == cfg.resolve()


def test_load_valid_config(tmp_path: Path) -> None:
    cfg = _write(tmp_path / CONFIG_FILENAME, VALID_BODY)

    result = load_project_config(cfg)

    assert result.schema_version in SUPPORTED_SCHEMA_VERSIONS
    assert result.profile == "github-level-1"
    assert result.fail_on == "fail"
    assert result.output_dir == "./oss-policy-reports"
    assert result.report_json_contract == "1.0"
    assert result.detected_platform == "github"
    assert result.detected_primary_stack == "Python"


def test_load_for_target_returns_none_when_missing(tmp_path: Path) -> None:
    assert load_project_config_for_target(tmp_path) is None


def test_load_for_target_returns_config_when_present(tmp_path: Path) -> None:
    _write(tmp_path / CONFIG_FILENAME, VALID_BODY)
    result = load_project_config_for_target(tmp_path)
    assert result is not None
    assert result.profile == "github-level-1"


def test_invalid_yaml_raises(tmp_path: Path) -> None:
    cfg = _write(tmp_path / CONFIG_FILENAME, "not: valid: yaml: [\n")
    with pytest.raises(InvalidInputError) as exc:
        load_project_config(cfg)
    assert "invalid YAML" in exc.value.message


def test_unknown_schema_raises(tmp_path: Path) -> None:
    cfg = _write(
        tmp_path / CONFIG_FILENAME,
        "schema_version: oss-policy-kit/config/v999\nprofile: x\nfail_on: fail\noutput_dir: out\n",
    )
    with pytest.raises(InvalidInputError) as exc:
        load_project_config(cfg)
    assert "unsupported schema_version" in exc.value.message


def test_missing_profile_raises(tmp_path: Path) -> None:
    cfg = _write(
        tmp_path / CONFIG_FILENAME,
        "schema_version: oss-policy-kit/config/v1\nfail_on: fail\noutput_dir: out\n",
    )
    with pytest.raises(InvalidInputError) as exc:
        load_project_config(cfg)
    assert "profile" in exc.value.message


def test_invalid_fail_on_raises(tmp_path: Path) -> None:
    cfg = _write(
        tmp_path / CONFIG_FILENAME,
        "schema_version: oss-policy-kit/config/v1\nprofile: github-level-1\nfail_on: bogus\noutput_dir: out\n",
    )
    with pytest.raises(InvalidInputError) as exc:
        load_project_config(cfg)
    assert "fail_on" in exc.value.message


def test_root_must_be_mapping(tmp_path: Path) -> None:
    cfg = _write(tmp_path / CONFIG_FILENAME, "- not\n- a\n- mapping\n")
    with pytest.raises(InvalidInputError) as exc:
        load_project_config(cfg)
    assert "must be a mapping" in exc.value.message
