"""Branch-coverage gaps for application.profile_hints stack detection + based-on helpers."""

from __future__ import annotations

from pathlib import Path

from oss_policy_kit.application import profile_hints as ph


# --------------------------------------------------------------------------- #
# _detect_python_stack notes (lines 195, 197) + setup.py/cfg (203-204)
# --------------------------------------------------------------------------- #


def test_detect_python_stack_ruff_and_mypy_notes(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        "[tool.ruff]\nline-length = 120\n[tool.mypy]\nstrict = true\n", encoding="utf-8"
    )
    found: list[dict[str, str]] = []
    notes: list[str] = []
    assert ph._detect_python_stack(tmp_path, found, notes) == "Python"
    assert any("Ruff" in n for n in notes)
    assert any("Mypy" in n for n in notes)


def test_detect_python_stack_setup_py(tmp_path: Path) -> None:
    (tmp_path / "setup.cfg").write_text("[metadata]\nname = x\n", encoding="utf-8")
    found: list[dict[str, str]] = []
    assert ph._detect_python_stack(tmp_path, found, []) == "Python"
    assert any(s["id"] == "python_setup" for s in found)


# --------------------------------------------------------------------------- #
# _detect_simple_stacks (lines 227-228 go.mod, 230-231 .csproj)
# --------------------------------------------------------------------------- #


def test_detect_simple_stacks_go(tmp_path: Path) -> None:
    (tmp_path / "go.mod").write_text("module x\n", encoding="utf-8")
    found: list[dict[str, str]] = []
    assert ph._detect_simple_stacks(tmp_path, found, None) == "Go"


def test_detect_simple_stacks_dotnet(tmp_path: Path) -> None:
    (tmp_path / "app.csproj").write_text("<Project/>\n", encoding="utf-8")
    found: list[dict[str, str]] = []
    assert ph._detect_simple_stacks(tmp_path, found, None) == "C#/.NET"
    assert any(s["id"] == "dotnet_csproj" for s in found)


# --------------------------------------------------------------------------- #
# based-on hit/normalize helpers (lines 645, 662, 670, 679, 687)
# --------------------------------------------------------------------------- #


def test_bo_hit_unknown_names_return_false() -> None:
    assert ph._bo_hit("nope", [Path("w.yml")], []) is False
    assert ph._bo_hit_az("nope", [Path("a.yml")], []) is False
    assert ph._bo_hit_aws("nope", True, []) is False


def test_normalize_based_on_az_appends_evidence() -> None:
    out = ph._normalize_based_on_az([], [Path("a.yml")], [Path("e.json")])
    assert out[0] == "azure_pipelines_yaml" and "azure_evidence_json_files" in out


def test_normalize_based_on_aws_appends_evidence() -> None:
    out = ph._normalize_based_on_aws([], True, [Path("e.json")])
    assert out[0] == "aws_codebuild_buildspec" and "aws_evidence_json_files" in out
