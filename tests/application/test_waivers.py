"""Waiver parsing and expiry."""

from pathlib import Path

from tests.conftest import ROOT

from oss_policy_kit.application.waivers import parse_waivers_file


def test_expired_waiver_ignored(tmp_path: Path) -> None:
    p = tmp_path / "w.yaml"
    p.write_text(
        """
version: 1
waivers:
  - control_id: CI-DANGER-007
    justification: "legacy"
    owner: "a@b.com"
    status: approved
    expires_at: "2000-01-01"
""",
        encoding="utf-8",
    )
    out = parse_waivers_file(p)
    assert "CI-DANGER-007" not in out.by_control
    assert any("expired" in w.lower() for w in out.warnings)


def test_invalid_justification_skipped(tmp_path: Path) -> None:
    p = tmp_path / "w.yaml"
    p.write_text(
        """
version: 1
waivers:
  - control_id: X
    justification: ""
    owner: "a@b.com"
""",
        encoding="utf-8",
    )
    out = parse_waivers_file(p)
    assert "X" not in out.by_control


def test_example_waiver_file_loads() -> None:
    path = ROOT / "waivers" / "waivers.example.yaml"
    out = parse_waivers_file(path)
    assert "CI-DANGER-007" in out.by_control


# --------------------------------------------------------------------------- #
# Additional branch coverage (helpers + parse error paths)
# --------------------------------------------------------------------------- #

from datetime import date  # noqa: E402

import pytest  # noqa: E402

from oss_policy_kit.application import waivers as _w  # noqa: E402
from oss_policy_kit.domain.errors import LoadError  # noqa: E402


def _yaml(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "w.yaml"
    p.write_text(text, encoding="utf-8")
    return p


def test_parse_date_variants() -> None:
    assert _w._parse_date(None) is None
    assert _w._parse_date(date(2030, 1, 1)) == date(2030, 1, 1)
    assert _w._parse_date("2030-01-01T10:00:00") == date(2030, 1, 1)
    assert _w._parse_date(123) is None


def test_waiver_applies_to() -> None:
    assert _w._waiver_applies_to(["A", "B"]) == ["A", "B"]
    assert _w._waiver_applies_to("X") == ["X"]
    assert _w._waiver_applies_to("") is None
    assert _w._waiver_applies_to(42) is None


def test_parse_waivers_bad_read(tmp_path: Path) -> None:
    with pytest.raises(LoadError, match="Failed to read"):
        parse_waivers_file(_yaml(tmp_path, ": : [ unbalanced"))


def test_parse_waivers_root_not_mapping(tmp_path: Path) -> None:
    with pytest.raises(LoadError, match="must be a mapping"):
        parse_waivers_file(_yaml(tmp_path, "- a\n- b\n"))


def test_parse_waivers_no_list(tmp_path: Path) -> None:
    out = parse_waivers_file(_yaml(tmp_path, "other: 1\n"))
    assert out.by_control == {} and any("No 'waivers' list" in w for w in out.warnings)


def test_parse_waivers_not_a_list(tmp_path: Path) -> None:
    with pytest.raises(LoadError, match="must be a list"):
        parse_waivers_file(_yaml(tmp_path, "waivers: {}\n"))


def test_parse_waivers_valid_with_applies_to(tmp_path: Path) -> None:
    src = (
        "waivers:\n"
        "  - control_id: GOV-SEC-001\n"
        "    justification: reviewed and accepted\n"
        "    owner: appsec\n"
        "    expires_at: '2099-01-01'\n"
        "    applies_to: [path/a, path/b]\n"
        "  - notamap\n"
        "  - justification: x\n"
        "    owner: o\n"
        "  - control_id: C3\n"
        "    justification: j\n"
    )
    out = parse_waivers_file(_yaml(tmp_path, src))
    assert out.by_control["GOV-SEC-001"].applies_to == ["path/a", "path/b"]
    assert "C3" not in out.by_control  # empty owner skipped
    assert len(out.warnings) >= 3


def test_parse_waivers_invalid_expires(tmp_path: Path) -> None:
    src = "waivers:\n  - control_id: C1\n    justification: j\n    owner: o\n    expires_at: 'not-a-date'\n"
    out = parse_waivers_file(_yaml(tmp_path, src))
    assert "C1" not in out.by_control and any("invalid expires_at" in w for w in out.warnings)
