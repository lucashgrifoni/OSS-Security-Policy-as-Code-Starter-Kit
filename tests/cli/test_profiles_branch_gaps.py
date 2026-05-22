"""Branch-coverage gaps for cli.profiles helpers and command error paths."""

from __future__ import annotations

import json

import pytest
from rich.table import Table
from typer.testing import CliRunner

from oss_policy_kit.cli import profiles as p
from oss_policy_kit.cli import terminal_ui
from oss_policy_kit.cli.main import app
from oss_policy_kit.domain.errors import InvalidInputError, LoadError

runner = CliRunner()


def _row(profile_id: str = "github-level-2", *, legacy: bool = False) -> p._ProfileDisplayRow:
    return p._ProfileDisplayRow(
        profile_id=profile_id,
        title="Title",
        platform=p._profile_platform(profile_id),
        level=p._profile_level(profile_id),
        controls=3,
        track=p._profile_track(profile_id),
        summary="s",
        description="desc",
        audience="aud",
        is_legacy_alias=legacy,
    )


# --------------------------------------------------------------------------- #
# Pure helpers (lines 136, 185, 198, 287, 316)
# --------------------------------------------------------------------------- #


def test_maturity_label_legacy_alias() -> None:
    assert "legacy" in p._profile_maturity_label("x", is_legacy_alias=True).lower()


def test_posture_descriptor_legacy_and_general() -> None:
    assert p._profile_posture_descriptor("x", "legacy bundled id (non-canonical)") == "legacy_alias"
    # A maturity string with no recognised keyword falls through to "general".
    assert p._profile_posture_descriptor("custom-x", "mystery tier") == "general"


def test_profile_level_release_hardening_base() -> None:
    assert p._profile_level("github-release-hardening") == "L1"


def test_profile_summary_short_normalized() -> None:
    # custom track/level not in the fixed map -> returns the normalized description.
    out = p._profile_summary("custom-x", "short  description  here", "Title")
    assert out == "short description here"


# --------------------------------------------------------------------------- #
# _filter_profile_display_rows invalid family (line 236)
# --------------------------------------------------------------------------- #


def test_filter_rows_invalid_family_raises() -> None:
    with pytest.raises(InvalidInputError):
        p._filter_profile_display_rows([], family="gcp", only_extreme=False, advisory_only=False)


# --------------------------------------------------------------------------- #
# _profile_assurance_mix skips unknown control ids (line 257)
# --------------------------------------------------------------------------- #


def test_assurance_mix_skips_unknown_control() -> None:
    mix = p._profile_assurance_mix(("DOES-NOT-EXIST-999",), {})
    assert mix["deterministic"] == 0 and mix["signal"] == 0 and mix["evidence-backed"] == 0


# --------------------------------------------------------------------------- #
# _add_profile_rows legacy alias pid formatting (lines 413-414)
# --------------------------------------------------------------------------- #


def test_add_profile_rows_legacy_alias_pid() -> None:
    table = Table()
    for _ in range(7):
        table.add_column("c")
    p._add_profile_rows(table, [_row("github-level-3", legacy=True)], detailed=True)
    assert table.row_count == 1


# --------------------------------------------------------------------------- #
# _print_profiles_table human-tty compact panel + early return (447-451, 455)
# --------------------------------------------------------------------------- #


def test_print_profiles_table_human_tty_compact(monkeypatch, capsys) -> None:
    monkeypatch.setattr(terminal_ui, "human_tty_stdout", lambda: True)
    monkeypatch.setattr(terminal_ui, "print_profiles_catalog_panel", lambda *a, **k: None)
    p._print_profiles_table(detailed=False, compact_layout=True, rows=[_row()])
    out = capsys.readouterr().out
    assert "Full table" in out


# --------------------------------------------------------------------------- #
# _print_profiles_json with rows=None resolves bundled profiles (line 499)
# --------------------------------------------------------------------------- #


def test_print_profiles_json_rows_none(capsys) -> None:
    p._print_profiles_json()
    payload = json.loads(capsys.readouterr().out)
    assert payload["profiles"]


# --------------------------------------------------------------------------- #
# profiles_cmd LoadError path (lines 580-581)
# --------------------------------------------------------------------------- #


def test_profiles_cmd_load_error(monkeypatch) -> None:
    def _boom() -> list:
        raise LoadError("catalog missing")

    monkeypatch.setattr(p, "_iter_bundled_profiles", _boom)
    res = runner.invoke(app, ["profiles", "--format", "json"])
    assert res.exit_code == 2


def test_profiles_cmd_invalid_family_exit(monkeypatch) -> None:
    res = runner.invoke(app, ["profiles", "--format", "json", "--family", "gcp"])
    assert res.exit_code == 2
