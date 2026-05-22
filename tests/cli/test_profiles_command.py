"""Coverage for the ``profiles`` listing command across formats and filters."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from oss_policy_kit.cli import profiles as profiles_mod
from oss_policy_kit.cli.main import app

runner = CliRunner()


def test_profiles_compact() -> None:
    res = runner.invoke(app, ["profiles", "--format", "compact"])
    assert res.exit_code == 0, res.output
    assert "github" in res.output.lower()


def test_profiles_detailed() -> None:
    res = runner.invoke(app, ["profiles", "--format", "detailed"])
    assert res.exit_code == 0, res.output


def test_profiles_table() -> None:
    res = runner.invoke(app, ["profiles", "--format", "table"])
    assert res.exit_code == 0, res.output


def test_profiles_json() -> None:
    res = runner.invoke(app, ["profiles", "--format", "json"])
    assert res.exit_code == 0, res.output
    payload = json.loads(res.stdout)
    assert isinstance(payload, (list, dict))


def test_profiles_family_filter() -> None:
    for fam in ("github", "azure", "aws"):
        res = runner.invoke(app, ["profiles", "--format", "json", "--family", fam])
        assert res.exit_code == 0, res.output


def test_profiles_only_extreme() -> None:
    res = runner.invoke(app, ["profiles", "--format", "compact", "--only-extreme"])
    assert res.exit_code == 0, res.output


def test_profiles_advisory_only() -> None:
    res = runner.invoke(app, ["profiles", "--format", "detailed", "--advisory-only"])
    assert res.exit_code == 0, res.output


def test_profiles_bad_format() -> None:
    res = runner.invoke(app, ["profiles", "--format", "yaml"])
    assert res.exit_code != 0


# --------------------------------------------------------------------------- #
# pure helpers
# --------------------------------------------------------------------------- #


def test_profile_platform_level_track() -> None:
    assert profiles_mod._profile_platform("github-level-1").lower() == "github"
    assert profiles_mod._profile_platform("azure-level-2").lower() == "azure"
    assert profiles_mod._profile_platform("aws-level-3").lower() == "aws"
    assert "2" in profiles_mod._profile_level("github-level-2")
    # _profile_track returns some non-empty descriptor; just assert it is a string.
    assert isinstance(profiles_mod._profile_track("github-release-hardening-1"), str)


def test_iter_bundled_profiles_nonempty() -> None:
    rows = profiles_mod._iter_bundled_profiles()
    assert rows
    assert profiles_mod._longest_profile_id_len(rows) > 0
