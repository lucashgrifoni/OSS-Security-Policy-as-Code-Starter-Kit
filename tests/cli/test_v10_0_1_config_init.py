"""v10.0.1 hotfix regressions for config honoring + init gitlab parity + contract help.

Covers the F4-config-init unit:

- X5-03: ``evaluate`` honors ``fail_on`` / ``output_dir`` recorded in
  ``oss-policy-kit.yaml`` when the user omits the corresponding CLI flag, while an
  explicit CLI flag always wins. The existing profile-from-config fallback keeps
  working (guarded here so the wiring refactor cannot silently regress it).
- X6-03: ``init --with-evidence --platform gitlab`` scaffolds evidence (no false
  downgrade note), and ``init --help`` lists ``gitlab`` in the ``--platform`` help.
- X5-04: the ``--report-json-contract`` help documents that the value is normalized
  (case / whitespace / optional leading ``v``); acceptance behavior is unchanged
  (normalized ``2.0`` accepted, non-``2.0`` exits 2).
"""

from __future__ import annotations

import shutil
from pathlib import Path

from typer.testing import CliRunner

from oss_policy_kit.cli.main import app, prepare_cli_args

REPO_ROOT = Path(__file__).resolve().parents[2]
EXAMPLE_VULNERABLE = REPO_ROOT / "examples" / "vulnerable-repo"


def _write_config(
    target: Path,
    *,
    profile: str = "github-level-1",
    fail_on: str = "none",
    output_dir: str = "./oss-policy-reports",
) -> None:
    """Write a valid ``oss-policy-kit.yaml`` under *target*."""

    # Use forward slashes even on Windows: a backslash in a YAML double-quoted scalar
    # is an escape lead-in ("\U", "\L", ...) and would break parsing. pathlib parses
    # forward-slash paths correctly on every OS.
    output_dir_yaml = output_dir.replace("\\", "/")
    body = (
        "schema_version: oss-policy-kit/config/v1\n"
        f"profile: {profile}\n"
        "profile_source: recommended\n"
        f"fail_on: {fail_on}\n"
        f'output_dir: "{output_dir_yaml}"\n'
        'report_json_contract: "2.0"\n'
        "detected:\n"
        "  platform: github\n"
        "  primary_stack: null\n"
        "  signals: []\n"
    )
    (target / "oss-policy-kit.yaml").write_text(body, encoding="utf-8")


def _vuln_copy(tmp_path: Path) -> Path:
    """Return a writable copy of examples/vulnerable-repo (fails github-level-1)."""

    dest = tmp_path / "vuln"
    shutil.copytree(EXAMPLE_VULNERABLE, dest)
    return dest


# --------------------------------------------------------------------------- #
# X5-03: config fail_on / output_dir honored when the CLI flag is omitted.
# --------------------------------------------------------------------------- #


def test_config_fail_on_fail_trips_gate_without_cli_flag(tmp_path: Path) -> None:
    """A config with ``fail_on: fail`` makes evaluate exit 1 on a failing target
    even though ``--fail-on`` was not passed on the command line."""

    repo = _vuln_copy(tmp_path)
    _write_config(repo, fail_on="fail")

    runner = CliRunner()
    result = runner.invoke(
        app,
        prepare_cli_args(
            [
                "evaluate",
                "--target",
                str(repo),
                "--profile",
                "github-level-1",
                "--output-dir",
                str(tmp_path / "out"),
                "--summary-only",
                "--format",
                "json",
            ]
        ),
    )
    # vulnerable-repo fails github-level-1, so fail_on=fail (from config) trips the gate.
    assert result.exit_code == 1, result.output


def test_config_fail_on_none_does_not_trip_gate(tmp_path: Path) -> None:
    """Control: same failing target + config ``fail_on: none`` -> exit 0."""

    repo = _vuln_copy(tmp_path)
    _write_config(repo, fail_on="none")

    runner = CliRunner()
    result = runner.invoke(
        app,
        prepare_cli_args(
            [
                "evaluate",
                "--target",
                str(repo),
                "--profile",
                "github-level-1",
                "--output-dir",
                str(tmp_path / "out"),
                "--summary-only",
                "--format",
                "json",
            ]
        ),
    )
    assert result.exit_code == 0, result.output


def test_cli_fail_on_flag_overrides_config(tmp_path: Path) -> None:
    """An explicit ``--fail-on none`` wins over a config that says ``fail_on: fail``."""

    repo = _vuln_copy(tmp_path)
    _write_config(repo, fail_on="fail")

    runner = CliRunner()
    result = runner.invoke(
        app,
        prepare_cli_args(
            [
                "evaluate",
                "--target",
                str(repo),
                "--profile",
                "github-level-1",
                "--fail-on",
                "none",
                "--output-dir",
                str(tmp_path / "out"),
                "--summary-only",
                "--format",
                "json",
            ]
        ),
    )
    # CLI flag wins: the gate is NOT tripped despite the config's fail_on: fail.
    assert result.exit_code == 0, result.output


def test_config_output_dir_used_when_flag_omitted(tmp_path: Path) -> None:
    """``output_dir`` from the config is used when ``--output-dir`` is not passed.

    An absolute path is written into the config so the assertion is independent of
    the (in-process) CliRunner working directory. It points inside the repository: since
    PATH-01b (2026-10-06) a config output_dir outside it is refused.
    """

    repo = _vuln_copy(tmp_path)
    config_out = repo / "config-out"
    _write_config(repo, fail_on="none", output_dir=str(config_out))

    runner = CliRunner()
    result = runner.invoke(
        app,
        prepare_cli_args(
            [
                "evaluate",
                "--target",
                str(repo),
                "--profile",
                "github-level-1",
                "--summary-only",
                "--format",
                "json",
            ]
        ),
    )
    assert result.exit_code == 0, result.output
    assert (config_out / "evaluation-report.json").is_file(), (
        "reports should land in the config's output_dir when --output-dir is omitted"
    )


def test_cli_output_dir_flag_overrides_config(tmp_path: Path) -> None:
    """An explicit ``--output-dir`` wins over the config's ``output_dir``."""

    repo = _vuln_copy(tmp_path)
    config_out = tmp_path / "config-out"
    cli_out = tmp_path / "cli-out"
    _write_config(repo, fail_on="none", output_dir=str(config_out))

    runner = CliRunner()
    result = runner.invoke(
        app,
        prepare_cli_args(
            [
                "evaluate",
                "--target",
                str(repo),
                "--profile",
                "github-level-1",
                "--output-dir",
                str(cli_out),
                "--summary-only",
                "--format",
                "json",
            ]
        ),
    )
    assert result.exit_code == 0, result.output
    assert (cli_out / "evaluation-report.json").is_file()
    assert not config_out.exists(), "config output_dir must not be used when --output-dir is passed"


def test_profile_from_config_still_honored(tmp_path: Path) -> None:
    """Regression guard: the profile-from-config fallback still works after the
    config-resolver refactor (must not break existing behavior)."""

    repo = _vuln_copy(tmp_path)
    _write_config(repo, profile="github-level-1", fail_on="none")

    runner = CliRunner()
    result = runner.invoke(
        app,
        prepare_cli_args(
            [
                "evaluate",
                "--target",
                str(repo),
                "--output-dir",
                str(tmp_path / "out"),
                "--summary-only",
                "--format",
                "json",
            ]
        ),
    )
    assert result.exit_code == 0, result.output
    assert "Using profile from oss-policy-kit.yaml" in result.output


# --------------------------------------------------------------------------- #
# X6-03: init gitlab evidence parity.
# --------------------------------------------------------------------------- #


def test_init_with_evidence_gitlab_scaffolds_no_downgrade(tmp_path: Path) -> None:
    """``init --with-evidence --platform gitlab`` scaffolds evidence and emits no
    false 'evidence only for github/azure/aws' downgrade note."""

    repo = tmp_path / "gl"
    repo.mkdir()

    runner = CliRunner()
    result = runner.invoke(
        app,
        prepare_cli_args(
            [
                "init",
                "--target",
                str(repo),
                "--platform",
                "gitlab",
                "--with-evidence",
                "--force",
            ]
        ),
    )
    assert result.exit_code == 0, result.output
    # Evidence directory was actually scaffolded for gitlab.
    evidence_dir = repo / ".oss-policy-kit" / "evidence"
    assert evidence_dir.is_dir(), result.output
    assert any(evidence_dir.iterdir()), "gitlab evidence templates should be written"
    # No downgrade note about skipping --with-evidence.
    assert "skipped --with-evidence" not in result.output


def test_init_help_platform_lists_gitlab() -> None:
    """``init --help`` documents gitlab as an accepted ``--platform`` value."""

    runner = CliRunner()
    result = runner.invoke(app, prepare_cli_args(["init", "--help"]))
    assert result.exit_code == 0, result.output
    assert "gitlab" in result.output


# --------------------------------------------------------------------------- #
# X5-04: report-json-contract help documents normalization; behavior unchanged.
# --------------------------------------------------------------------------- #


def test_evaluate_help_documents_contract_normalization() -> None:
    """``evaluate --help`` explains the value is normalized (case/whitespace/leading v)."""

    runner = CliRunner()
    result = runner.invoke(app, prepare_cli_args(["evaluate", "--help"]))
    assert result.exit_code == 0, result.output
    # Rich may wrap the help text, so match on a stable single word rather than a phrase.
    assert "normalized" in result.output


def test_report_contract_v_prefixed_value_accepted(tmp_path: Path) -> None:
    """Acceptance behavior is unchanged: 'v2.0' normalizes to 2.0 and is accepted
    (the run does NOT exit 2 because of the contract value)."""

    repo = _vuln_copy(tmp_path)

    runner = CliRunner()
    result = runner.invoke(
        app,
        prepare_cli_args(
            [
                "evaluate",
                "--target",
                str(repo),
                "--profile",
                "github-level-1",
                "--report-json-contract",
                "v2.0",
                "--output-dir",
                str(tmp_path / "out"),
                "--summary-only",
                "--format",
                "json",
            ]
        ),
    )
    # Accepted -> normal run (exit 0 with fail_on none). Never a contract exit 2.
    assert result.exit_code == 0, result.output
    assert (tmp_path / "out" / "evaluation-report.json").is_file()


def test_report_contract_non_2_0_value_exits_2(tmp_path: Path) -> None:
    """A value that does not normalize to 2.0 still exits 2 (behavior unchanged)."""

    repo = _vuln_copy(tmp_path)

    runner = CliRunner()
    result = runner.invoke(
        app,
        prepare_cli_args(
            [
                "evaluate",
                "--target",
                str(repo),
                "--profile",
                "github-level-1",
                "--report-json-contract",
                "1.0",
                "--output-dir",
                str(tmp_path / "out"),
                "--summary-only",
                "--format",
                "json",
            ]
        ),
    )
    assert result.exit_code == 2, result.output


def test_init_refuses_an_output_dir_outside_the_target(tmp_path: Path) -> None:
    """``init`` must not write a config output_dir that ``evaluate`` would refuse (PATH-01b)."""

    repo = tmp_path / "repo"
    repo.mkdir()

    runner = CliRunner()
    for outside in (str(tmp_path / "shared"), "../shared"):
        result = runner.invoke(
            app,
            prepare_cli_args(["init", "--target", str(repo), "--output-dir", outside, "--force"]),
        )
        assert result.exit_code == 2, result.output
        assert "must be inside the target" in result.output
        assert not (repo / "oss-policy-kit.yaml").exists()


def test_init_keeps_an_output_dir_inside_the_target(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()

    result = CliRunner().invoke(
        app,
        prepare_cli_args(["init", "--target", str(repo), "--output-dir", "./reports", "--force"]),
    )

    assert result.exit_code == 0, result.output
    assert "reports" in (repo / "oss-policy-kit.yaml").read_text(encoding="utf-8")
