"""`scan-sast --help` promised a default the command stopped using.

`DEFAULT_RULESETS` became `("p/security-audit",)` because `auto` cannot resolve while the
adapter passes `--metrics=off`, and that reason is written down beside the constant. The help
string and the adapter's own docstring kept saying `auto`, so the documented default was one
Semgrep refuses to run.

The flag's default value was always correct: Typer renders it from `DEFAULT_RULESETS`. Only the
prose disagreed with it, which is the worst shape for this kind of drift, because the value the
operator reads and the value the tool uses come from the same screen.

`param.opts` rather than a grep of `--help`: Rich hard-wraps at 80 columns in CI and will split
a flag name across lines, which makes a help-text search pass on one machine and fail on the
other. See the note in `tests/cli/` about that.
"""

from __future__ import annotations

import typer

from oss_policy_kit.cli.main import app
from oss_policy_kit.infrastructure.scanners import semgrep_adapter


def _rulesets_param() -> typer.models.ParameterInfo:
    command = typer.main.get_command(app)
    scan_sast = command.commands["scan-sast"]  # type: ignore[attr-defined]
    return next(p for p in scan_sast.params if "--rulesets" in getattr(p, "opts", []))


def test_the_help_does_not_name_a_default_the_command_does_not_use() -> None:
    help_text = _rulesets_param().help or ""

    assert "Defaults to 'auto'" not in help_text, help_text


def test_the_help_names_the_default_the_command_does_use() -> None:
    help_text = _rulesets_param().help or ""

    assert "p/security-audit" in help_text, help_text


def test_the_flag_default_and_the_constant_still_agree() -> None:
    """The half that was never wrong. Pinned so a fix to the prose cannot drift the value."""

    assert _rulesets_param().default == ",".join(semgrep_adapter.DEFAULT_RULESETS)


def test_the_adapter_docstring_does_not_promise_auto_either() -> None:
    """`run_semgrep` said `Defaults to ``("auto",)``` in the same paragraph as the real default."""

    doc = semgrep_adapter.run_semgrep.__doc__ or ""

    assert '("auto",)' not in doc, doc
