"""The default `scan-sast` invocation has to be one Semgrep will actually run.

The adapter always passes ``--metrics=off``, and Semgrep refuses ``--config auto`` whenever
telemetry is disabled:

    [ERROR]: Cannot create auto config when metrics are off.
    Please allow metrics or run with a specific config.

Both settings shipped together, so the documented quick start --

    pip install semgrep
    python -m oss_policy_kit scan-sast --target .

-- exited 2 on every run, for every user, online or offline, with the real cause written
only into the evidence file's diagnostics. Nothing caught it because no test asserted on
the argv the adapter builds, and the suite never had Semgrep installed to reject it.

These are argv assertions on purpose: they hold with or without Semgrep on the machine, and
they fail the moment the combination comes back.
"""

from __future__ import annotations

from pathlib import Path

from oss_policy_kit.infrastructure.scanners import semgrep_adapter


def test_the_default_ruleset_is_not_auto() -> None:
    """`auto` cannot coexist with this adapter's `--metrics=off`, so it cannot be the default."""

    assert "auto" not in semgrep_adapter.DEFAULT_RULESETS, (
        "`--config auto` requires Semgrep telemetry to be enabled, and this adapter always "
        "passes --metrics=off, so a default of `auto` makes every run exit 2"
    )


def test_the_default_ruleset_is_concrete() -> None:
    assert semgrep_adapter.DEFAULT_RULESETS, "a default ruleset has to exist; an empty tuple scans nothing"
    for ruleset in semgrep_adapter.DEFAULT_RULESETS:
        assert ruleset.strip(), "a blank ruleset is not a config Semgrep can resolve"


def test_metrics_stay_off() -> None:
    """The reason `auto` had to go, rather than the other way round.

    A security tool that reports what it scanned to a third party by default is not one an
    adopter can drop into a pipeline unexamined. If this ever flips, the choice was made
    somewhere other than here.
    """

    source = Path(semgrep_adapter.__file__).read_text(encoding="utf-8")

    assert '"--metrics=off"' in source, "the adapter stopped disabling Semgrep telemetry"
