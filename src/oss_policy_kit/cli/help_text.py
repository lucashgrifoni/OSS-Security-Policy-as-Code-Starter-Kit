"""CLI epilog blocks shared across Typer commands."""

from __future__ import annotations

ROOT_CLI_EPILOG = "\n\n".join(
    [
        "----------------------------------------------------------------------",
        "EXAMPLES",
        "----------------------------------------------------------------------",
        "Baseline evaluation (writes reports under ./out):",
        "  python -m oss_policy_kit evaluate --target . --profile github-level-1",
        "Compatibility (root flags, no subcommand):",
        "  python -m oss_policy_kit --target . --profile github-level-1",
        "CI gate (exit 1 when any control is fail):",
        "  python -m oss_policy_kit evaluate --target . --profile github-level-1 --fail-on fail",
        "JSON summary on stdout:",
        "  python -m oss_policy_kit evaluate --target . --profile github-level-1 --format json --summary-only",
        "List bundled profiles (compact table on stdout):",
        "  python -m oss_policy_kit profiles",
        "Show bundled profiles with full audience/description via root flag:",
        "  python -m oss_policy_kit --show-profiles",
        "Profiles as JSON:",
        "  python -m oss_policy_kit profiles --format json",
        "Many repos under one parent folder:",
        "  python -m oss_policy_kit evaluate-many --target-root ./repos --profiles github-level-1,azure-level-1",
        "Evidence JSON templates (release-hardening):",
        "  python -m oss_policy_kit scaffold-evidence --target . --platform github",
        "Heuristic profile suggestions:",
        "  python -m oss_policy_kit recommend-profile --target .",
        "",
        "----------------------------------------------------------------------",
        "EXIT CODES",
        "----------------------------------------------------------------------",
        "  0  Success; fail-on threshold not violated (when --fail-on applies).",
        "  1  Evaluation finished; fail-on threshold violated.",
        "  2  Invalid usage, missing input, or validation/load error.",
        "  3  Unexpected internal error.",
        "",
        "----------------------------------------------------------------------",
        "WINDOWS",
        "----------------------------------------------------------------------",
        "Prefer python -m oss_policy_kit if the oss-policy-kit script is not on PATH.",
    ]
)

EVALUATE_EPILOG = "\n\n".join(
    [
        "----------------------------------------------------------------------",
        "EXAMPLES",
        "----------------------------------------------------------------------",
        "Baseline (reports under ./out):",
        "  python -m oss_policy_kit evaluate --target . --profile github-level-1",
        "Positional target (when the path has no spaces):",
        "  python -m oss_policy_kit evaluate . --profile github-level-1",
        "JSON summary on stdout:",
        "  python -m oss_policy_kit evaluate --target . --profile github-level-1 --summary-only --format json",
        "CI gate (fail severity):",
        "  python -m oss_policy_kit evaluate --target . --profile github-level-1 --fail-on fail",
        "CI gate (fail or manual-review-required):",
        "  python -m oss_policy_kit evaluate --target . --profile github-level-1 --fail-on degraded",
        "Custom output dir and waivers file:",
        (
            "  python -m oss_policy_kit evaluate -t . --profile github-release-hardening-1 "
            "-o ./reports --waivers ./waivers/waivers.example.yaml"
        ),
        "Optional OpenSSF Scorecard JSON:",
        "  python -m oss_policy_kit evaluate --target . --profile github-level-1 --scorecard-json ./scorecard.json",
        "",
        "----------------------------------------------------------------------",
        "FAIL-ON MODES",
        "----------------------------------------------------------------------",
        "  none       Never fail (exit 0 unless internal error).",
        "  fail       Exit 1 if any control has status 'fail'.",
        "  degraded   Exit 1 if any control has 'fail' OR 'manual-review-required'.",
        "             Operational warnings alone do NOT trigger this gate.",
        "",
        "----------------------------------------------------------------------",
        "EXIT CODES",
        "----------------------------------------------------------------------",
        "  0  Evaluation completed; fail-on threshold not violated.",
        "  1  Evaluation completed; fail-on threshold violated.",
        "  2  Invalid usage, missing input, or validation/load error.",
        "  3  Unexpected internal error.",
    ]
)

EVALUATE_MANY_EPILOG = "\n\n".join(
    [
        "----------------------------------------------------------------------",
        "EXAMPLES",
        "----------------------------------------------------------------------",
        "Evaluate each child folder as a repo:",
        "  python -m oss_policy_kit evaluate-many --target-root ./repos --profiles github-level-1",
        "CI gate across the batch (exit 1 if any repo has fail):",
        "  python -m oss_policy_kit evaluate-many --target-root ./repos --profiles github-level-1 --fail-on fail",
        "Skip folders that look like docs/assets (non-repos):",
        "  python -m oss_policy_kit evaluate-many --target-root ./mono --profiles github-level-1 --skip-non-repos",
        "",
        "----------------------------------------------------------------------",
        "EXIT CODES",
        "----------------------------------------------------------------------",
        "  0  Batch finished; fail-on threshold not violated (when --fail-on applies).",
        "  1  Batch finished; fail-on threshold violated.",
        "  2  Invalid usage, missing input, or validation/load error.",
        "  3  Unexpected internal error.",
        "",
        "----------------------------------------------------------------------",
        "TIPS",
        "----------------------------------------------------------------------",
        "Use --skip-non-repos or --include/--exclude to avoid evaluating non-repository directories.",
    ]
)

DIFF_REPORTS_EPILOG = "\n\n".join(
    [
        "----------------------------------------------------------------------",
        "EXAMPLES",
        "----------------------------------------------------------------------",
        "Default CI gate (exit 1 when any control regresses):",
        "  python -m oss_policy_kit diff-reports --before old.json --after new.json",
        "Opt out of the regression gate (always exit 0 unless the inputs are invalid):",
        "  python -m oss_policy_kit diff-reports --before old.json --after new.json --no-fail-on-regression",
        "Markdown drift report on stdout for a PR comment:",
        "  python -m oss_policy_kit diff-reports --before old.json --after new.json --format markdown",
        "",
        "Note: the gate flag pair is --fail-on-regression / --no-fail-on-regression (singular).",
    ]
)
