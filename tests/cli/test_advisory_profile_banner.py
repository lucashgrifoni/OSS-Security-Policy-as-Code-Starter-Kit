"""Advisory profile banner coverage (F3-04 of the v5.8.0 maturity plan).

The plan lists the canonical set of bundled advisory profiles that must
trigger the ``[advisory profile]`` banner in interactive ``evaluate``
output: ``ai-agent-baseline-1``, ``cra-eu-ready-1``, ``github-aws-level-2``,
``github-azure-level-2``, every ``iac-*-baseline-1``,
``container-baseline-1``, ``kubernetes-baseline-1``, and
``webhook-security-1``. Missing any of them would let an adopter wire a
profile as a release gate without seeing the disclaimer.

This test pins the CLI's canonical advisory set so accidental removal
(or accidental promotion of a non-advisory profile) fails the suite
with a clear identifying message.
"""

from __future__ import annotations

from oss_policy_kit.cli.terminal_ui import _ADVISORY_ONLY_PROFILE_IDS

EXPECTED_ADVISORY_PROFILE_IDS: frozenset[str] = frozenset(
    {
        "ai-agent-baseline-1",
        "container-baseline-1",
        "cra-eu-ready-1",
        "cra-eu-reporting-1",
        "github-aws-level-2",
        "github-azure-level-2",
        "iac-bicep-baseline-1",
        "iac-cfn-baseline-1",
        "iac-pulumi-baseline-1",
        "iac-terraform-baseline-1",
        "kubernetes-baseline-1",
        "webhook-security-1",
    }
)


def test_canonical_advisory_set_is_complete() -> None:
    """Every expected advisory profile must be in the banner set."""

    missing = EXPECTED_ADVISORY_PROFILE_IDS - _ADVISORY_ONLY_PROFILE_IDS
    assert not missing, f"Banner set missing expected advisory profile(s): {sorted(missing)}"


def test_canonical_advisory_set_has_no_extras() -> None:
    """The banner set must not silently include non-advisory profiles.

    If the set grows beyond the canonical list, document it here so the
    intent is explicit (e.g. promote a new profile to advisory).
    """

    extras = _ADVISORY_ONLY_PROFILE_IDS - EXPECTED_ADVISORY_PROFILE_IDS
    assert not extras, (
        f"Banner set contains profiles not in the canonical advisory list: {sorted(extras)}. "
        "Update EXPECTED_ADVISORY_PROFILE_IDS to acknowledge the promotion, or remove from the CLI set."
    )
