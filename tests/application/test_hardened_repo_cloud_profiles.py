"""End-to-end snapshot of Azure/AWS profiles against ``examples/hardened-repo``.

These tests pin the observable evaluation shape of the bundled hardened fixture so maintainers
notice when a change silently shifts status counts or the mix of ``pass`` vs ``self-attested``.
They deliberately do **not** assert on exact counts so adding a new control does not break the
snapshot; they assert the invariants the docs and profile specs promise (no ``fail``, no
``manual-review-required``, and that strict tiers keep at least one ``self-attested`` row because
the fixture is synthetic and cannot be API-attested).
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from tests.conftest import EXAMPLE_HARDENED

from oss_policy_kit.application.engine import evaluate_repository
from oss_policy_kit.application.loader import bundled_kit_root, load_catalog, load_profile_by_id
from oss_policy_kit.domain.models import ExecutionReport


def _evaluate(repo: Path, profile_id: str) -> ExecutionReport:
    root = bundled_kit_root()
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    profile = load_profile_by_id(root, profile_id)
    return evaluate_repository(
        repo_root=repo,
        profile=profile,
        catalog=catalog,
        waiver_outcome=None,
        scorecard=None,
    )


def _status_counts(report: ExecutionReport) -> Counter[str]:
    return Counter(r.status.value for r in report.results)


def test_aws_level_1_all_pass_on_hardened_repo() -> None:
    """``aws-level-1`` is the advertised daily baseline and must stay fully green on the fixture."""

    counts = _status_counts(_evaluate(EXAMPLE_HARDENED, "aws-level-1"))
    assert counts["fail"] == 0
    assert counts["manual-review-required"] == 0
    assert counts["pass"] >= 1
    # The fixture is deliberately designed to keep level-1 free of synthetic self-attested rows.
    assert counts.get("self-attested", 0) == 0


def test_azure_level_1_all_pass_on_hardened_repo() -> None:
    """``azure-level-1`` is the advertised daily baseline and must stay fully green on the fixture."""

    counts = _status_counts(_evaluate(EXAMPLE_HARDENED, "azure-level-1"))
    assert counts["fail"] == 0
    assert counts["manual-review-required"] == 0
    assert counts["pass"] >= 1
    assert counts.get("self-attested", 0) == 0


def test_aws_release_hardening_3_reaches_zero_fail_but_keeps_self_attested() -> None:
    """Strict tier: ``fail == 0`` is achievable on the synthetic fixture, but artifact/governance rows
    must stay ``self-attested`` because the fixture never runs ``collect-evidence``.

    If this invariant flips to all-pass, either the fixture silently received live evidence files
    (scope expansion) or the evaluator relaxed its hard-gate. Either case deserves review.
    """

    counts = _status_counts(_evaluate(EXAMPLE_HARDENED, "aws-release-hardening-3"))
    assert counts["fail"] == 0
    assert counts["manual-review-required"] == 0
    assert counts["pass"] >= 1
    assert counts.get("self-attested", 0) >= 1, "Synthetic fixture must not claim live-attested posture"


def test_azure_release_hardening_3_reaches_zero_fail_but_keeps_self_attested() -> None:
    """Same invariant as the AWS counterpart; guards against silent relaxation of azure-release-hardening-3."""

    counts = _status_counts(_evaluate(EXAMPLE_HARDENED, "azure-release-hardening-3"))
    assert counts["fail"] == 0
    assert counts["manual-review-required"] == 0
    assert counts["pass"] >= 1
    assert counts.get("self-attested", 0) >= 1, "Synthetic fixture must not claim live-attested posture"


def test_aws_level_3_hard_gate_keeps_at_least_one_self_attested_row() -> None:
    """``aws-level-3`` is the hard-gate tier — synthetic fixtures must not reach all-pass here."""

    counts = _status_counts(_evaluate(EXAMPLE_HARDENED, "aws-level-3"))
    assert counts["fail"] == 0
    assert counts["manual-review-required"] == 0
    assert counts.get("self-attested", 0) >= 1


def test_azure_level_3_hard_gate_keeps_at_least_one_self_attested_row() -> None:
    """``azure-level-3`` is the hard-gate tier — synthetic fixtures must not reach all-pass here."""

    counts = _status_counts(_evaluate(EXAMPLE_HARDENED, "azure-level-3"))
    assert counts["fail"] == 0
    assert counts["manual-review-required"] == 0
    assert counts.get("self-attested", 0) >= 1


def test_github_release_hardening_2_dominantly_passes_on_hardened_repo() -> None:
    """``github-release-hardening-2`` is the release-track ladder for GitHub teams.

    On the synthetic fixture it should be predominantly green: governance, branch protection,
    workflow hardening and platform evidence all line up. The realistic exceptions are
    ``GH-PROV-023`` (no provenance signal embedded in the synthetic workflows) and
    ``OSS-SCORECARD-001`` (no scorecard JSON provided to the evaluator) — these are intentional
    and document the tier's expectation that maintainers wire provenance and scorecard before
    relying on the gate.
    """

    counts = _status_counts(_evaluate(EXAMPLE_HARDENED, "github-release-hardening-2"))
    # No manual-review at this tier — controls either pass, fail honestly, or are skipped.
    assert counts["manual-review-required"] == 0
    # Generous failure ceiling tracks the documented "fill provenance / scorecard before release" caveats.
    assert counts["fail"] <= 2, f"github-release-hardening-2 regression: {dict(counts)}"
    # At least the governance + workflow + branch-protection rows must pass.
    assert counts["pass"] >= 20


def test_azure_release_hardening_2_predominantly_passes_with_self_attested_tail() -> None:
    """``azure-release-hardening-2`` keeps the synthetic fixture green on the deterministic side.

    The expected ``self-attested`` rows correspond to the artifact-bound SBOM/provenance
    evidence (whose digests must come from a real release pipeline, not a clone-visible file).
    No ``fail`` and no ``manual-review-required`` should appear at this tier on the hardened
    fixture; deviations are signal that an evaluator silently changed contract.
    """

    counts = _status_counts(_evaluate(EXAMPLE_HARDENED, "azure-release-hardening-2"))
    assert counts["fail"] == 0
    assert counts["manual-review-required"] == 0
    assert counts["pass"] >= 15
    assert counts.get("self-attested", 0) >= 1, "Synthetic fixture must not claim live-attested posture"


def test_aws_release_hardening_2_predominantly_passes_with_self_attested_tail() -> None:
    """``aws-release-hardening-2`` mirrors the Azure invariant: no fails on the hardened fixture,
    deterministic rows pass, and a small ``self-attested`` tail remains for artifact-bound rows
    that need release-pipeline-emitted digests.
    """

    counts = _status_counts(_evaluate(EXAMPLE_HARDENED, "aws-release-hardening-2"))
    assert counts["fail"] == 0
    assert counts["manual-review-required"] == 0
    assert counts["pass"] >= 15
    assert counts.get("self-attested", 0) >= 1, "Synthetic fixture must not claim live-attested posture"
