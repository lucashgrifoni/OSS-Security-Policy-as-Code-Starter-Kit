"""Guardrails for the public documentation surface."""

from __future__ import annotations

from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]

# ROADMAP.md and docs/releasing.md are intentionally kept local-only (gitignored)
# and are NOT part of the public/remote surface. The guardrails below assert the
# public artifacts that must ship in the repository checkout.
_REQUIRED_PUBLIC_ARTIFACTS: tuple[Path, ...] = (
    _REPO_ROOT / "README.md",
    _REPO_ROOT / "CHANGELOG.md",
    _REPO_ROOT / "CONTRIBUTING.md",
    _REPO_ROOT / "SECURITY.md",
    _REPO_ROOT / "docs" / "README.md",
    _REPO_ROOT / "docs" / "release-readiness.md",
    _REPO_ROOT / ".github" / "ISSUE_TEMPLATE" / "false_positive.yml",
)

_PUBLIC_DOCS: tuple[Path, ...] = (
    _REPO_ROOT / "README.md",
    _REPO_ROOT / "CONTRIBUTING.md",
    _REPO_ROOT / "SECURITY.md",
    _REPO_ROOT / "docs" / "README.md",
    _REPO_ROOT / "docs" / "release-readiness.md",
)

_NON_PUBLIC_ARTIFACT_REFERENCES: tuple[str, ...] = (
    "docs/public-launch-checklist.md",
    "docs/public-release-readiness.md",
    "docs/publication-traceability-matrix.md",
    "docs/evidence-packs/",
    "public-release-readiness.md",
    "publication-traceability-matrix.md",
)


def test_required_public_documentation_artifacts_exist() -> None:
    for path in _REQUIRED_PUBLIC_ARTIFACTS:
        assert path.is_file(), f"missing required public artifact: {path.relative_to(_REPO_ROOT)}"


def test_public_docs_reference_supported_release_artifacts_only() -> None:
    readme = (_REPO_ROOT / "README.md").read_text(encoding="utf-8")
    docs_index = (_REPO_ROOT / "docs" / "README.md").read_text(encoding="utf-8")
    contributing = (_REPO_ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")

    assert "docs/release-readiness.md" in readme
    assert "release-readiness.md" in docs_index
    assert "docs/release-readiness.md" in contributing
    assert "False positives" in contributing


def test_non_public_launch_artifacts_are_not_exposed() -> None:
    removed_paths = (
        _REPO_ROOT / "docs" / "public-launch-checklist.md",
        _REPO_ROOT / "docs" / "public-release-readiness.md",
        _REPO_ROOT / "docs" / "publication-traceability-matrix.md",
    )

    for path in removed_paths:
        assert not path.exists(), f"{path.relative_to(_REPO_ROOT)} should stay out of the public repo"

    evidence_dir = _REPO_ROOT / "docs" / "evidence-packs"
    if evidence_dir.exists():
        assert not any(evidence_dir.iterdir()), "docs/evidence-packs/ should not expose public launch evidence"


def test_public_docs_do_not_reference_non_public_launch_artifacts() -> None:
    for path in _PUBLIC_DOCS:
        text = path.read_text(encoding="utf-8")
        for reference in _NON_PUBLIC_ARTIFACT_REFERENCES:
            assert reference not in text, f"{path.relative_to(_REPO_ROOT)} references {reference}"


def test_false_positive_template_mentions_reproducibility() -> None:
    template = (_REPO_ROOT / ".github" / "ISSUE_TEMPLATE" / "false_positive.yml").read_text(encoding="utf-8")
    assert "false-positive" in template
    assert "Steps to reproduce" in template
    assert "smallest reliable reproduction" in template


def test_public_docs_do_not_expose_maintainer_local_paths() -> None:
    forbidden_windows_home = "C:" + "\\" + "Users" + "\\"
    for path in _PUBLIC_DOCS:
        text = path.read_text(encoding="utf-8")
        assert forbidden_windows_home not in text, f"{path.relative_to(_REPO_ROOT)} must not expose Windows user paths"


def test_the_disclosure_policy_names_a_reporting_address_the_reader_can_use() -> None:
    """A security policy whose preferred channel is "when it is enabled" is not a channel.

    `SECURITY.md` named GitHub private vulnerability reporting as the preferred channel while
    the feature was switched off on the repository, and sent the reader who noticed to "a
    private channel you trust" -- naming none. For a project that ships a control asserting
    other repositories have a disclosure path, that is the one page that cannot be aspirational.
    The reporting form is now enabled and linked; this holds the link.
    """

    policy = (_REPO_ROOT / "SECURITY.md").read_text(encoding="utf-8")

    assert "/security/advisories/new" in policy, (
        "SECURITY.md must link the advisory form a reporter actually opens, not only describe "
        "where to click. Verify the feature is still enabled: "
        "`gh api repos/<owner>/<repo>/private-vulnerability-reporting`"
    )
    assert "when it is enabled" not in policy, (
        "SECURITY.md hedges its preferred reporting channel. Either the channel is open and the "
        "policy says so, or the policy names the one that is."
    )
