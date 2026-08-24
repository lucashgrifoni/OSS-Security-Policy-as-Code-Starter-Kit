"""A dependency is what a manifest DECLARES, not what its text happens to contain.

Two controls decided whether a repository uses an LLM SDK by lowercasing a manifest and looking
for a package name anywhere in it. So

    # we evaluated openai and rejected it        (pyproject.toml)
    # no openai packages are used in this repo   (.github/dependabot.yml)

each satisfied "an LLM SDK is present" and "the dependency-update config explicitly references
an LLM SDK" -- using the strongest available statement that the SDK is *not* used as proof that
it is. A commented-out requirement line did the same.

These files are parseable, so the fix is to read the values that carry the meaning: the
dependency tables of `pyproject.toml`, `package.json`, `requirements.txt`, `Pipfile` and
`poetry.lock`, and the package-selecting keys of a Dependabot or Renovate config.

**Both directions are asserted on every case.** Two earlier fixes in this release removed a
false positive by removing a true finding as well, and the only defence against repeating that
is a test that fails when the real dependency stops being found. Each lab below appears twice:
once with the SDK merely mentioned, once with it genuinely declared.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from oss_policy_kit.application.evaluators import eval_llm_218a_pw_001, eval_llm_218a_rv_001
from oss_policy_kit.domain.models import ControlStatus

#: (label, files, the SDK is genuinely declared)
_MANIFEST_CASES: tuple[tuple[str, dict[str, str], bool], ...] = (
    (
        "pyproject-comment",
        {
            "pyproject.toml": (
                '[project]\nname = "a"\nversion = "1"\n'
                "# we evaluated openai and rejected it\n"
                'dependencies = ["httpx"]\n'
            )
        },
        False,
    ),
    (
        "pyproject-declared",
        {"pyproject.toml": '[project]\nname = "a"\nversion = "1"\ndependencies = ["openai>=1.2", "httpx"]\n'},
        True,
    ),
    (
        "pyproject-optional-extra",
        {
            "pyproject.toml": (
                '[project]\nname = "a"\nversion = "1"\ndependencies = []\n\n'
                '[project.optional-dependencies]\nai = ["anthropic"]\n'
            )
        },
        True,
    ),
    (
        "poetry-group",
        {
            "pyproject.toml": (
                '[tool.poetry]\nname = "a"\nversion = "1"\n\n[tool.poetry.group.dev.dependencies]\nlangchain = "^0.2"\n'
            )
        },
        True,
    ),
    (
        "requirements-commented",
        {"requirements.txt": "httpx==0.27.0\n# openai==1.2.0  # disabled for now\n"},
        False,
    ),
    (
        "requirements-declared",
        {"requirements.txt": "httpx==0.27.0\nopenai==1.2.0\n"},
        True,
    ),
    (
        "requirements-marker-and-extra",
        {"requirements.txt": "openai[datalib]>=1.2 ; python_version<'3.13'\n"},
        True,
    ),
    (
        "package-json-comment-like-name",
        {
            "package.json": json.dumps(
                {"name": "a", "description": "we removed openai", "dependencies": {"axios": "^1"}}
            )
        },
        False,
    ),
    (
        "package-json-declared",
        {"package.json": json.dumps({"name": "a", "dependencies": {"openai": "^4"}})},
        True,
    ),
    (
        "unparseable-falls-back",
        # A manifest the parser cannot read keeps the older, blunter behaviour on purpose: a fix
        # for a false positive must not become a dependency the kit stops finding.
        {"pyproject.toml": '[project\nname = "broken"\ndependencies = ["openai"]\n'},
        True,
    ),
)

#: (label, files, the config genuinely names an SDK)
_UPDATE_CONFIG_CASES: tuple[tuple[str, dict[str, str], bool], ...] = (
    (
        "dependabot-comment",
        {
            ".github/dependabot.yml": (
                'version: 2\nupdates:\n  - package-ecosystem: "npm"\n    directory: "/"\n'
                "    schedule:\n      interval: weekly\n# no openai packages are used in this repo\n"
            )
        },
        False,
    ),
    (
        "dependabot-allow-entry",
        {
            ".github/dependabot.yml": (
                'version: 2\nupdates:\n  - package-ecosystem: "pip"\n    directory: "/"\n'
                '    schedule:\n      interval: weekly\n    allow:\n      - dependency-name: "openai"\n'
            )
        },
        True,
    ),
    (
        "dependabot-group-pattern",
        {
            ".github/dependabot.yml": (
                'version: 2\nupdates:\n  - package-ecosystem: "pip"\n    directory: "/"\n'
                "    schedule:\n      interval: weekly\n    groups:\n      ai:\n"
                '        patterns:\n          - "langchain*"\n'
            )
        },
        True,
    ),
    (
        "renovate-match-names",
        {"renovate.json": json.dumps({"packageRules": [{"matchPackageNames": ["anthropic"], "automerge": True}]})},
        True,
    ),
    (
        "renovate-description-only",
        {"renovate.json": json.dumps({"description": "we do not use openai here", "packageRules": []})},
        False,
    ),
)


def _repo(tmp_path: Path, files: dict[str, str]) -> SimpleNamespace:
    for rel, body in files.items():
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")
    return SimpleNamespace(repo_root=tmp_path)


@pytest.mark.parametrize(("label", "files", "declared"), _MANIFEST_CASES, ids=[c[0] for c in _MANIFEST_CASES])
def test_an_llm_sdk_counts_when_the_manifest_declares_it(
    tmp_path: Path, label: str, files: dict[str, str], declared: bool
) -> None:
    outcome = eval_llm_218a_pw_001(_repo(tmp_path, files))

    if declared:
        assert outcome.status is ControlStatus.PASS, (
            f"{label}: the SDK is a real declared dependency and the control no longer finds it "
            f"({outcome.status.value}). Removing a false positive must not remove a true finding: "
            f"{outcome.reason}"
        )
    else:
        assert outcome.status is not ControlStatus.PASS, (
            f"{label}: the only mention of the SDK is prose that says it is NOT used, and the "
            f"control reported it as present: {outcome.reason}"
        )


@pytest.mark.parametrize(("label", "files", "declared"), _UPDATE_CONFIG_CASES, ids=[c[0] for c in _UPDATE_CONFIG_CASES])
def test_an_update_config_counts_when_it_selects_the_package(
    tmp_path: Path, label: str, files: dict[str, str], declared: bool
) -> None:
    outcome = eval_llm_218a_rv_001(_repo(tmp_path, files))

    if declared:
        assert outcome.status is ControlStatus.PASS, (
            f"{label}: the config selects the SDK through a real entry and the control no longer "
            f"sees it ({outcome.status.value}): {outcome.reason}"
        )
    else:
        assert outcome.status is not ControlStatus.PASS, (
            f"{label}: a comment or description is not a package selector, and the control "
            f"reported the SDK as covered: {outcome.reason}"
        )


def test_a_requirement_specifier_reduces_to_its_package_name() -> None:
    """The unit under the two tests above, exercised on the shapes that appear in the wild."""

    from oss_policy_kit.application.evaluators._shared import _requirement_name  # noqa: PLC0415

    assert _requirement_name("openai>=1.2") == "openai"
    assert _requirement_name("openai[datalib]>=1.2 ; python_version<'3.13'") == "openai"
    assert _requirement_name("  Anthropic == 0.34.0  ") == "anthropic"
    assert _requirement_name("langchain-openai~=0.1") == "langchain-openai"
    assert _requirement_name("httpx") == "httpx"


#: (label, `pyproject.toml`, this repository is an agent)
_AGENTIC_GATE_CASES: tuple[tuple[str, str, bool], ...] = (
    (
        "declared",
        '[project]\nname = "a"\nversion = "1"\ndependencies = ["langchain"]\n',
        True,
    ),
    (
        "mentioned-in-a-comment",
        '[project]\nname = "a"\nversion = "1"\n'
        "# we looked at langchain and did not adopt it\n"
        'dependencies = ["httpx"]\n',
        False,
    ),
    (
        "unparseable-but-mentioned",
        '[project\nname = "a"\ndependencies = ["langchain"\n',
        True,
    ),
    (
        "unparseable-and-absent",
        "[project\nname = broken\n",
        False,
    ),
)


@pytest.mark.parametrize(("label", "manifest", "agentic"), _AGENTIC_GATE_CASES, ids=[c[0] for c in _AGENTIC_GATE_CASES])
def test_the_agentic_gate_reads_declarations_and_still_falls_back(
    tmp_path: Path, label: str, manifest: str, agentic: bool
) -> None:
    """The gate that decides whether the twelve `AGENT-ASI-*`/`AI-AGENT-*` controls run at all.

    A comment must not switch the family on -- but a manifest the parser cannot read must not
    switch it *off* either. An unparseable file is not evidence of absence, so the gate keeps
    the old raw-text read for exactly that case: whatever used to be found is still found.
    """

    from oss_policy_kit.application.evaluators._shared import _agentic_applicable  # noqa: PLC0415

    (tmp_path / "pyproject.toml").write_text(manifest, encoding="utf-8")

    applicable, found = _agentic_applicable(tmp_path)

    assert applicable is agentic, (
        f"{label}: the gate said applicable={applicable}. A comment is not a declaration, and an "
        f"unreadable manifest is not proof the framework is absent. Evidence: {found}"
    )
