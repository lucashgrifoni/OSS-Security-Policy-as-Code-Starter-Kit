"""The new manifest readers return `None` for "I could not read this", never an empty answer.

Replacing a text search with a parser buys precision and introduces a failure mode the text
search never had: the parser can refuse. If a refusal came back as "no dependencies declared",
every fix in this release would have turned one false positive into a silent false negative --
a broken `pyproject.toml` would mean "this repository declares no LLM SDK", which is the
`not-applicable` claim ADR-045 exists to forbid.

So each reader has three answers, and this file pins all three: the names it found, the empty
set when the file genuinely declares nothing, and `None` when it could not read the file at all.
Callers turn `None` into `manual-review-required` or into the old raw-text read, never into a
verdict.

The dependency shapes below are the ones that appear in real repositories and that a single
`[project].dependencies` reader would miss: PEP 735 groups, Poetry's group tables, `Pipfile`
and the `poetry.lock` package list. Missing one of them is not a crash -- it is an LLM SDK
that goes undeclared and a control that answers about a repository it only half read.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from oss_policy_kit.application.evaluators import eval_llm_218a_rv_001
from oss_policy_kit.application.evaluators._shared import (
    _declared_dependency_names,
    _flatten_strings,
    _has_content,
    _holds_a_non_empty_file,
    _update_config_names,
)
from oss_policy_kit.domain.models import ControlStatus

#: (label, filename, contents, the names the reader must find -- or None for "unreadable")
_DEPENDENCY_SHAPES: tuple[tuple[str, str, str, set[str] | None], ...] = (
    (
        "pep735-dependency-groups",
        "pyproject.toml",
        '[project]\nname = "a"\nversion = "1"\ndependencies = []\n\n[dependency-groups]\nai = ["openai>=1.2"]\n',
        {"openai"},
    ),
    (
        "poetry-group-table",
        "pyproject.toml",
        '[tool.poetry]\nname = "a"\nversion = "1"\n\n[tool.poetry.group.ai.dependencies]\nanthropic = "^0.34"\n',
        {"anthropic"},
    ),
    (
        "poetry-dev-dependencies",
        "pyproject.toml",
        '[tool.poetry]\nname = "a"\n\n[tool.poetry.dev-dependencies]\nlangchain = "*"\n',
        {"langchain"},
    ),
    (
        # A `group` whose entries are not tables. Poetry would reject it, but the reader is
        # handed whatever is on disk and must skip the malformed entry rather than raise --
        # a `TypeError` here is an exit 3 on a manifest the adopter merely typo'd.
        "poetry-group-entry-not-a-table",
        "pyproject.toml",
        '[tool.poetry]\nname = "a"\n\n[tool.poetry.group]\nai = "not-a-table"\n',
        set(),
    ),
    (
        "pipfile-packages",
        "Pipfile",
        '[packages]\nopenai = "*"\n\n[dev-packages]\npytest = "*"\n',
        {"openai", "pytest"},
    ),
    (
        "poetry-lock-package-list",
        "poetry.lock",
        '[[package]]\nname = "openai"\nversion = "1.2.0"\n\n[[package]]\nname = "httpx"\nversion = "0.27"\n',
        {"openai", "httpx"},
    ),
    (
        "requirements-txt",
        "requirements.txt",
        "# openai is deliberately not used\nhttpx==0.27\nanthropic>=0.34\n",
        {"httpx", "anthropic"},
    ),
    (
        "package-json-both-maps",
        "package.json",
        json.dumps({"dependencies": {"openai": "^4"}, "devDependencies": {"vitest": "^1"}}),
        {"openai", "vitest"},
    ),
    (
        "declares-nothing",
        "pyproject.toml",
        '[project]\nname = "a"\nversion = "1"\ndependencies = []\n',
        set(),
    ),
    ("toml-unparseable", "pyproject.toml", "[project\nname = broken\n", None),
    # Valid TOML carrying no dependency table at all. This case asserted `set()` -- "the project
    # declares nothing" -- which is a claim the file does not support: a pyproject with no
    # `[project]`, no `[dependency-groups]` and no known `[tool.*]` table has said nothing about
    # dependencies, and they may well live in a requirements file next to it. It is a refusal,
    # and the caller falls back to the raw-text read rather than to a verdict. See
    # test_a_layout_the_reader_does_not_know_is_not_an_absent_dependency.py.
    ("toml-with-no-dependency-table", "pyproject.toml", "# only a comment, no tables\n", None),
    ("package-json-unparseable", "package.json", "{not json at all", None),
    ("package-json-root-not-an-object", "package.json", '["openai"]', None),
    ("unknown-manifest-kind", "deps.lock", "openai==1.2.0\n", None),
)


@pytest.mark.parametrize(
    ("label", "filename", "body", "expected"), _DEPENDENCY_SHAPES, ids=[c[0] for c in _DEPENDENCY_SHAPES]
)
def test_a_manifest_reader_finds_the_names_or_admits_it_could_not(
    tmp_path: Path, label: str, filename: str, body: str, expected: set[str] | None
) -> None:
    (tmp_path / filename).write_text(body, encoding="utf-8")

    names = _declared_dependency_names(tmp_path / filename)

    if expected is None:
        assert names is None, (
            f"{label}: the reader could not parse this file and answered {names!r} instead of None. "
            "An empty answer here reads as 'declares no LLM SDK', which is a claim about the "
            "repository the kit has not earned."
        )
    else:
        assert names is not None, f"{label}: the reader refused a file it should have read"
        assert expected <= names, f"{label}: expected {expected} within the declared names, got {names}"


#: (label, filename, contents, the package selectors -- or None for "unreadable")
_UPDATE_CONFIGS: tuple[tuple[str, str, str, set[str] | None], ...] = (
    (
        "dependabot-allow",
        "dependabot.yml",
        "version: 2\nupdates:\n  - package-ecosystem: pip\n    allow:\n      - dependency-name: openai\n",
        {"openai"},
    ),
    (
        "renovate-json-match",
        "renovate.json",
        json.dumps({"packageRules": [{"matchPackageNames": ["openai", "anthropic"]}]}),
        {"openai", "anthropic"},
    ),
    (
        "comment-only",
        "dependabot.yml",
        "version: 2\nupdates:\n  - package-ecosystem: pip  # openai\n",
        set(),
    ),
    ("yaml-unparseable", "dependabot.yml", "updates:\n  - [unclosed\n", None),
    ("json-unparseable", "renovate.json", "{nope", None),
    # Not a refusal. The reader has no filename allow-list -- callers only ever hand it a
    # Dependabot or Renovate path -- so a file it does not recognise parses as YAML and simply
    # carries no selector keys. `set()` is the honest answer: read, and it names nothing.
    ("unrecognised-shape", "updates.cfg", "openai\n", set()),
)


@pytest.mark.parametrize(
    ("label", "filename", "body", "expected"), _UPDATE_CONFIGS, ids=[c[0] for c in _UPDATE_CONFIGS]
)
def test_an_update_config_reader_finds_the_selectors_or_admits_it_could_not(
    tmp_path: Path, label: str, filename: str, body: str, expected: set[str] | None
) -> None:
    (tmp_path / filename).write_text(body, encoding="utf-8")

    selectors = _update_config_names(tmp_path / filename)

    if expected is None:
        assert selectors is None, f"{label}: unreadable config answered {selectors!r} instead of None"
    else:
        assert selectors is not None, f"{label}: the reader refused a file it should have read"
        assert expected <= selectors, f"{label}: expected {expected} within {selectors}"


def test_an_unreadable_update_config_falls_back_instead_of_losing_the_entry(tmp_path: Path) -> None:
    """`LLM-218A-RV-001`'s half of the same rule, at the control boundary.

    The parser is an improvement, so it must not be a way to lose a finding: a config the
    parser chokes on is read the old way rather than reported as "no SDK referenced".
    """

    (tmp_path / ".github").mkdir()
    (tmp_path / ".github" / "dependabot.yml").write_text(
        "updates:\n  - [unclosed\n    dependency-name: openai\n", encoding="utf-8"
    )

    outcome = eval_llm_218a_rv_001(SimpleNamespace(repo_root=tmp_path))

    assert outcome.status is ControlStatus.PASS, (
        "the config names the SDK but the parser could not read the file, and the control "
        f"dropped the entry instead of falling back to the old read: {outcome.reason}"
    )


def test_selector_values_are_flattened_out_of_whatever_nests_them() -> None:
    """Both config formats nest the package name differently, and neither nests it predictably."""

    assert _flatten_strings("OpenAI") == {"openai"}
    assert _flatten_strings(["openai", ["anthropic"]]) == {"openai", "anthropic"}
    assert _flatten_strings({"dependency-name": "openai"}) == {"openai"}
    assert _flatten_strings({"a": [{"b": "openai"}]}) == {"openai"}
    assert _flatten_strings(7) == set()
    assert _flatten_strings(None) == set()


def test_an_artifact_the_kit_cannot_open_does_not_count_as_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The refusal path of the two content checks the artifact controls rely on.

    A file that exists but cannot be read is not an artifact that carries something. Answering
    True here would restore exactly the defect these helpers were written to remove, with the
    added insult that nobody could see the contents to argue about.
    """

    artifact = tmp_path / "MODEL_CARD.md"
    artifact.write_text("# Card\n", encoding="utf-8")
    registry = tmp_path / "prompts"
    registry.mkdir()
    (registry / "system.md").write_text("You are a careful assistant.\n", encoding="utf-8")

    assert _has_content(artifact)
    assert _holds_a_non_empty_file(registry)

    def _refuse(self: Path, *args: object, **kwargs: object) -> str:
        raise OSError(13, "Permission denied")

    monkeypatch.setattr(Path, "read_text", _refuse)

    assert not _has_content(artifact), "an unreadable file was reported as carrying content"
    assert not _holds_a_non_empty_file(registry), "an unreadable registry was reported as populated"


def test_a_directory_the_kit_cannot_even_list_is_not_a_populated_registry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A separate refusal from the one above, and it fails one step earlier.

    The test above makes reading each file fail; this one makes *listing* the directory fail,
    which is what a permission-denied mount actually does. Both have to answer False, and only
    the walk-level one exercises the guard around `rglob`.
    """

    registry = tmp_path / "prompts"
    registry.mkdir()
    (registry / "system.md").write_text("You are a careful assistant.\n", encoding="utf-8")

    assert _holds_a_non_empty_file(registry)

    def _refuse_to_walk(self: Path, *args: object, **kwargs: object) -> object:
        raise OSError(13, "Permission denied")

    monkeypatch.setattr(Path, "rglob", _refuse_to_walk)

    assert not _holds_a_non_empty_file(registry), "a directory the kit could not list was reported as holding a prompt"


def test_an_update_config_the_kit_cannot_open_is_a_refusal_not_an_empty_answer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Unreadable and 'names nothing' are different answers, and only one of them is a claim."""

    config = tmp_path / "dependabot.yml"
    config.write_text(
        "version: 2\nupdates:\n  - package-ecosystem: pip\n    allow:\n      - dependency-name: openai\n",
        encoding="utf-8",
    )

    assert _update_config_names(config) is not None

    def _refuse(self: Path, *args: object, **kwargs: object) -> str:
        raise OSError(13, "Permission denied")

    monkeypatch.setattr(Path, "read_text", _refuse)

    assert _update_config_names(config) is None, (
        "a config the kit could not open answered 'names no package' instead of 'I could not "
        "read this', which is the difference between a refusal and a claim"
    )
