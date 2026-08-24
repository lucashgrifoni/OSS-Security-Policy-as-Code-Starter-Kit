"""The refusal and malformed-shape branches of the manifest readers.

`test_a_parser_that_cannot_read_says_so.py` pins the contract on `pyproject.toml` and
`package.json`. The same three answers have to hold for the other three manifests and for the two
text readers, and each of those paths is reached by a real repository: a `Pipfile` on a
permission-denied mount, a `poetry.lock` whose `package` key was hand-edited into a table, a
`requirements.txt` line that is only an option flag.

Every case here is a branch that would otherwise be carried by a `# pragma: no cover`, which
would be a claim that the branch is unreachable. It is not -- it is untested, and these are the
tests.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from oss_policy_kit.application.evaluators._shared import (
    _declared_dependency_names,
    _documents_section,
    _raw_text_mentions,
)


def _refuse(self: Path, *args: object, **kwargs: object) -> object:
    raise OSError(13, "Permission denied")


# --------------------------------------------------------------------------- #
# the two text readers
# --------------------------------------------------------------------------- #


def test_a_document_that_cannot_be_opened_documents_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Not "no section": the reader never saw the file, so it must not answer for it."""

    doc = tmp_path / "SECURITY.md"
    doc.write_text("## Intended purpose\nClassifying tickets.\n", encoding="utf-8")

    assert _documents_section(doc, ("intended purpose",))

    monkeypatch.setattr(Path, "read_text", _refuse)

    assert not _documents_section(doc, ("intended purpose",))


def test_a_manifest_that_cannot_be_opened_mentions_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The raw-text fallback has the same duty as the parser it backs up."""

    manifest = tmp_path / "pyproject.toml"
    manifest.write_text('dependencies = ["openai"]\n', encoding="utf-8")

    assert _raw_text_mentions(manifest, ("openai",))

    monkeypatch.setattr(Path, "read_text", _refuse)

    assert not _raw_text_mentions(manifest, ("openai",))


# --------------------------------------------------------------------------- #
# shapes TOML accepts and Poetry would not
# --------------------------------------------------------------------------- #


def test_a_poetry_group_whose_dependencies_key_is_not_a_table_is_skipped(tmp_path: Path) -> None:
    """`dependencies = "openai"` inside a group parses as TOML and is not a dependency table.

    Raising here would be an exit 3 on a manifest the adopter merely typo'd, and treating the
    string as a name would invent a dependency nobody declared.
    """

    manifest = tmp_path / "pyproject.toml"
    manifest.write_text(
        '[tool.poetry]\nname = "a"\n\n[tool.poetry.group.ai]\ndependencies = "openai"\n',
        encoding="utf-8",
    )

    assert _declared_dependency_names(manifest) == set()


def test_a_pyproject_whose_tool_poetry_is_not_a_table_still_reads_the_rest(tmp_path: Path) -> None:
    """`[tool]` with a scalar `poetry` is legal TOML; the PEP 621 table beside it still counts."""

    manifest = tmp_path / "pyproject.toml"
    manifest.write_text(
        '[project]\nname = "a"\nversion = "1"\ndependencies = ["openai"]\n\n[tool]\npoetry = "not-a-table"\n',
        encoding="utf-8",
    )

    assert _declared_dependency_names(manifest) == {"openai"}


def test_a_pipfile_whose_packages_key_is_not_a_table_declares_nothing(tmp_path: Path) -> None:
    manifest = tmp_path / "Pipfile"
    manifest.write_text('packages = "openai"\n', encoding="utf-8")

    assert _declared_dependency_names(manifest) == set()


def test_a_poetry_lock_whose_package_key_is_not_a_list_declares_nothing(tmp_path: Path) -> None:
    """Read, and it names nothing -- which is a different answer from "I could not read it"."""

    manifest = tmp_path / "poetry.lock"
    manifest.write_text('package = "openai"\n', encoding="utf-8")

    assert _declared_dependency_names(manifest) == set()


def test_a_requirements_line_that_reduces_to_no_name_is_skipped(tmp_path: Path) -> None:
    """A bare marker or separator line carries no package, and must not become one."""

    manifest = tmp_path / "requirements.txt"
    manifest.write_text("===\nhttpx==0.27\n", encoding="utf-8")

    assert _declared_dependency_names(manifest) == {"httpx"}


# --------------------------------------------------------------------------- #
# refusals: the file is there and the reader cannot use it
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("filename", ["Pipfile", "poetry.lock"])
def test_a_toml_manifest_that_cannot_be_opened_is_a_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, filename: str
) -> None:
    manifest = tmp_path / filename
    manifest.write_text('[packages]\nopenai = "*"\n', encoding="utf-8")

    assert _declared_dependency_names(manifest) is not None

    monkeypatch.setattr(Path, "open", _refuse)

    assert _declared_dependency_names(manifest) is None


def test_a_requirements_file_that_cannot_be_opened_is_a_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("openai==1.2.0\n", encoding="utf-8")

    assert _declared_dependency_names(manifest) == {"openai"}

    # `Path.open`, like the TOML case above and for the same reason: the reader reaches this file
    # through `decode_source`, which takes bytes. Patching `read_text` used to land on the reader
    # and now lands on nothing -- the refusal branch stopped being exercised and the coverage
    # floor caught it. `read_bytes` is implemented in terms of `self.open`, so this is the lowest
    # point both readers genuinely share.
    monkeypatch.setattr(Path, "open", _refuse)

    assert _declared_dependency_names(manifest) is None


# --------------------------------------------------------------------------- #
# encoding artefacts that carry no meaning
# --------------------------------------------------------------------------- #


def test_a_byte_order_mark_does_not_hide_the_first_heading(tmp_path: Path) -> None:
    """Found by a metamorphic probe, and it was a regression this campaign introduced.

    The raw-text read that `_markdown_sections` replaced was immune to a BOM -- `"## title" in
    text` does not care what precedes the match. The parser was not, so a `SECURITY.md` saved with
    a signature, which is what several Windows editors do by default, silently lost three
    conformance sections.
    """

    from oss_policy_kit.application.evaluators._shared import _markdown_sections  # noqa: PLC0415

    without = _markdown_sections("## Intended purpose\nClassifying tickets.\n")
    with_bom = _markdown_sections("\ufeff## Intended purpose\nClassifying tickets.\n")

    assert without == [("intended purpose", "Classifying tickets.")]
    assert with_bom == without, "a byte-order mark changed the parsed structure"


# --------------------------------------------------------------------------- #
# the PDM and Hatch tables, and the shapes that are legal TOML but not tables
# --------------------------------------------------------------------------- #


def test_a_pdm_dev_dependencies_key_that_is_not_a_table_recognises_nothing(tmp_path: Path) -> None:
    """`[tool.pdm]` alone says nothing about dependencies, so the file is not conclusive.

    The reader must not count `[tool.pdm]` as a recognised dependency surface merely because the
    tool is configured there: PDM projects declare runtime dependencies in `[project]`, and a
    `[tool.pdm]` holding only build settings has told the reader nothing.
    """

    manifest = tmp_path / "pyproject.toml"
    manifest.write_text("[tool.pdm]\ndistribution = true\n", encoding="utf-8")

    assert _declared_dependency_names(manifest) is None


def test_a_hatch_envs_key_that_is_not_a_table_recognises_nothing(tmp_path: Path) -> None:
    """Same rule one level up: `[tool.hatch]` without `envs` is configuration, not dependencies."""

    manifest = tmp_path / "pyproject.toml"
    manifest.write_text('[tool.hatch.build]\nsources = ["src"]\n', encoding="utf-8")

    assert _declared_dependency_names(manifest) is None


def test_a_hatch_environment_that_is_not_a_table_is_skipped(tmp_path: Path) -> None:
    """A scalar under `[tool.hatch.envs]` is legal TOML; the real environment beside it counts."""

    manifest = tmp_path / "pyproject.toml"
    manifest.write_text(
        '[tool.hatch.envs]\nbroken = "not-a-table"\n\n[tool.hatch.envs.default]\ndependencies = ["openai"]\n',
        encoding="utf-8",
    )

    assert _declared_dependency_names(manifest) == {"openai"}


def test_hatch_extra_dependencies_are_declarations_too(tmp_path: Path) -> None:
    """`extra-dependencies` adds to an inherited set, so it declares as plainly as the base list."""

    manifest = tmp_path / "pyproject.toml"
    manifest.write_text('[tool.hatch.envs.test]\nextra-dependencies = ["anthropic>=0.34"]\n', encoding="utf-8")

    assert _declared_dependency_names(manifest) == {"anthropic"}
