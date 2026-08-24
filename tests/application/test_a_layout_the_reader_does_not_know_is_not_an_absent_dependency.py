"""`not-applicable` needs a dependency surface the reader RECOGNISED, not a file that parsed.

`_llm_sdk_scan` marked a manifest conclusive whenever it parsed. Parsing is not reading: a
`pyproject.toml` is perfectly valid TOML whether its dependencies live in `[project]`, in
`[tool.pdm.dev-dependencies]`, in `[tool.hatch.envs.default]`, or in a table no version of this
kit has heard of. The reader knew three of those layouts and answered "declares nothing" for the
rest -- so eight agentic and LLM controls announced *"LLM controls do not apply to this
repository"* about a repository whose `pyproject.toml` declares `openai` on the next line.

That is the worst available direction for a wrong answer. `not-applicable` is a positive claim
and it is the one state no summary counts, so nobody reading the report sees a number move.

Measured against `HEAD` before the fix, three shapes went `pass` -> `not-applicable`:

    -e git+https://github.com/openai/openai-python.git#egg=openai   (requirements.txt)
    [tool.pdm.dev-dependencies]   ai = ["openai"]
    [tool.hatch.envs.default]     dependencies = ["openai"]

Two defects, and each needs its own half. The first is a parse gap inside a surface the reader
DOES know: `_requirements_names` skipped every line beginning `-`, which is right for `--hash`
and `-r` and wrong for `-e ...#egg=NAME`, where the egg fragment is the package name. The second
is a recognition gap: PDM and Hatch were simply not read, and because the file parsed the caller
treated silence as an answer.

Fixing only the known layouts would leave the class open for the next one. So the reader now says
`None` -- "I recognised no dependency surface here" -- and the caller treats that the way it
already treats an unreadable file: it falls back to the raw-text read rather than to a verdict,
and it refuses to call the repository conclusive. A layout nobody has written yet gets the same
treatment on the day it appears.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from oss_policy_kit.application.evaluators import eval_llm_218a_pw_001
from oss_policy_kit.domain.models import ControlStatus

#: (label, files, the repository really declares an LLM SDK)
_DECLARED: tuple[tuple[str, dict[str, str], bool], ...] = (
    (
        "requirements-editable-vcs-egg",
        {"requirements.txt": "-e git+https://github.com/openai/openai-python.git#egg=openai\n"},
        True,
    ),
    (
        "pdm-dev-dependencies",
        {
            "pyproject.toml": (
                '[project]\nname = "a"\nversion = "1"\ndependencies = []\n\n'
                '[tool.pdm.dev-dependencies]\nai = ["openai>=1.2"]\n'
            )
        },
        True,
    ),
    (
        "hatch-environment-dependencies",
        {
            "pyproject.toml": (
                '[project]\nname = "a"\nversion = "1"\ndependencies = []\n\n'
                '[tool.hatch.envs.default]\ndependencies = ["anthropic"]\n'
            )
        },
        True,
    ),
    (
        # The counterpart for the egg fragment: the option lines that really do name no package
        # must keep being skipped, or `-r base.txt` starts declaring a package called "base".
        "requirements-option-lines-only",
        {"requirements.txt": "-r base.txt\n--hash=sha256:abc\n-c constraints.txt\nhttpx==0.27\n"},
        False,
    ),
    (
        # A recognised surface that genuinely declares no SDK stays a genuine `not-applicable`.
        "pep621-without-an-sdk",
        {"pyproject.toml": '[project]\nname = "a"\nversion = "1"\ndependencies = ["httpx"]\n'},
        False,
    ),
    (
        # And the defect the parsing replaced must stay dead: a comment is not a declaration,
        # even in a file whose dependency surface the reader knows.
        "recognised-surface-with-only-a-comment",
        {
            "pyproject.toml": (
                '[project]\nname = "a"\nversion = "1"\n'
                "# we evaluated openai and rejected it\n"
                'dependencies = ["httpx"]\n'
            )
        },
        False,
    ),
)


def _repo(tmp_path: Path, files: dict[str, str]) -> SimpleNamespace:
    for rel, body in files.items():
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")
    return SimpleNamespace(repo_root=tmp_path)


@pytest.mark.parametrize(("label", "files", "declared"), _DECLARED, ids=[c[0] for c in _DECLARED])
def test_a_declared_sdk_is_found_in_every_layout_the_reader_claims_to_know(
    tmp_path: Path, label: str, files: dict[str, str], declared: bool
) -> None:
    outcome = eval_llm_218a_pw_001(_repo(tmp_path, files))

    if declared:
        assert outcome.status is ControlStatus.PASS, (
            f"{label}: this manifest declares an LLM SDK and the control no longer finds it "
            f"({outcome.status.value}). Removing a false positive must not remove a true "
            f"finding: {outcome.reason}"
        )
    else:
        assert outcome.status is not ControlStatus.PASS, (
            f"{label}: nothing here declares an SDK and the control reported one: {outcome.reason}"
        )


def test_an_unrecognised_dependency_surface_is_not_an_absent_dependency(tmp_path: Path) -> None:
    """The claim rule, at the control boundary.

    A `pyproject.toml` carrying only build configuration tells the kit nothing about what the
    project depends on. Answering `not-applicable` there states that LLM controls do not apply to
    the repository, on the strength of a file that was never about dependencies.
    """

    outcome = eval_llm_218a_pw_001(
        _repo(
            tmp_path,
            {
                "pyproject.toml": (
                    '[build-system]\nrequires = ["setuptools"]\nbuild-backend = "setuptools.build_meta"\n\n'
                    "[tool.ruff]\nline-length = 120\n"
                )
            },
        )
    )

    assert outcome.status is not ControlStatus.NOT_APPLICABLE, (
        "the only manifest present declares no dependencies anywhere the reader understands, and "
        f"the control still announced that LLM controls do not apply to this repository: {outcome.reason}"
    )


def test_a_recognised_but_empty_surface_is_still_a_real_answer(tmp_path: Path) -> None:
    """The counterpart, so the rule above cannot be satisfied by refusing to answer at all.

    `[project]` with no `dependencies` key is PEP 621 for "this project has no dependencies".
    That is a surface the reader understands and an answer it is entitled to give.
    """

    outcome = eval_llm_218a_pw_001(_repo(tmp_path, {"pyproject.toml": '[project]\nname = "a"\nversion = "1"\n'}))

    assert outcome.status is ControlStatus.NOT_APPLICABLE, (
        "an empty PEP 621 dependency list is a real statement that the project declares nothing, "
        f"and the control declined to use it: {outcome.reason}"
    )


#: (label, requirements.txt body, the SDK is genuinely declared)
#:
#: `#egg=` is a URL fragment, not a comment -- but `#` also opens a comment in a requirements
#: file, and the egg search ran over the whole line before anything separated the two. So a
#: pinned requirement whose trailing comment happened to mention an egg fragment declared that
#: package: the comment-decides-the-verdict class, walked back in through the repair for it.
#:
#: pip's own parser is `[#&]egg=`, because a URL may carry `#subdirectory=src&egg=name` -- the
#: order pip's documentation itself uses. Matching only `#egg=` drops the SDK from a line that
#: really does install it.
_EGG_FRAGMENTS: tuple[tuple[str, str, bool], ...] = (
    ("hash-fragment", "-e git+https://example.invalid/y.git#egg=openai\n", True),
    ("ampersand-fragment", "-e git+https://example.invalid/y.git#subdirectory=src&egg=openai\n", True),
    ("fragment-in-a-trailing-comment", "httpx==0.27  # we do not use #egg=openai here\n", False),
    ("comment-only-line", "# -e git+https://example.invalid/y.git#egg=openai\n", False),
)


@pytest.mark.parametrize(("label", "body", "declared"), _EGG_FRAGMENTS, ids=[c[0] for c in _EGG_FRAGMENTS])
def test_an_egg_fragment_declares_a_package_only_where_pip_would_read_one(
    tmp_path: Path, label: str, body: str, declared: bool
) -> None:
    outcome = eval_llm_218a_pw_001(_repo(tmp_path, {"requirements.txt": body}))

    if declared:
        assert outcome.status is ControlStatus.PASS, (
            f"{label}: pip installs this package from this line and the reader did not see it "
            f"({outcome.status.value}): {outcome.reason}"
        )
    else:
        assert outcome.status is not ControlStatus.PASS, (
            f"{label}: the only mention of the SDK is inside a comment, and the control reported "
            f"it as a declared dependency: {outcome.reason}"
        )
