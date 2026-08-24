""" "Every dependency manifest was read" may not be printed when one of them was not.

`_llm_sdk_scan` walks five manifests and carries a single `conclusive` flag. The flag was set by
any manifest that could be read, so one readable `pyproject.toml` made the whole scan conclusive
even when the `package.json` beside it was malformed and skipped. `LLM-218A-PW-001` then answered
`not-applicable` -- "LLM controls do not apply to this repository" -- and said in its reason that
every manifest had been read, about a repository holding a manifest it never opened.

An OR across the files answers "did I read ANY of them". The claim needs "did I read ALL of them",
which is an AND, and the difference only shows up in the mixed case nobody writes a fixture for.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from oss_policy_kit.application.evaluators import eval_llm_218a_pw_001
from oss_policy_kit.domain.models import ControlStatus

_READABLE_PYPROJECT = '[project]\nname = "a"\nversion = "1"\ndependencies = ["httpx"]\n'

#: (label, files, expected status)
_CASES: tuple[tuple[str, dict[str, str], ControlStatus], ...] = (
    (
        "one-readable-one-broken",
        {"pyproject.toml": _READABLE_PYPROJECT, "package.json": "{ this is not json"},
        ControlStatus.MANUAL_REVIEW_REQUIRED,
    ),
    (
        "one-readable-one-broken-lockfile",
        {"pyproject.toml": _READABLE_PYPROJECT, "poetry.lock": "[[package\nname = broken\n"},
        ControlStatus.MANUAL_REVIEW_REQUIRED,
    ),
    # The counterpart: every manifest present was read and none declares an SDK, so the claim is
    # earned and `not-applicable` stays available.
    (
        "every-manifest-readable",
        {
            "pyproject.toml": _READABLE_PYPROJECT,
            "package.json": json.dumps({"dependencies": {"axios": "^1"}}),
        },
        ControlStatus.NOT_APPLICABLE,
    ),
    (
        "single-readable-manifest",
        {"pyproject.toml": _READABLE_PYPROJECT},
        ControlStatus.NOT_APPLICABLE,
    ),
    # A manifest that PARSED but declares under a table the reader does not know costs the claim
    # in the same way an unparseable one does -- and the readable file beside it must not buy it
    # back. Without this case the AND is indistinguishable from the OR it replaced.
    (
        "one-readable-one-unknown-surface",
        {
            "pyproject.toml": (
                '[project]\nname = "a"\nversion = "1"\ndependencies = []\n\n[tool.futurepm]\ndependencies = ["httpx"]\n'
            ),
            "package.json": json.dumps({"dependencies": {"axios": "^1"}}),
        },
        ControlStatus.MANUAL_REVIEW_REQUIRED,
    ),
    # No manifest at all is not "every manifest was read". Without this case the flag could drop
    # the "did any exist" half and nothing would notice.
    ("no-manifest-at-all", {"main.go": "package main\n"}, ControlStatus.MANUAL_REVIEW_REQUIRED),
)


def _repo(tmp_path: Path, files: dict[str, str]) -> SimpleNamespace:
    for rel, body in files.items():
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")
    return SimpleNamespace(repo_root=tmp_path)


@pytest.mark.parametrize(("label", "files", "expected"), _CASES, ids=[c[0] for c in _CASES])
def test_a_manifest_that_was_skipped_costs_the_claim(
    tmp_path: Path, label: str, files: dict[str, str], expected: ControlStatus
) -> None:
    outcome = eval_llm_218a_pw_001(_repo(tmp_path, files))

    assert outcome.status is expected, (
        f"{label}: expected {expected.value} and got {outcome.status.value}. A manifest the kit "
        f"could not open is one it cannot speak for: {outcome.reason}"
    )
