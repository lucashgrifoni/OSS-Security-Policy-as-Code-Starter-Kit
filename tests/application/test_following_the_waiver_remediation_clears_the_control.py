"""Doing what GOV-WAIV-014 says has to clear GOV-WAIV-014.

Found by the 10.0.25 clean-room adopter journey. Following the README quickstart and then
each remediation the report printed took a fresh repository from ``fail=10`` to ``pass=13``
and left this control at ``manual-review-required``. Its remediation said to create
``waivers/policy.yaml`` or ``waivers/README.md``, and the control reads neither: it looks for
``waivers.yaml``, ``waivers.yml``, ``waivers/waivers.yaml`` and ``.oss-policy-kit/waivers.yaml``.
An adopter who did exactly what the kit said stayed where they were, and under
``--fail-on degraded`` kept failing CI with no instruction that would clear it.

The text now names the files the control reads. The list below is taken from that text
rather than repeated here, so advice that names a file the control ignores fails this test
the day it is written.
"""

from __future__ import annotations

import functools
import re
from pathlib import Path

from oss_policy_kit.application.engine import evaluate_repository
from oss_policy_kit.application.loader import ControlSpec, bundled_kit_root, load_catalog, load_profile_by_id
from oss_policy_kit.domain.models import ControlStatus

#: A file the advice tells the adopter to create, written as a code span.
_NAMED_FILE = re.compile(r"`([\w./-]+\.(?:ya?ml|md))`")


@functools.cache
def _catalog() -> dict[str, ControlSpec]:
    return load_catalog(bundled_kit_root() / "controls" / "catalog.yaml")


def _repo(root: Path) -> Path:
    root.mkdir(parents=True)
    (root / "README.md").write_text("# demo\n", encoding="utf-8")
    return root


def _waiver_control(repo: Path) -> object:
    report = evaluate_repository(
        repo_root=repo,
        profile=load_profile_by_id(bundled_kit_root(), "github-level-1"),
        catalog=_catalog(),
        waiver_outcome=None,
        scorecard=None,
    )
    (result,) = [r for r in report.results if r.control_id == "GOV-WAIV-014"]
    return result


def test_the_advice_names_the_files_to_create(tmp_path: Path) -> None:
    """A derived list that comes back empty passes for the wrong reason."""

    result = _waiver_control(_repo(tmp_path / "empty"))

    assert result.status is ControlStatus.MANUAL_REVIEW_REQUIRED  # type: ignore[attr-defined]
    assert _NAMED_FILE.findall(result.remediation), result.remediation  # type: ignore[attr-defined]


def test_every_file_the_advice_names_clears_the_control(tmp_path: Path) -> None:
    unmet = _waiver_control(_repo(tmp_path / "empty"))
    named = sorted(set(_NAMED_FILE.findall(f"{unmet.reason} {unmet.remediation}")))  # type: ignore[attr-defined]

    ignored = []
    for index, name in enumerate(named):
        repo = _repo(tmp_path / f"followed-{index}")
        (repo / name).parent.mkdir(parents=True, exist_ok=True)
        (repo / name).write_text("waivers: []\n", encoding="utf-8")
        if _waiver_control(repo).status is not ControlStatus.PASS:  # type: ignore[attr-defined]
            ignored.append(name)

    assert named
    assert not ignored, f"the advice names files this control does not read: {ignored}"
