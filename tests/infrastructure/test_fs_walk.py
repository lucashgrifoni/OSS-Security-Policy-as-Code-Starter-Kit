"""The shared discovery walk behind every IaC and Kubernetes scanner.

This decides which files each scanner sees, so every rejection here is a file that will never
be scanned and every duplicate is a finding reported twice. It is deliberately conservative in
four ways, and all four are asserted: directories are not files, a path that resolves outside
the repository root is not ours to scan, a noisy directory (vendor, cache, virtualenv) is
skipped whatever it contains, and an operator exclude wins over an include.

De-duplication is by *resolved* path, not by the glob that found it, so a file matched by two
include patterns -- or reached through a symlinked directory -- is scanned and reported once.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from oss_policy_kit.infrastructure.fs_walk import walk_matching_files

_SKIP = frozenset({"node_modules", ".git", ".venv"})


def _file(root: Path, rel: str, body: str = "x") -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path


def _names(paths: list[Path]) -> list[str]:
    return sorted(p.name for p in paths)


def test_matching_files_are_returned(tmp_path: Path) -> None:
    _file(tmp_path, "main.tf")
    _file(tmp_path, "modules/vpc/main.tf")
    found = walk_matching_files(tmp_path, ["**/*.tf"], None, _SKIP)
    assert _names(found) == ["main.tf", "main.tf"]


def test_a_directory_is_not_a_match(tmp_path: Path) -> None:
    """A glob can match a directory named like a file; scanning one would raise on read."""

    (tmp_path / "weird.tf").mkdir()
    assert walk_matching_files(tmp_path, ["**/*.tf"], None, _SKIP) == []


@pytest.mark.parametrize("noisy", ["node_modules", ".git", ".venv"])
def test_a_noisy_directory_is_skipped_whatever_it_contains(noisy: str, tmp_path: Path) -> None:
    """Vendored Terraform is somebody else's posture, and scanning it inflates every count."""

    _file(tmp_path, f"{noisy}/pkg/main.tf")
    _file(tmp_path, "main.tf")
    assert _names(walk_matching_files(tmp_path, ["**/*.tf"], None, _SKIP)) == ["main.tf"]


def test_an_operator_exclude_wins_over_an_include(tmp_path: Path) -> None:
    _file(tmp_path, "main.tf")
    _file(tmp_path, "generated.tf")
    found = walk_matching_files(tmp_path, ["**/*.tf"], ["*generated*"], _SKIP)
    assert _names(found) == ["main.tf"]


def test_no_excludes_rejects_nothing(tmp_path: Path) -> None:
    """The counterpart: an empty exclude tuple must not behave like a match-everything one."""

    _file(tmp_path, "main.tf")
    assert _names(walk_matching_files(tmp_path, ["**/*.tf"], [], _SKIP)) == ["main.tf"]


def test_a_file_matched_by_two_patterns_is_returned_once(tmp_path: Path) -> None:
    """De-duplication is by resolved path; otherwise the finding is reported twice."""

    _file(tmp_path, "main.tf")
    found = walk_matching_files(tmp_path, ["**/*.tf", "*.tf"], None, _SKIP)
    assert len(found) == 1, found


def test_a_path_resolving_outside_the_root_is_not_ours_to_scan(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A symlink escaping --target would report findings against a tree nobody asked about."""

    _file(tmp_path, "main.tf")
    outside = tmp_path.parent / "elsewhere.tf"
    real_resolve = Path.resolve

    def _resolve(self: Path, *args: object, **kwargs: object) -> Path:
        if self.name == "main.tf":
            return outside
        return real_resolve(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "resolve", _resolve)
    assert walk_matching_files(tmp_path, ["**/*.tf"], None, _SKIP) == []


def test_an_include_pattern_that_matches_nothing_yields_nothing(tmp_path: Path) -> None:
    _file(tmp_path, "main.tf")
    assert walk_matching_files(tmp_path, ["**/*.bicep"], None, _SKIP) == []


def test_each_candidate_is_resolved_once_and_the_root_is_not_re_resolved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The walk must not pay for the same ``resolve()`` twice.

    A wall-clock assertion would be flaky on a shared runner, so the guard counts calls
    instead: the cost this pins is a syscall count, and a syscall count is deterministic.

    It used to resolve three paths per candidate -- the candidate for the ``relative_to``
    comparison, the root again although it cannot change inside the loop, and the candidate
    a second time to build the return value. On Windows each ``Path.resolve()`` is two
    ``nt._getfinalpathname`` calls, so a 20,002-file Python tree cost 120,012 of them and
    ``scan-pulumi`` spent 8.56s of a 14.76s run inside this walk against 0.61s of actual
    parsing. The budget is now one resolve per candidate plus exactly one for the root.

    Written as ``<=`` on the per-candidate figure rather than ``==`` so a future change that
    resolves *less* is not reported as a regression; the root is pinned at exactly one,
    because that is the loop-invariant that regressed before.
    """

    for i in range(7):
        _file(tmp_path, f"mod{i}/main.tf")
    root_resolved = tmp_path.resolve()

    calls: list[Path] = []
    real_resolve = Path.resolve

    def _counting_resolve(self: Path, *args: object, **kwargs: object) -> Path:
        calls.append(self)
        return real_resolve(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "resolve", _counting_resolve)
    found = walk_matching_files(tmp_path, ["**/*.tf"], None, _SKIP)

    assert len(found) == 7, found
    root_resolves = sum(1 for c in calls if real_resolve(c) == root_resolved)
    assert root_resolves == 1, f"root resolved {root_resolves} times, expected exactly 1"
    assert len(calls) <= len(found) + 1, (
        f"{len(calls)} resolve() calls for {len(found)} candidates; budget is one each plus one root"
    )
