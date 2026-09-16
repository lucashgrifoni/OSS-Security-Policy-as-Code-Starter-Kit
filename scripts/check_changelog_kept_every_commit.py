"""Fail when release-please dropped a commit it should have written into the CHANGELOG.

The defect this exists for: a commit BODY the conventional-commits parser rejects -- an
unbalanced "(", or a nested call such as bytes(range(256)) -- makes release-please omit that
commit from the CHANGELOG while the run stays green. It ate a security fix from the 10.0.22
cycle, and nothing noticed, because there is nothing to notice: the release succeeds and the
entry is simply absent.

Why this checks the OUTCOME rather than replaying the parser. The parser's exact rejection
rule is not pinned, and a hand-written approximation of it would be a second thing to be wrong
about -- it would pass on bodies release-please drops and fail on bodies it keeps. Comparing
what reached the CHANGELOG against what was in the range needs no theory of the parser at all.

The denominator comes from release-please's own output. The section header it writes carries a
compare link, `compare/v10.0.22...v10.0.23`, which is its own statement of the range it read.
Taking the range from there rather than from `git describe` means this compares release-please
against itself instead of against a second guess at what it looked at.

The visible types come from `.github/release-please-config.json`, the same file that decides
them for real, so a type added or hidden there cannot drift from this check. A type marked
`hidden: true`, and any type absent from that file, is expected to be missing and is skipped.

It checks the section that is still being written. When the newest section's tag already
exists, that release is published and its CHANGELOG cannot be changed, so the check would be
reporting history rather than something anyone can act on: it says so and passes. The moment
it exists for is the release branch, where the section is new and the tag is not created yet.

What it does NOT catch: a commit whose SUBJECT the parser rejects outright, because such a
commit has no type this can classify, and a release cut with no new CHANGELOG section at all.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

_COMPARE = re.compile(r"/compare/(v\d+\.\d+\.\d+)\.\.\.(v\d+\.\d+\.\d+)")
_SUBJECT = re.compile(r"^(?P<type>[a-z]+)(?:\([^)]*\))?!?:")


def visible_types(config_path: Path) -> set[str]:
    """The commit types release-please is configured to write into the CHANGELOG."""

    config = json.loads(config_path.read_text(encoding="utf-8"))
    return {e["type"] for e in config.get("changelog-sections", []) if not e.get("hidden")}


def released_range(changelog: str) -> tuple[str, str] | None:
    """The `(previous, current)` tags from the newest section header, or None."""

    match = _COMPARE.search(changelog)
    return (match.group(1), match.group(2)) if match else None


def _commits(previous: str, head: str, repo: Path) -> list[tuple[str, str]]:
    """`(full sha, subject)` for every commit in the range, oldest last.

    `--format=` is a terminator, not a separator: with `--pretty=format:` the final commit
    carries no trailing newline and a line-oriented reader drops it. That exact mistake cost
    three releases their oldest entry in the published notes.
    """

    out = subprocess.run(
        ["git", "log", "--no-merges", "--format=%H%x09%s", f"{previous}..{head}"],
        cwd=repo,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    rows = []
    for line in out.stdout.splitlines():
        if "\t" in line:
            sha, subject = line.split("\t", 1)
            rows.append((sha, subject))
    return rows


def _tag_exists(tag: str, repo: Path) -> bool:
    """Whether *tag* resolves, which is how a published section is told from a pending one."""

    return (
        subprocess.run(
            ["git", "rev-parse", "--verify", f"refs/tags/{tag}"],
            cwd=repo,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
        ).returncode
        == 0
    )


def dropped_commits(commits: list[tuple[str, str]], changelog: str, types: set[str]) -> list[tuple[str, str]]:
    """Every commit of a visible type whose sha the CHANGELOG does not cite."""

    missing = []
    for sha, subject in commits:
        match = _SUBJECT.match(subject)
        if match is None or match.group("type") not in types:
            continue
        if sha not in changelog:
            missing.append((sha, subject))
    return missing


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)

    repo: Path = args.repo
    changelog = (repo / "CHANGELOG.md").read_text(encoding="utf-8")
    types = visible_types(repo / ".github" / "release-please-config.json")

    span = released_range(changelog)
    if span is None:
        print("No compare link in the newest CHANGELOG section; nothing to check.")
        return 0

    previous, current = span
    if _tag_exists(current, repo):
        print(
            f"{current} is already tagged, so its CHANGELOG section is published history "
            "rather than something this run can change. Nothing to check."
        )
        return 0

    commits = _commits(previous, "HEAD", repo)
    missing = dropped_commits(commits, changelog, types)

    print(f"Range {previous}..{current}: {len(commits)} commits, visible types {sorted(types)}")
    if not missing:
        print("Every commit of a visible type is cited in the CHANGELOG.")
        return 0

    print(f"\n{len(missing)} commit(s) of a visible type are missing from the CHANGELOG:")
    for sha, subject in missing:
        print(f"  {sha[:12]}  {subject}")
    print(
        "\nrelease-please read these commits and wrote none of them. The usual cause is a "
        "commit BODY its parser rejects, such as an unbalanced '(' or a nested call. Fix the "
        "body on the release branch and let the workflow refresh the PR."
    )
    return 1


if __name__ == "__main__":  # pragma: no cover - exercised through main() in tests
    sys.exit(main())
