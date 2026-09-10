"""Guard: documented Action tag references match the shipped version.

The composite Action is advertised in several places. Each `@vX.Y.Z` reference is a copy-paste
target, so a stale one hands the reader an Action release older than the kit they just installed.
Four had drifted before this guard existed: README.md pinned `@v7.2.0`, docs/quickstart-15-min.md
`@v7.2.0`, and docs/github-action.md carried `@v10.0.1` *and* `@v6.4.0` — up to four majors behind.

Each is now annotated with `# x-release-please-version` and its file is listed under `extra-files`
in `.github/release-please-config.json`, so release-please rewrites them on every release. This test
is the backstop: it fails if a reference drifts from the packaged version, if a new reference is
added without the annotation, or if a file carrying one drops out of `extra-files`.

Commit-SHA pins are deliberately exempt: the SHA of a release commit cannot be known before that
release exists, so it necessarily trails by one version and release-please cannot rewrite it.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

from oss_policy_kit import __version__

REPO_ROOT = Path(__file__).resolve().parents[2]
RELEASE_PLEASE_CONFIG = REPO_ROOT / ".github" / "release-please-config.json"

_ACTION = "lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit"
# `@v1.2.3` tag references only; a 40-hex commit pin is matched separately and skipped.
_TAG_REF = re.compile(rf"{re.escape(_ACTION)}@v(\d+\.\d+\.\d+)")
_SHA_REF = re.compile(rf"{re.escape(_ACTION)}@[0-9a-f]{{40}}")
_ANNOTATION = "x-release-please-version"


def _searchable_files() -> list[Path]:
    """Every git-tracked Markdown/YAML file.

    Deliberately asks git rather than walking the tree with a skip-list. "Tracked" is exactly
    what "shipped" means here, and a skip-list has to be extended for every new scratch
    directory: an earlier version of this helper walked the whole tree and flagged a stale pin
    inside gitignored `.tmp-validation/` scratch output, which no reader ever sees.
    """

    out = subprocess.run(
        ["git", "ls-files", "-z", "*.md", "*.yml", "*.yaml"],
        cwd=REPO_ROOT,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        text=True,
        check=True,
    ).stdout
    return [REPO_ROOT / rel for rel in out.split("\0") if rel]


def _tag_reference_lines() -> list[tuple[Path, int, str]]:
    hits: list[tuple[Path, int, str]] = []
    for path in _searchable_files():
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if _ACTION not in text:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            if _SHA_REF.search(line):
                continue
            if _TAG_REF.search(line):
                hits.append((path, lineno, line.strip()))
    return hits


def test_documented_action_tag_matches_packaged_version() -> None:
    stale = [
        f"{path.relative_to(REPO_ROOT).as_posix()}:{lineno}: {line}"
        for path, lineno, line in _tag_reference_lines()
        if _TAG_REF.search(line).group(1) != __version__  # type: ignore[union-attr]
    ]
    assert not stale, (
        f"These Action references do not match the packaged version {__version__}. "
        "A reader copying them gets an older Action than the kit they installed:\n  " + "\n  ".join(stale)
    )


def test_every_action_tag_reference_is_release_please_annotated() -> None:
    unannotated = [
        f"{path.relative_to(REPO_ROOT).as_posix()}:{lineno}: {line}"
        for path, lineno, line in _tag_reference_lines()
        if _ANNOTATION not in line
    ]
    assert not unannotated, (
        f"These Action references lack the `{_ANNOTATION}` annotation, so release-please will not "
        "bump them and they will silently go stale:\n  " + "\n  ".join(unannotated)
    )


def test_files_with_annotated_references_are_release_please_extra_files() -> None:
    config = json.loads(RELEASE_PLEASE_CONFIG.read_text(encoding="utf-8"))
    extra_files = set(config["packages"]["."]["extra-files"])
    missing = sorted(
        {path.relative_to(REPO_ROOT).as_posix() for path, _, line in _tag_reference_lines() if _ANNOTATION in line}
        - extra_files
    )
    assert not missing, (
        "These files carry an annotated Action reference but are not in the release-please "
        "`extra-files` list, so the annotation is inert:\n  " + "\n  ".join(missing)
    )


def test_guard_actually_finds_the_known_references() -> None:
    """Mutation check: the guard must be scanning something, not passing on an empty set."""

    assert len(_tag_reference_lines()) >= 3


# Any `uses:` line in tracked docs and templates. Third-party actions are covered here;
# the kit's own Action is handled by the tests above.
_ANY_USES = re.compile(r"^\s*(-\s*)?uses:\s*(?P<ref>\S+@\S+)")
_SHA_PINNED = re.compile(r"@[0-9a-f]{40}\b")


def test_no_third_party_action_is_referenced_by_mutable_tag() -> None:
    """Guard: documented third-party actions are SHA-pinned.

    `docs/github-action.md` showed `github/codeql-action/upload-sarif@v3` - mutable, and a major
    behind what the repo itself runs. Readers copy these blocks verbatim, and `CI-PIN-008` flags
    exactly this pattern, so a mutable reference in the kit's own documentation contradicts the
    control it ships.

    The kit's own Action is exempt: it is deliberately shown as a readable `@vX.Y.Z` tag that
    release-please rewrites, with a SHA-pinned example alongside it.
    """

    offenders: list[str] = []
    for path in _searchable_files():
        if "examples" in path.parts and "vulnerable-repo" in path.parts:
            continue  # deliberately insecure fixture
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            m = _ANY_USES.match(line)
            if not m:
                continue
            ref = m.group("ref")
            if _ACTION in ref or _SHA_PINNED.search(ref):
                continue
            offenders.append(f"{path.relative_to(REPO_ROOT).as_posix()}:{lineno}: {line.strip()}")

    assert not offenders, (
        "These third-party actions are referenced by a mutable tag in shipped docs or templates. "
        "Pin them to a commit SHA with the tag in a trailing comment:\n  " + "\n  ".join(offenders)
    )


# --------------------------------------------------------------------------- #
# pre-commit `rev:` pins are the same promise in a different shape
# --------------------------------------------------------------------------- #

#: A pre-commit `rev: vX.Y.Z` line. `_TAG_REF` above cannot see these: a pre-commit config names
#: the repository on the `repo:` line and its version two lines below on `rev:`, so nothing that
#: matches `owner/repo@vX.Y.Z` matches here.
_REV_PIN = re.compile(r"^\s*#?\s*rev:\s*v(\d+\.\d+\.\d+)")


def _rev_pin_lines() -> list[tuple[Path, int, str]]:
    """Every `rev: vX.Y.Z` in a tracked file that also names this repository."""

    hits: list[tuple[Path, int, str]] = []
    for path in _searchable_files():
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        # `.pre-commit-hooks.yaml` documents the snippet without repeating the full slug on the
        # same line, so the file is included when either the slug or a hook id is present.
        if _ACTION not in text and "oss-policy-kit-evaluate" not in text:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            if _REV_PIN.match(line):
                hits.append((path, lineno, line.strip()))
    return hits


def test_documented_pre_commit_rev_matches_packaged_version() -> None:
    """`docs/pre-commit-integration.md` pinned `rev: v6.4.0` while the kit shipped v10.0.20.

    Four majors: an adopter following that page installed a kit that still had the pre-2.0
    report contracts and the old CRA profile id, both removed in v9.0.0 -- so the hook they were
    told to install disagreed with every other page they had just read. The page's own
    troubleshooting table says the fix for a broken hook is to bump `rev:`.

    `test_documented_action_tag_matches_packaged_version` did not catch it. That guard matches
    `owner/repo@vX.Y.Z`, and a pre-commit pin puts the version on its own `rev:` line.
    """

    stale = [
        f"{path.relative_to(REPO_ROOT).as_posix()}:{lineno}: {line}"
        for path, lineno, line in _rev_pin_lines()
        if _REV_PIN.match(line).group(1) != __version__  # type: ignore[union-attr]
    ]
    assert not stale, (
        f"These pre-commit `rev:` pins do not match the packaged version {__version__}. An adopter "
        "copying them installs an older kit than the docs around the snippet describe:\n  " + "\n  ".join(stale)
    )


def test_every_pre_commit_rev_pin_is_release_please_annotated() -> None:
    unannotated = [
        f"{path.relative_to(REPO_ROOT).as_posix()}:{lineno}: {line}"
        for path, lineno, line in _rev_pin_lines()
        if _ANNOTATION not in line
    ]
    assert not unannotated, (
        f"These pre-commit `rev:` pins lack the `{_ANNOTATION}` annotation, so release-please will "
        "not bump them and they will go stale exactly as v6.4.0 did:\n  " + "\n  ".join(unannotated)
    )


def test_files_with_annotated_rev_pins_are_release_please_extra_files() -> None:
    config = json.loads(RELEASE_PLEASE_CONFIG.read_text(encoding="utf-8"))
    extra_files = set(config["packages"]["."]["extra-files"])
    missing = sorted(
        {path.relative_to(REPO_ROOT).as_posix() for path, _, line in _rev_pin_lines() if _ANNOTATION in line}
        - extra_files
    )
    assert not missing, (
        "These files carry an annotated pre-commit `rev:` pin and are not in the release-please "
        "`extra-files` list, so the annotation is inert:\n  " + "\n  ".join(missing)
    )


def test_the_rev_pin_guard_finds_the_known_pins() -> None:
    """An empty sweep passes the three assertions above for the wrong reason."""

    pins = _rev_pin_lines()
    assert len(pins) >= 3, f"only {len(pins)} pre-commit rev pins found: {pins}"
    assert {path.name for path, _, _ in pins} >= {"pre-commit-integration.md", ".pre-commit-hooks.yaml"}, (
        f"the two files that carry the adopter-facing snippet are not both being scanned: {pins}"
    )
