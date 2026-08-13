#!/usr/bin/env python
"""Public hygiene scanner for release-time validation.

Scans every Git-tracked file plus untracked-but-not-ignored files for private
tokens that must never appear in public source, generated release assets, or
mirror-clone reachable objects.

Returns exit code 0 when clean, 1 when violations are found, 2 on usage errors.

Usage:

    python scripts/check_public_hygiene.py
    python scripts/check_public_hygiene.py --extra-token "MyToken"
    python scripts/check_public_hygiene.py --root /path/to/repo
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from collections.abc import Iterable
from pathlib import Path


def _join(*parts: str) -> str:
    return "".join(parts)


_CONSUMER_MAIL_PROVIDER = _join("gm", "ail")
_PERSONAL_HANDLE = _join("lucas.henrique", "grifoni")
_PRIVATE_PLANNING_DIR = _join("mel", "horias")
_LOCAL_AUTHOR_MAP = _join(".", "mail", "map")
_VALIDATION_PREFIX = _join("VALID", "ACAO_")
_PROMPT_MARKER_A = _join("prompt-", "claude")
_PROMPT_MARKER_B = _join("prompt-", "cursor")
_PRIVATE_FIXTURE_NAME = _join("App ", "vuln")


# Tokens that must NEVER appear in public files, generated assets, or mirror-clone objects.
# Each entry is (label, regex_or_substring, is_regex).
DEFAULT_FORBIDDEN_TOKENS: tuple[tuple[str, str, bool], ...] = (
    (
        "personal-consumer-email",
        re.escape(_join(_PERSONAL_HANDLE, "@", _CONSUMER_MAIL_PROVIDER, ".com")),
        True,
    ),
    (
        "consumer-email-domain",
        r"@(" + "|".join((_CONSUMER_MAIL_PROVIDER, _join("out", "look"), _join("hot", "mail"))) + r")\.com",
        True,
    ),
    ("windows-home-path", r"[A-Za-z]:\\+Users\\+[^\s\\]+", True),
    # Anchor the leading slash so prose like ``Roles/Users/Groups`` or
    # ``foo/home/bar`` is not mistaken for a real POSIX home path. Only
    # match when the slash starts a path component (start-of-line, or
    # preceded by a non-identifier character such as whitespace or quotes).
    ("posix-home-path", r"(?<![A-Za-z0-9_])/(?:Users|home)/[^\s/]+", True),
    ("author-map-file", _LOCAL_AUTHOR_MAP, False),
    ("private-planning-dir", _PRIVATE_PLANNING_DIR + "/", False),
    ("validation-pack-prefix", _VALIDATION_PREFIX, False),
    ("internal-prompt-marker-a", _PROMPT_MARKER_A, False),
    ("internal-prompt-marker-b", _PROMPT_MARKER_B, False),
    ("private-fixture-name", _PRIVATE_FIXTURE_NAME, False),
    # Credential-shaped patterns (heuristic; refine if false positives).
    ("github-pat", r"\bgh[pousr]_[A-Za-z0-9]{20,}\b", True),
    ("aws-access-key", r"\bAKIA[0-9A-Z]{16}\b", True),
    ("azure-pat-like", r"\b[a-z0-9]{52}\b", True),
)

# Filenames that must never be tracked, matched on basename regardless of directory.
#
# Content scanning alone does not catch these: an assistant instruction file holds
# ordinary prose, so every token regex above passes it. CLAUDE.md was tracked for a
# month and this scanner reported OK the whole time, because it was asking the wrong
# question — "does this file contain a forbidden string?" instead of "should this file
# be here at all?".
#
# These files carry standing authorizations, private remote names, and local workflow
# notes. They are operating context for whoever runs the assistant, never project surface.
FORBIDDEN_TRACKED_FILENAMES: frozenset[str] = frozenset(
    {
        "CLAUDE.md",
        "AGENTS.md",
        "GEMINI.md",
        ".cursorrules",
        ".aider.conf.yml",
        "copilot-instructions.md",
    }
)


# Files whose content is allowed to contain high-signal synthetic credentials.
ALLOWLISTED_PATHS: frozenset[str] = frozenset(
    {
        # gitleaks config and parser tests reference documented synthetic cloud-key
        # examples on purpose — these are not real credentials.
        ".gitleaks.toml",
        "tests/infrastructure/test_aws_ci.py",
        # Sibling AWS CI parser test: also embeds the documented synthetic AWS
        # access-key example to exercise the detector. Not a real credential.
        "tests/infrastructure/test_aws_ci_parser_signals.py",
        # This test pins the public-hygiene regexes themselves and therefore
        # has to embed synthetic POSIX home-path fixtures to exercise the
        # matcher. The strings are not real paths.
        "tests/test_check_public_hygiene.py",
        # M-002 regression test contains synthetic POSIX/Windows home-path
        # fixtures to prove _sanitize_target_path_for_payload strips them.
        # Not real auditor paths.
        "tests/application/test_reports_v1_schema.py",
        # Evidence-projection helper test embeds synthetic POSIX/Windows home-path
        # fixtures to prove _redact_path strips them. Not real auditor paths.
        "tests/application/test_evidence_projection_helpers.py",
        # .gitignore must name the project-local private planning directory in
        # order to ignore it — the reference is functionally required, not a leak
        # (same rationale as .dockerignore below).
        ".gitignore",
        # The .dockerignore file deliberately excludes the project-local
        # private planning directory from container builds. That exclusion
        # rule is a protective allow-out, not a leaked path.
        ".dockerignore",
        # Dockerfile creates a non-root runtime user with a conventional
        # POSIX home path under the standard system user tree. This is a
        # generic container pattern, not a real auditor or maintainer
        # home directory.
        "Dockerfile",
        # The four below are the same case as the entries above — a leak detector
        # needs leak-shaped fixtures — and they went red on master because this
        # script runs nowhere in CI. It does now (github-ci-cd.yml, Quality job),
        # so an entry added here is a decision on the record rather than a drift
        # nobody sees.
        #
        # Synthetic POSIX home-shaped fixtures proving the reporting layer redacts
        # such a path out of SARIF and report output.
        "tests/application/test_findings_sarif_and_reporting_edges.py",
        # Same, for the CLI's own path-display helpers: the fixtures have to be
        # home-shaped or the redaction under test is never exercised.
        "tests/cli/test_common_output_and_paths.py",
        # Third AWS CI parser test embedding AWS's own published example access
        # key to drive the plaintext-credential detector. Not a real credential.
        "tests/infrastructure/test_aws_ci_parser_and_init_planner_edges.py",
        # Docstring quotes the verbatim Windows error this test exists to stop
        # reaching the operator; the account segment in it is already `<name>`.
        "tests/cli/test_scan_error_sanitisation.py",
    }
)


def _git_public_files(root: Path) -> list[Path]:
    """Return absolute paths of tracked and untracked-not-ignored files."""

    out = subprocess.run(
        ["git", "-C", str(root), "ls-files", "--cached", "--others", "--exclude-standard"],
        capture_output=True,
        text=True,
        check=True,
    )
    files: list[Path] = []
    for line in out.stdout.splitlines():
        rel = line.strip()
        if not rel:
            continue
        files.append(root / rel)
    return files


def _is_text_file(path: Path) -> bool:
    """Return True for files we should scan as text."""

    try:
        with path.open("rb") as fh:
            chunk = fh.read(4096)
    except OSError:
        return False
    return b"\x00" not in chunk


def _scan_file(
    path: Path,
    *,
    forbidden: Iterable[tuple[str, str, bool]],
    relative_for_allowlist: str,
) -> list[tuple[str, int, str]]:
    """Return list of (token_label, line_number, line_excerpt) violations."""

    if relative_for_allowlist in ALLOWLISTED_PATHS:
        return []
    if not _is_text_file(path):
        return []

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    violations: list[tuple[str, int, str]] = []
    for label, pattern, is_regex in forbidden:
        if is_regex:
            rgx = re.compile(pattern)
            for i, line in enumerate(text.splitlines(), start=1):
                if rgx.search(line):
                    violations.append((label, i, line[:160]))
        else:
            for i, line in enumerate(text.splitlines(), start=1):
                if pattern in line:
                    violations.append((label, i, line[:160]))
    return violations


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="Repository root (default: cwd).")
    parser.add_argument(
        "--extra-token",
        action="append",
        default=[],
        help="Extra forbidden substring to scan for. Can be passed multiple times.",
    )
    args = parser.parse_args(argv)

    root: Path = args.root.resolve()
    if not (root / ".git").exists() and not (root / ".git").is_dir():
        print(f"[hygiene] not a Git repository: {root}", file=sys.stderr)
        return 2

    forbidden = list(DEFAULT_FORBIDDEN_TOKENS)
    for tok in args.extra_token:
        forbidden.append((f"extra:{tok}", tok, False))

    try:
        files = _git_public_files(root)
    except subprocess.CalledProcessError as exc:
        print(f"[hygiene] failed to list public files: {exc}", file=sys.stderr)
        return 2

    total_violations = 0

    # Filename check first: a forbidden file is a violation whatever its content.
    for f in sorted(files):
        if f.name in FORBIDDEN_TRACKED_FILENAMES:
            rel = f.relative_to(root).as_posix()
            print(f"[hygiene] {rel}  [forbidden-tracked-filename]  agent instruction file must not be public")
            total_violations += 1

    for f in sorted(files):
        rel = f.relative_to(root).as_posix()
        violations = _scan_file(f, forbidden=forbidden, relative_for_allowlist=rel)
        if violations:
            for label, lineno, excerpt in violations:
                print(f"[hygiene] {rel}:{lineno}  [{label}]  {excerpt}")
            total_violations += len(violations)

    if total_violations:
        print(f"\n[hygiene] FAIL: {total_violations} violation(s) across public files.", file=sys.stderr)
        return 1
    print("[hygiene] OK: no forbidden tokens in public files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
