"""Evaluator for ``SEC-FUZZ-001`` (OSS-Fuzz / cifuzz / atheris / Scorecard Fuzzing).

Clone-visible signal: the kit looks for a fuzzing harness directory, a
known fuzzing-runner workflow, OR an OpenSSF Scorecard ``Fuzzing`` check
``score >= 7`` from optional Scorecard JSON evidence.

The control deliberately stays ``assurance: signal``: a positive find
proves a harness is present in the repo, not that the harness produced
useful coverage. Operators wanting hard proof should use the dedicated
fuzzing dashboards or the Scorecard live API.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

from oss_policy_kit.adapters.scorecard_json import checks_as_map
from oss_policy_kit.domain.models import ControlStatus, EvalOutcome

_FUZZ_DIR_NAMES: tuple[str, ...] = ("fuzz", "fuzzing", "fuzzers", "fuzz_tests", "test/fuzz", "tests/fuzz")
_FUZZ_FILENAME_HINTS: tuple[str, ...] = ("fuzz_target", "fuzz_test", "_fuzz.py", "_fuzz.go", "fuzz.cc", "fuzz.cpp")
_FUZZ_CONTENT_HINTS: tuple[str, ...] = (
    "atheris",
    "libfuzzer",
    "honggfuzz",
    "cifuzz",
    "go-fuzz",
    "oss-fuzz",
    "ossfuzz",
    "cargo-fuzz",
    "google/clusterfuzzlite",
)
_SCAN_FILE_LIMIT = 200
_SCAN_BYTES_PER_FILE = 4096
_SKIP_DIRS = frozenset(
    {".git", ".venv", "node_modules", "dist", "build", "__pycache__", ".oss-policy-kit", ".terraform"}
)


def _scorecard_fuzzing_signal(ctx: Any) -> tuple[bool, str | None]:
    """``(matched, reason)`` if Scorecard reports a Fuzzing check with score>=7."""

    bundle = getattr(ctx, "scorecard", None)
    if bundle is None:
        return False, None
    checks = checks_as_map(bundle)
    fuzz = checks.get("fuzzing")
    if fuzz is None:
        return False, None
    if fuzz.score is None or fuzz.score < 7:
        return False, None
    return True, f"OpenSSF Scorecard reports Fuzzing check score={fuzz.score} (>=7)."


def _iter_candidate_paths(repo_root: Path) -> Iterable[Path]:
    """Yield up to ``_SCAN_FILE_LIMIT`` candidate files under repo (skipping noisy dirs)."""

    seen = 0
    try:
        for path in repo_root.rglob("*"):
            parts = path.relative_to(repo_root).parts
            if any(p in _SKIP_DIRS for p in parts):
                continue
            if path.is_file():
                yield path
                seen += 1
                if seen >= _SCAN_FILE_LIMIT:
                    return
    except OSError:
        return


def _has_fuzz_directory(repo_root: Path) -> str | None:
    for name in _FUZZ_DIR_NAMES:
        d = repo_root / name
        if d.is_dir() and any(d.iterdir()):
            return f"Detected fuzz harness directory at {name}/."
    return None


def _has_fuzz_filename(repo_root: Path) -> str | None:
    for path in _iter_candidate_paths(repo_root):
        n = path.name.lower()
        if any(hint in n for hint in _FUZZ_FILENAME_HINTS):
            return f"Detected fuzz target file: {path.relative_to(repo_root).as_posix()}."
    return None


def _has_fuzz_content(repo_root: Path) -> str | None:
    """Scan a bounded sample of files for fuzzing-runner library mentions."""

    for path in _iter_candidate_paths(repo_root):
        suf = path.suffix.lower()
        if suf not in {".py", ".go", ".rs", ".c", ".cc", ".cpp", ".yaml", ".yml", ".toml"}:
            continue
        try:
            head = path.read_bytes()[:_SCAN_BYTES_PER_FILE].decode("utf-8", errors="ignore").lower()
        except OSError:
            continue
        for hint in _FUZZ_CONTENT_HINTS:
            if hint in head:
                return f"Detected fuzzing runner reference '{hint}' in {path.relative_to(repo_root).as_posix()}."
    return None


def eval_sec_fuzz_001(ctx: Any) -> EvalOutcome:
    """SEC-FUZZ-001: presence of a fuzzing harness or a Scorecard Fuzzing>=7 score."""

    matched, reason = _scorecard_fuzzing_signal(ctx)
    if matched and reason:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=reason,
            remediation="Keep the fuzzing target healthy and integrate findings into your triage flow.",
            evidence_sources=[],
            confidence="high",
        )
    repo_root: Path = ctx.repo_root
    for detector in (_has_fuzz_directory, _has_fuzz_filename, _has_fuzz_content):
        hit = detector(repo_root)
        if hit:
            return EvalOutcome(
                status=ControlStatus.PASS,
                reason=hit,
                remediation="Keep the fuzz harness building and the corpus refreshed in CI.",
                evidence_sources=[],
                confidence="medium",
            )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason=("No fuzzing harness, fuzz workflow, or Scorecard Fuzzing>=7 signal detected from a clone."),
        remediation=(
            "Add a fuzzing harness (libFuzzer / atheris / go-fuzz / cargo-fuzz / cifuzz) "
            "or wire OSS-Fuzz / ClusterFuzzLite. Keep an OpenSSF Scorecard report under "
            ".oss-policy-kit/evidence/ to surface the Fuzzing check directly."
        ),
        evidence_sources=[],
        confidence="medium",
    )


def build_fuzzing_evaluators() -> dict[str, Callable[[Any], EvalOutcome]]:
    """Return ``{control_id: evaluator}`` for every SEC-FUZZ rule."""

    return {"SEC-FUZZ-001": eval_sec_fuzz_001}
