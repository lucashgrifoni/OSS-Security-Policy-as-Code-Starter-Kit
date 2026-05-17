"""Smoke test: published .pre-commit-hooks.yaml has the expected structure.

This is a structural check — it does NOT invoke the `pre-commit` framework
binary (which adds a heavy dev-extras dependency). Instead it parses the
YAML and verifies the three published hooks declare the right entry,
language, stages, and behavior contract.

If the parser test breaks, downstream adopters who pinned the hook IDs in
their .pre-commit-config.yaml will silently lose coverage. The structural
contract (`id`, `entry`, `language`, `pass_filenames`, `always_run`,
`stages`) is therefore part of the public surface and must change
deliberately (with a CHANGELOG note).
"""

from __future__ import annotations

from pathlib import Path

import yaml

_HOOKS_YAML = Path(__file__).resolve().parents[2] / ".pre-commit-hooks.yaml"


def _load_hooks() -> list[dict]:
    raw = _HOOKS_YAML.read_text(encoding="utf-8")
    parsed = yaml.safe_load(raw)
    assert isinstance(parsed, list), "Top-level of .pre-commit-hooks.yaml must be a list"
    return parsed


def test_pre_commit_hooks_file_exists() -> None:
    assert _HOOKS_YAML.is_file(), f"Expected {_HOOKS_YAML} to exist for downstream adopters"


def test_pre_commit_hooks_yaml_parses_as_list_of_dicts() -> None:
    hooks = _load_hooks()
    assert all(isinstance(h, dict) for h in hooks), "Each hook entry must be a mapping"


def test_pre_commit_hooks_publish_expected_ids() -> None:
    hooks = _load_hooks()
    ids = {h.get("id") for h in hooks}
    # Public contract — adopters reference these IDs in their .pre-commit-config.yaml.
    # Adding new IDs is fine; renaming or removing breaks adopters.
    expected = {
        "oss-policy-kit-evaluate",
        "oss-policy-kit-evaluate-degraded",
        "oss-policy-kit-validate-profiles",
    }
    missing = expected - ids
    assert not missing, f"Pre-commit hook ids missing from published file: {missing}"


def test_evaluate_hook_targets_dot_with_fail_on_fail() -> None:
    """The default `oss-policy-kit-evaluate` hook is meant for CI-style hard gates."""
    hook = next(h for h in _load_hooks() if h["id"] == "oss-policy-kit-evaluate")
    entry = hook["entry"]
    assert "oss_policy_kit" in entry, f"entry must invoke the kit CLI: {entry}"
    assert "evaluate" in entry
    assert "--target ." in entry, "evaluate hook must target the consumer's clone (dot)"
    assert "--fail-on fail" in entry, "default hook must hard-gate"


def test_evaluate_degraded_hook_uses_fail_on_degraded() -> None:
    """Advisory-profile hook must gate on `degraded` (covers fail OR manual-review)."""
    hook = next(h for h in _load_hooks() if h["id"] == "oss-policy-kit-evaluate-degraded")
    assert "--fail-on degraded" in hook["entry"]


def test_validate_profiles_hook_runs_local_script() -> None:
    """The maintainer-facing validate hook must point at the bundled script."""
    hook = next(h for h in _load_hooks() if h["id"] == "oss-policy-kit-validate-profiles")
    assert "scripts/validate-bundled-profiles.py" in hook["entry"]


def test_every_hook_declares_language_python_and_no_filename_pass() -> None:
    """Every hook must be language: python and pass_filenames: false; otherwise
    pre-commit would shell-quote per-file paths into a CLI that doesn't take them."""
    for hook in _load_hooks():
        assert hook.get("language") == "python", f"{hook['id']} must declare language: python"
        assert hook.get("pass_filenames") is False, f"{hook['id']} must set pass_filenames: false"
        assert hook.get("always_run") is True, f"{hook['id']} must set always_run: true"


def test_every_hook_declares_explicit_stages() -> None:
    """Stages must be set so pre-commit does not run an expensive hook on every commit."""
    for hook in _load_hooks():
        stages = hook.get("stages")
        assert isinstance(stages, list) and stages, f"{hook['id']} must declare explicit stages"


def test_evaluate_script_is_invokable_as_module() -> None:
    """The entry string must be runnable: `python -m oss_policy_kit evaluate ...`.

    We don't actually spawn pre-commit here; we just confirm that `python -m
    oss_policy_kit --version` resolves, which is the minimum invariant the hook
    relies on to do anything useful in adopter repositories.
    """
    import subprocess
    import sys

    proc = subprocess.run(
        [sys.executable, "-m", "oss_policy_kit", "--version"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, f"`python -m oss_policy_kit --version` failed: {proc.stderr}"
    assert proc.stdout.strip(), "expected non-empty version string"
