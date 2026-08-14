"""The action's version resolver, executed rather than described.

`action.yml` ships a composite action whose first step decides which wheel to install.
It had no test of any kind, and three defects had settled into it:

1. A SHA-pinned reference resolved to an EMPTY pin, so `pip install oss-policy-kit`
   took whatever was newest on PyPI. The file's own header recommends SHA pinning for
   production -- so following the hardening advice produced a less reproducible install
   than ignoring it, and the wheel could be a different major than the action code
   running beside it.
2. `kit-version: latest`, offered by the input's own description, became
   `pip install oss-policy-kit==latest`, which is not valid requirement syntax. The
   documented escape hatch failed the install step.
3. The comments described a 5.x line on a kit that is at 10.x.

These tests run the real script out of the real file. A test that asserted on the text
of `action.yml` would have passed against all three defects -- the text was there, it
just did the wrong thing.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
from tests.conftest import ROOT

from oss_policy_kit.infrastructure.yaml_io import load_yaml_file

ACTION_YML = ROOT / "action.yml"
RESOLVE_STEP = "Resolve kit version"


def _working_bash() -> str | None:
    """Find a bash that actually runs, not just one that is on PATH.

    On Windows, `bash` on PATH is usually the WSL launcher, which fails with an RPC
    error when no distribution is installed -- so `shutil.which("bash")` finding
    something is not evidence that it works. Git Bash is checked first there. On the
    Linux runners this returns `/usr/bin/bash` on the first probe.
    """

    candidates = [
        shutil.which("bash"),
        r"C:\Program Files\Git\bin\bash.exe",
        r"C:\Program Files\Git\usr\bin\bash.exe",
    ]
    for candidate in candidates:
        if not candidate or not Path(candidate).exists():
            continue
        try:
            probe = subprocess.run([candidate, "-c", "printf ok"], capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.SubprocessError):
            continue
        if probe.returncode == 0 and probe.stdout.strip() == "ok":
            return candidate
    return None


BASH = _working_bash()

# A silent skip here would put `action.yml` back where it was: shipped, and covered by
# nothing. That file accumulated three defects while it had no test at all, so the failure
# mode to guard is not "bash is missing" -- it is "bash went missing and the whole file
# stopped running without anyone noticing". On a developer machine without a working bash a
# skip is the right answer; on CI it is not, so there it fails instead.
_ON_CI = os.environ.get("CI", "").lower() in {"1", "true", "yes"}

if BASH is None and _ON_CI:  # pragma: no cover - only reachable on a runner without bash
    raise RuntimeError(
        "No working bash found on CI, so action.yml would ship untested. "
        "Install bash on the runner or fix the probe in _working_bash()."
    )

pytestmark = pytest.mark.skipif(BASH is None, reason="needs a working bash to run the composite step")


def _step_script(step_name: str) -> str:
    """Return the ``run:`` body of a named step, straight out of the shipped action."""

    data: Any = load_yaml_file(ACTION_YML)
    for step in data["runs"]["steps"]:
        if step.get("name") == step_name:
            return str(step["run"])
    raise AssertionError(f"step {step_name!r} not found in action.yml")


def _resolve(tmp_path: Path, *, kit_version: str = "", action_ref: str = "", action_path: Path | None = None):
    """Run the resolve step and return ``(returncode, kit_version, stderr)``."""

    script = tmp_path / "resolve.sh"
    script.write_text(_step_script(RESOLVE_STEP), encoding="utf-8", newline="\n")
    output = tmp_path / "gh_output"
    output.write_text("", encoding="utf-8")

    assert BASH is not None  # guarded by pytestmark
    proc = subprocess.run(
        [BASH, str(script)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env={
            "PATH": os.environ.get("PATH", ""),
            "INPUT_KIT_VERSION": kit_version,
            "ACTION_REF": action_ref,
            "GITHUB_OUTPUT": str(output),
            "GITHUB_ACTION_PATH": str(action_path if action_path is not None else ROOT),
        },
    )
    resolved = ""
    for line in output.read_text(encoding="utf-8").splitlines():
        if line.startswith("kit_version="):
            resolved = line.split("=", 1)[1]
    return proc.returncode, resolved, proc.stderr


def _declared_version() -> str:
    for line in (ROOT / "src" / "oss_policy_kit" / "__init__.py").read_text(encoding="utf-8").splitlines():
        if line.startswith("__version__"):
            return line.split('"')[1]
    raise AssertionError("__version__ not found")


def test_an_explicit_input_wins(tmp_path: Path) -> None:
    rc, version, _ = _resolve(tmp_path, kit_version="9.9.9", action_ref="v10.0.13")
    assert rc == 0
    assert version == "9.9.9"


def test_latest_means_no_pin_not_a_literal_version(tmp_path: Path) -> None:
    """Defect 2. `pip install oss-policy-kit==latest` is a syntax error, not a version."""

    rc, version, _ = _resolve(tmp_path, kit_version="latest", action_ref="v10.0.13")
    assert rc == 0
    assert version == "", "`latest` must resolve to an empty pin, never to the literal string"


def test_a_release_tag_installs_the_matching_wheel(tmp_path: Path) -> None:
    rc, version, _ = _resolve(tmp_path, action_ref="v10.0.13")
    assert rc == 0
    assert version == "10.0.13"


def test_a_sha_pin_resolves_to_the_version_that_sha_ships(tmp_path: Path) -> None:
    """Defect 1, the one that mattered: this used to resolve to nothing at all."""

    rc, version, _ = _resolve(tmp_path, action_ref="8dffce7a1c2b3d4e5f60718293a4b5c6d7e8f900")
    assert rc == 0
    assert version == _declared_version()


def test_a_major_line_tag_also_pins(tmp_path: Path) -> None:
    """`@v10` is not a full version, so it took the same unpinned path a SHA did."""

    rc, version, _ = _resolve(tmp_path, action_ref="v10")
    assert rc == 0
    assert version == _declared_version()


def test_an_unreadable_checkout_fails_closed(tmp_path: Path) -> None:
    """Failing loudly beats installing an unrelated version and calling it pinned."""

    empty = tmp_path / "not-a-checkout"
    empty.mkdir()

    rc, version, stderr = _resolve(tmp_path, action_ref="deadbeef", action_path=empty)

    assert rc != 0, "an unresolvable version must stop the run"
    assert version == ""
    assert "kit-version" in stderr, "the error must name the input that unblocks it"


def _install(tmp_path: Path, *, kit_version: str, reports: str) -> tuple[int, str]:
    """Run the install step against a stub `python`, returning ``(returncode, stderr)``.

    *reports* is what the stub answers to ``--version``, standing in for the wheel pip
    actually resolved. No network, no real install -- the step's decision is the subject.
    """

    binstub = tmp_path / "bin"
    binstub.mkdir(exist_ok=True)  # two invocations per test share one tmp_path
    (binstub / "python").write_text(
        f'#!/bin/sh\ncase "$*" in\n  *pip*) exit 0 ;;\n  *--version*) echo "{reports}" ; exit 0 ;;\nesac\nexit 0\n',
        encoding="utf-8",
        newline="\n",
    )
    (binstub / "python").chmod(0o755)

    script = tmp_path / "install.sh"
    script.write_text(_step_script("Install oss-policy-kit"), encoding="utf-8", newline="\n")

    assert BASH is not None
    proc = subprocess.run(
        [BASH, str(script)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=str(tmp_path),
        env={"PATH": f"{binstub}{os.pathsep}{os.environ.get('PATH', '')}", "KIT_VERSION": kit_version},
    )
    return proc.returncode, proc.stderr


def test_the_install_step_verifies_the_wheel_it_got(tmp_path: Path) -> None:
    """A pin that resolves is worth nothing if the wheel that arrives is a different one."""

    rc, _ = _install(tmp_path, kit_version="10.0.13", reports="oss-policy-kit 10.0.13")
    assert rc == 0

    rc, stderr = _install(tmp_path, kit_version="10.0.13", reports="oss-policy-kit 9.1.0")
    assert rc != 0, "a mismatched wheel must fail the step, not run the evaluation"
    assert "10.0.13" in stderr


def test_an_unpinned_install_has_nothing_to_verify(tmp_path: Path) -> None:
    """`latest` resolves to an empty pin on purpose; the check must not fire on it."""

    rc, _ = _install(tmp_path, kit_version="", reports="oss-policy-kit 10.0.13")
    assert rc == 0


def test_the_resolved_version_is_one_pip_can_actually_install(tmp_path: Path) -> None:
    """Guards the shape of what we emit: a bare `latest`, a `v` prefix, or stray
    whitespace all produce an invalid requirement at install time."""

    from packaging.requirements import InvalidRequirement, Requirement

    for ref in ("v10.0.13", "v10", "8dffce7a1c2b3d4e5f60718293a4b5c6d7e8f900"):
        _, version, _ = _resolve(tmp_path, action_ref=ref)
        assert version, f"{ref} resolved to nothing"
        try:
            Requirement(f"oss-policy-kit=={version}")
        except InvalidRequirement as exc:  # pragma: no cover - only on a regression
            raise AssertionError(f"ref {ref} resolved to an uninstallable pin {version!r}: {exc}") from exc
