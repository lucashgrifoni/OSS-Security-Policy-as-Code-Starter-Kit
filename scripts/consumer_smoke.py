#!/usr/bin/env python3
"""Official consumer smoke test: isolated venv, wheel install, CLI exercises.

Run from the repository root after ``python -m build``. See docs/packaging-and-release.md.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import tomllib
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass
class SmokeStep:
    """One CLI invocation result."""

    name: str
    argv: list[str]
    exit_code: int
    expected_exit_code: int | None
    #: First few hundred characters of stderr, kept only so a failing step can say why.
    #: The streams were captured and thrown away before, which left a red summary naming
    #: a step and nothing else to act on.
    stderr_excerpt: str = ""


@dataclass(frozen=True)
class ProjectDist:
    """Project metadata needed to resolve built artifacts."""

    dist_stem: str
    version: str


#: Variables that decide which `oss_policy_kit` a child imports, removed from every child
#: environment this script starts.
#:
#: The point of the script is to run the wheel it just installed into a throwaway venv. It
#: runs the CLI from inside the checkout, because the steps evaluate `examples/hardened-repo`
#: and the fixtures by relative path, and that on its own is harmless: there is no top-level
#: Every step also runs the interpreter with `-P`, which drops the current directory from
#: `sys.path` outright. The environment scrub below and the flag answer the same question
#: from two sides, and the flag is the stronger of the two because it does not depend on
#: knowing which variables matter.
#: `oss_policy_kit` package at the repo root, only `src/oss_policy_kit`. `PYTHONPATH` is the
#: one thing that changes the answer. An operator who happens to have it pointing at a `src/`
#: gets a run that installs the artifact and then exercises the working tree, finishes green,
#: and proves nothing about what was built.
#:
#: `PYTHONHOME` goes too, for the same reason one step further down: it can move the whole
#: standard library out from under the venv's interpreter.
_ENVIRONMENT_THAT_WOULD_SHADOW_THE_WHEEL = ("PYTHONPATH", "PYTHONHOME")


def _child_env() -> dict[str, str]:
    """The parent environment with the import-path overrides taken out."""

    env = dict(os.environ)
    for name in _ENVIRONMENT_THAT_WOULD_SHADOW_THE_WHEEL:
        env.pop(name, None)
    return env


_CAPTURE_TEXT_KWARGS = {
    "capture_output": True,
    "text": True,
    "encoding": "utf-8",
    "errors": "replace",
}
_DEFAULT_OUTPUT_SUMMARY = Path("out/consumer-smoke-summary.json")
_DEFAULT_VENV_DIR = Path(".consumer-smoke-venv")


def _py_exe(venv_dir: Path) -> Path:
    if os.name == "nt":
        return venv_dir / "Scripts" / "python.exe"
    return venv_dir / "bin" / "python"


def _console_script(venv_dir: Path) -> Path:
    """The `oss-policy-kit` executable the wheel installs.

    Every other step runs `-P -m oss_policy_kit`. The console script is a separate thing the
    wheel declares and pip writes, and nothing exercised it: a broken `[project.scripts]`
    entry would have shipped with every check green.

    An earlier version of this docstring said the console script is "what the documentation
    tells an adopter to type". Counted afterwards, the docs taught `python -m` 201 times
    against 52 for the console script, so the sentence was wrong; the step is worth having
    for the smaller reason above. The same wrong sentence was corrected in the test beside
    this script in #300 and survived here, which is what a copy of a claim does.
    """

    if os.name == "nt":
        return venv_dir / "Scripts" / "oss-policy-kit.exe"
    return venv_dir / "bin" / "oss-policy-kit"


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _resolve_repo_root(value: Path) -> Path:
    try:
        repo_root = value.expanduser().resolve(strict=True)
    except FileNotFoundError as exc:
        raise SystemExit(f"--repo-root does not exist: {value}") from exc
    if not repo_root.is_dir():
        raise SystemExit(f"--repo-root is not a directory: {repo_root}")
    if not (repo_root / "pyproject.toml").is_file():
        raise SystemExit(f"--repo-root must contain pyproject.toml: {repo_root}")
    return repo_root


def _resolve_current_repo_root(requested: Path) -> Path:
    repo_root = _resolve_repo_root(Path.cwd())
    requested_root = _resolve_repo_root(requested)
    if requested_root != repo_root:
        raise SystemExit("--repo-root must match the current working directory for consumer smoke runs.")
    return repo_root


def _resolve_repo_child(
    repo_root: Path,
    value: Path,
    *,
    label: str,
    must_exist: bool = False,
    allow_repo_root: bool = False,
) -> Path:
    expanded = value.expanduser()
    candidate = expanded if expanded.is_absolute() else repo_root / expanded
    try:
        resolved = candidate.resolve(strict=must_exist)
    except FileNotFoundError as exc:
        raise SystemExit(f"{label} does not exist: {candidate}") from exc
    if not _is_relative_to(resolved, repo_root):
        raise SystemExit(f"{label} must stay inside --repo-root: {resolved}")
    if not allow_repo_root and resolved == repo_root:
        raise SystemExit(f"{label} must not point at the repository root: {resolved}")
    return resolved


def _validate_wheel_glob(pattern: str) -> str:
    pattern_path = Path(pattern)
    if pattern_path.is_absolute() or pattern_path.drive or pattern_path.root:
        raise SystemExit("--wheel-glob must be relative to --repo-root.")
    if any(part == ".." for part in pattern_path.parts):
        raise SystemExit("--wheel-glob must not contain parent-directory traversal.")
    if not pattern_path.parts or pattern_path.parts[0] != "dist":
        raise SystemExit("--wheel-glob must resolve under the repository dist/ directory.")
    if not pattern.endswith(".whl"):
        raise SystemExit("--wheel-glob must select wheel artifacts ending in .whl.")
    return pattern


def _resolve_venv_dir(repo_root: Path, value: Path | None) -> Path:
    venv_dir = _resolve_repo_child(
        repo_root,
        value or _DEFAULT_VENV_DIR,
        label="--venv-dir",
    )
    if venv_dir.exists() and not (venv_dir / "pyvenv.cfg").is_file():
        raise SystemExit(f"--venv-dir exists but is not a virtualenv: {venv_dir}")
    return venv_dir


def _resolve_smoke_venv() -> tuple[Path, Path]:
    """Return ``(venv_dir, containment_root)`` for the smoke virtualenv.

    The venv used to live inside the repository unconditionally, which tied the length of every
    installed path to wherever the adopter had cloned. On a 143-character checkout the worst
    installed path reached 274 against a 260 limit, and `pip install` failed with `ENOENT` -- so
    one of the canonical baseline commands could not run at all.

    Moving it to a temp directory is the obvious repair and, done carelessly, removes a guard that
    exists on purpose: :func:`_remove_virtualenv` calls ``shutil.rmtree``, and every path reaching
    it is forced through :func:`_resolve_repo_child`, which refuses anything outside the
    repository. So the containment is kept and its ROOT is parameterised instead of dropped: the
    directory this script chooses is one it created itself, and deletion is confined to that.

    A ``--venv-dir`` override shipped with the first version of this fix and was withdrawn. It let
    the operator choose the directory the venv -- and therefore the interpreter this script
    executes -- was built in, which Snyk Code reported as a command-injection dataflow from the
    argument parser into :func:`subprocess.run`. By the letter of that class it is a false
    positive: every call passes a list with ``shell=False``, and :func:`_safe_python_exe` already
    refuses an interpreter resolving outside the venv. It was removed anyway, because the flag was
    convenience rather than repair -- the MAX_PATH defect is fixed by the default alone -- and a
    suppression would have needed an owner and an expiry to buy nothing.
    """

    containment_root = Path(tempfile.mkdtemp(prefix="oss-policy-kit-smoke-")).resolve()
    return _resolve_venv_dir(containment_root, _DEFAULT_VENV_DIR), containment_root


def _remove_virtualenv(repo_root: Path, venv_dir: Path, *, ignore_errors: bool = False) -> None:
    safe_venv_dir = _resolve_repo_child(repo_root, venv_dir, label="virtualenv cleanup target", must_exist=True)
    if not safe_venv_dir.is_dir() or not (safe_venv_dir / "pyvenv.cfg").is_file():
        raise SystemExit(f"Refusing to remove non-virtualenv directory: {safe_venv_dir}")
    shutil.rmtree(safe_venv_dir, ignore_errors=ignore_errors)


def _safe_python_exe(venv_dir: Path) -> Path:
    py = _py_exe(venv_dir).resolve(strict=True)
    if not _is_relative_to(py, venv_dir):
        raise SystemExit(f"Virtualenv Python resolved outside --venv-dir: {py}")
    return py


def _safe_subprocess_argv(py: Path, argv: Sequence[str]) -> list[str]:
    py_arg = os.fspath(py)
    safe_args = [str(arg) for arg in argv]
    if any("\x00" in arg for arg in [py_arg, *safe_args]):
        raise SystemExit("Refusing to execute subprocess arguments containing NUL bytes.")
    return [py_arg, *safe_args]


def _load_project_dist(repo_root: Path) -> ProjectDist:
    pyproject = repo_root / "pyproject.toml"
    if not pyproject.is_file():
        raise SystemExit(f"Missing {pyproject}.")
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    project = data.get("project")
    if not isinstance(project, dict):
        raise SystemExit(f"Missing [project] table in {pyproject}.")
    name = project.get("name")
    version = project.get("version")
    if not isinstance(name, str) or not isinstance(version, str):
        raise SystemExit(f"Missing project.name/project.version in {pyproject}.")
    return ProjectDist(dist_stem=name.replace("-", "_"), version=version)


def resolve_wheel(repo_root: Path, wheel_glob: str | None = None) -> Path:
    project = _load_project_dist(repo_root)
    pattern = _validate_wheel_glob(wheel_glob or f"dist/{project.dist_stem}-{project.version}-*.whl")
    matches = sorted(
        _resolve_repo_child(repo_root, path, label="wheel artifact", must_exist=True)
        for path in repo_root.glob(pattern)
    )
    if not matches:
        msg = f"No wheel found under {repo_root} matching {pattern}. Run python -m build first."
        raise SystemExit(msg)
    if len(matches) > 1:
        joined = ", ".join(str(path.name) for path in matches)
        msg = f"Expected exactly one wheel for pattern {pattern}, found {len(matches)}: {joined}"
        raise SystemExit(msg)
    wheel = matches[0]
    if not _is_relative_to(wheel, repo_root / "dist") or wheel.suffix != ".whl":
        raise SystemExit(f"Resolved wheel must stay under dist/ and end in .whl: {wheel}")
    return wheel


def _run(py: Path, argv: Sequence[str], *, cwd: Path) -> tuple[int, str]:
    """Run *argv* under *py* and return its exit code together with a stderr excerpt.

    The excerpt exists because the summary used to print a step name and an exit code and
    nothing else. Reading it meant re-running the command by hand to find out what had
    happened, which is the state this script is supposed to spare a release from.
    """

    proc = subprocess.run(
        _safe_subprocess_argv(py, argv), cwd=cwd, shell=False, env=_child_env(), **_CAPTURE_TEXT_KWARGS
    )
    return int(proc.returncode), (proc.stderr or "").strip()[:400]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path.cwd(),
        help="Repository root (default: current directory).",
    )
    parser.add_argument(
        "--keep-venv",
        action="store_true",
        help="Do not delete the venv after the run.",
    )
    args = parser.parse_args()

    repo_root = _resolve_current_repo_root(args.repo_root)
    venv_dir, venv_containment = _resolve_smoke_venv()
    out_summary = _resolve_repo_child(
        repo_root,
        _DEFAULT_OUTPUT_SUMMARY,
        label="output summary",
    )
    wheel = resolve_wheel(repo_root)

    if venv_dir.is_dir():
        _remove_virtualenv(venv_containment, venv_dir)

    subprocess.run(
        [sys.executable, "-P", "-m", "venv", str(venv_dir)],
        cwd=repo_root,
        shell=False,
        env=_child_env(),
        check=True,
    )
    py = _safe_python_exe(venv_dir)

    subprocess.run(
        _safe_subprocess_argv(py, ["-P", "-m", "pip", "install", "--upgrade", "pip", str(wheel)]),
        cwd=repo_root,
        shell=False,
        env=_child_env(),
        check=True,
    )

    proc_kit = subprocess.run(
        _safe_subprocess_argv(
            py,
            ["-c", "from oss_policy_kit.application.loader import bundled_kit_root; print(bundled_kit_root())"],
        ),
        cwd=repo_root,
        shell=False,
        env=_child_env(),
        **_CAPTURE_TEXT_KWARGS,
        check=True,
    )
    kit_root = proc_kit.stdout.strip()
    examples_hardened = Path("examples") / "hardened-repo"
    examples_vuln = Path("examples") / "vulnerable-repo"
    invalid_wf = Path("tests") / "fixtures" / "repositories" / "invalid-workflow-target"
    waivers = examples_hardened / "waivers" / "waivers.yaml"

    #: Where the selfcheck step writes, and what it has to leave behind. An exit code of 0
    #: from a command that writes files says the process ended, not that it produced
    #: anything: every check here passed for a run that wrote no report at all.
    selfcheck_output = Path("out") / "consumer-smoke-selfcheck"

    steps: list[SmokeStep] = []

    def skipped(name: str, why: str) -> None:
        """Record a step that did not run, so the summary cannot shrink in silence.

        `expected_exit_code=None` is the file's existing way of saying "not checked", so
        this never counts as a pass and never counts as a mismatch. What it does is
        appear: in the step table, in the JSON, and in the `skipped_steps` list beside
        `all_expected_matched`, which on its own would have said true over a shorter run.
        """

        steps.append(
            SmokeStep(name=name, argv=[], exit_code=0, expected_exit_code=None, stderr_excerpt=f"skipped: {why}")
        )

    def add(name: str, argv: list[str], expect: int | None = 0) -> None:
        code, stderr_excerpt = _run(py, argv, cwd=repo_root)
        steps.append(
            SmokeStep(
                name=name,
                argv=argv,
                exit_code=code,
                expected_exit_code=expect,
                stderr_excerpt=stderr_excerpt,
            )
        )

    def add_console(name: str, args: list[str], expect: int | None = 0) -> None:
        """Same as `add`, through the executable the wheel installs.

        Kept separate because `_run` prepends the interpreter: this one is the entry point
        itself, so a missing or broken `[project.scripts]` shows up here and nowhere else.
        """

        executable = _console_script(venv_dir)
        if not executable.is_file():
            steps.append(
                SmokeStep(
                    name=name,
                    argv=[executable.name, *args],
                    exit_code=127,
                    expected_exit_code=expect,
                    stderr_excerpt=f"the wheel installed no console script at {executable.name}",
                )
            )
            return
        proc = subprocess.run(  # noqa: S603 - fixed argv from the venv, shell=False
            [str(executable), *args],
            cwd=repo_root,
            shell=False,
            env=_child_env(),
            **_CAPTURE_TEXT_KWARGS,
        )
        steps.append(
            SmokeStep(
                name=name,
                argv=[executable.name, *args],
                exit_code=int(proc.returncode),
                expected_exit_code=expect,
                stderr_excerpt=(proc.stderr or "").strip()[:400],
            )
        )

    add("version", ["-P", "-m", "oss_policy_kit", "--version"], 0)
    add_console("console_script_version", ["--version"], 0)
    add("help_root", ["-P", "-m", "oss_policy_kit", "--help"], 0)
    add("evaluate_help", ["-P", "-m", "oss_policy_kit", "evaluate", "--help"], 0)
    add(
        "selfcheck",
        [
            "-P",
            "-m",
            "oss_policy_kit",
            "evaluate",
            "--target",
            ".",
            "--profile",
            "github-level-1",
            "--output-dir",
            os.fspath(selfcheck_output),
            "--format",
            "json",
        ],
        0,
    )
    add(
        "hardened",
        [
            "-P",
            "-m",
            "oss_policy_kit",
            "evaluate",
            "--target",
            os.fspath(examples_hardened),
            "--profile",
            "github-level-1",
            "--output-dir",
            os.fspath(Path("out") / "consumer-smoke-hardened"),
        ],
        0,
    )
    add(
        "vulnerable",
        [
            "-P",
            "-m",
            "oss_policy_kit",
            "evaluate",
            "--target",
            os.fspath(examples_vuln),
            "--profile",
            "github-level-1",
            "--output-dir",
            os.fspath(Path("out") / "consumer-smoke-vuln"),
        ],
        0,
    )
    add(
        "vulnerable_fail_on_fail",
        [
            "-P",
            "-m",
            "oss_policy_kit",
            "evaluate",
            "--target",
            os.fspath(examples_vuln),
            "--profile",
            "github-level-1",
            "--output-dir",
            os.fspath(Path("out") / "consumer-smoke-vuln-fail"),
            "--fail-on",
            "fail",
        ],
        1,
    )
    if not (repo_root / invalid_wf).is_dir():
        skipped("invalid_fail_on_degraded", f"no fixture at {invalid_wf.as_posix()}")
    else:
        add(
            "invalid_fail_on_degraded",
            [
                "-P",
                "-m",
                "oss_policy_kit",
                "evaluate",
                "--target",
                os.fspath(invalid_wf),
                "--profile",
                "github-level-1",
                "--output-dir",
                os.fspath(Path("out") / "consumer-smoke-invalid-degraded"),
                "--fail-on",
                "degraded",
            ],
            1,
        )
    add(
        "waivers",
        [
            "-P",
            "-m",
            "oss_policy_kit",
            "evaluate",
            "--target",
            os.fspath(examples_hardened),
            "--profile",
            "github-level-1",
            "--waivers",
            os.fspath(waivers),
            "--output-dir",
            os.fspath(Path("out") / "consumer-smoke-waivers"),
        ],
        0,
    )
    add(
        "kit_root_override",
        [
            "-P",
            "-m",
            "oss_policy_kit",
            "evaluate",
            "--target",
            os.fspath(examples_hardened),
            "--profile",
            "github-level-1",
            "--kit-root",
            kit_root,
            "--output-dir",
            os.fspath(Path("out") / "consumer-smoke-kit-root"),
        ],
        0,
    )

    # An exit code of 0 from a command whose job is to write files says the process ended,
    # not that it produced anything. Every check in this script passed for a run that wrote
    # no report at all, so the artifact is now a step of its own and flows into the same
    # verdict as the rest.
    expected_report = repo_root / selfcheck_output / "evaluation-report.json"
    steps.append(
        SmokeStep(
            name="selfcheck_wrote_a_report",
            argv=[os.fspath(selfcheck_output / "evaluation-report.json")],
            exit_code=0 if expected_report.is_file() else 1,
            expected_exit_code=0,
            stderr_excerpt="" if expected_report.is_file() else f"no report at {expected_report}",
        )
    )

    mismatches = [
        step.name for step in steps if step.expected_exit_code is not None and step.exit_code != step.expected_exit_code
    ]
    skipped_steps = [step.name for step in steps if step.expected_exit_code is None]
    payload = {
        "repo_root": str(repo_root),
        "wheel": str(wheel),
        "venv_dir": str(venv_dir),
        "kit_root_resolved": kit_root,
        "all_expected_matched": len(mismatches) == 0,
        "mismatched_steps": mismatches,
        # Read this beside `all_expected_matched`: that flag is true over the steps that
        # ran, and says nothing about the ones that did not.
        "skipped_steps": skipped_steps,
        "steps": [asdict(step) for step in steps],
    }

    out_summary.parent.mkdir(parents=True, exist_ok=True)
    out_summary.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    md_path = out_summary.with_suffix(".md")
    lines = [
        "# Consumer smoke summary",
        "",
        f"- Wheel: `{wheel}`",
        f"- All expectations matched: **{payload['all_expected_matched']}**",
        (
            f"- Steps skipped: **{len(skipped_steps)}** ({', '.join(skipped_steps)})"
            if skipped_steps
            else "- Steps skipped: **0**"
        ),
        "",
        "| Step | Exit | Expected |",
        "| --- | ---: | ---: |",
    ]
    for step in steps:
        exp = "" if step.expected_exit_code is None else str(step.expected_exit_code)
        lines.append(f"| {step.name} | {step.exit_code} | {exp} |")
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    if not args.keep_venv:
        _remove_virtualenv(venv_containment, venv_dir, ignore_errors=True)
        if venv_containment != repo_root:
            # Only ever a directory this script created; the repository is never a candidate.
            shutil.rmtree(venv_containment, ignore_errors=True)

    if skipped_steps:
        print(f"Smoke steps skipped: {', '.join(skipped_steps)}", file=sys.stderr)
    if mismatches:
        print(f"Smoke mismatches: {', '.join(mismatches)}", file=sys.stderr)
        return 1
    print(f"OK: wrote {out_summary} and {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
