"""v10.0.2 residual guards — three same-class defects the raio-x fix pass left behind.

Each is the same class as a confirmed raio-x bug but lived in a file a sibling fix
agent did not own, so it was closed in the integration pass:

- merge_kit_root leaked the resolved absolute --kit-root path (M-002), same class as
  the loader.py catalog/profile leaks (#21/#22) but a distinct message site.
- evaluators._shared._safe_float coerced a non-finite float (inf/nan) unchecked, the
  same weakness as finding_sarif._safe_float (#15); inf clears any EPSS/CVSS threshold
  and nan compares false to every threshold, silently warping the KEV/high-EPSS class.
- _python_lock_or_pins used `body` outside the `contextlib.suppress(OSError)` block, so
  an unreadable requirements.txt left it unbound -> NameError -> exit 3 (same exit-code
  contract violation the raio-x targeted; pre-existing, caught by the static pass).
"""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from oss_policy_kit.application.evaluators._shared import _python_lock_or_pins, _safe_float
from oss_policy_kit.cli.main import app, prepare_cli_args

runner = CliRunner()


def _invoke(args: list[str]):  # type: ignore[no-untyped-def]
    return runner.invoke(app, prepare_cli_args(args))


# --- merge_kit_root: relative bad --kit-root must not leak the resolved path (M-002) ---


def test_kit_root_relative_missing_dir_echoes_user_string_not_resolved(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    result = _invoke(
        ["evaluate", "--target", ".", "--profile", "github-level-1", "--output-dir", "out", "--kit-root", "ghost-kit"]
    )
    assert result.exit_code == 2, result.output
    assert "ghost-kit" in result.output  # the user-typed relative string is echoed
    # ...but never its resolved absolute form (which carries cwd / home / OS username).
    assert str((tmp_path / "ghost-kit").resolve()) not in result.output
    assert str(tmp_path.resolve()) not in result.output
    assert "Traceback" not in result.output


# --- _safe_float: non-finite / out-of-range values sanitize to None ---


def test_shared_safe_float_rejects_non_finite() -> None:
    assert _safe_float(1e400) is None  # overflow -> inf
    assert _safe_float(-1e400) is None
    assert _safe_float("NaN") is None
    assert _safe_float("inf") is None
    # finite values still pass through unchanged.
    assert _safe_float(0.7) == 0.7
    assert _safe_float(0) == 0.0
    assert _safe_float(None) is None
    assert _safe_float("not-a-number") is None


# --- _python_lock_or_pins: unreadable requirements.txt must not crash ---


def test_python_lock_or_pins_unreadable_requirements_does_not_crash(tmp_path: Path, monkeypatch) -> None:
    req = tmp_path / "requirements.txt"
    req.write_text("flask==2.0.0\n", encoding="utf-8")
    # Force the read to raise OSError (as an unreadable/racing file would); the function
    # must fall back to body="" and return a bool, never leave `body` unbound.
    real_read_text = Path.read_text

    def _boom(self: Path, *a, **k):  # type: ignore[no-untyped-def]
        if self.name == "requirements.txt":
            raise OSError("simulated unreadable file")
        return real_read_text(self, *a, **k)

    # read_bytes as well as read_text: the reader under test decodes bytes so it can honour
    # the encoding a file declares, and a patch that covers only one of them refuses nothing.
    monkeypatch.setattr(Path, "read_text", _boom)
    monkeypatch.setattr(Path, "read_bytes", _boom)
    assert _python_lock_or_pins(tmp_path) is False  # no NameError, honest False


def test_python_lock_or_pins_reads_pins_normally(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("flask==2.0.0\n", encoding="utf-8")
    assert _python_lock_or_pins(tmp_path) is True
