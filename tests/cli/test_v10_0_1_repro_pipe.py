"""Regression tests for the v10.0.1 F5 unit: reproducibility, broken-pipe, terminal width.

Covers four confirmed defects:

- X7-03: the six scan evidence writers stamped raw ``datetime.now(UTC)`` for
  ``scanned_at``/``attested_at``, bypassing ``SOURCE_DATE_EPOCH``. They now
  route through :func:`oss_policy_kit.application.clock.report_generated_at`, so
  two runs on an unchanged target under a pinned epoch produce byte-identical
  evidence JSON.
- X6-02: those same writers emitted ``str(target.resolve())`` (an absolute path
  with the username) into a commonly-committed artifact. They now emit only the
  basename via ``application.reporting._sanitize_target_path_for_payload``.
- X6-04: piping long output into ``head`` and closing the reader raised
  ``OSError`` (EINVAL on Windows, ``BrokenPipeError`` elsewhere), which the CLI
  printed as "Unexpected error" + shutdown noise + exit 120. ``main()`` now
  swallows it quietly and exits 0.
- X2-F2: ``terminal_width``/``build_console`` hardwired 120 for non-TTY streams,
  ignoring ``COLUMNS``. They now consult a valid ``COLUMNS`` before the fallback.
"""

from __future__ import annotations

import errno
import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from tests.conftest import ROOT

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

# 1781524800 == 2026-06-15T12:00:00Z; conftest pins SOURCE_DATE_EPOCH to it so the
# whole suite is calendar-immune. The pinned wall-clock string the scanners must emit.
_PINNED_TS = "2026-06-15T12:00:00Z"

_TF_TARGET = """\
resource "aws_s3_bucket" "public" {
  acl = "public-read"
}
"""

_K8S_TARGET = """\
apiVersion: v1
kind: Pod
metadata:
  name: p
spec:
  containers:
    - name: c
      image: nginx:latest
      securityContext:
        privileged: true
"""

_CFN_TARGET = """\
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: PublicRead
"""

_BICEP_TARGET = """\
resource sa 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'sa'
  properties: {
    allowBlobPublicAccess: true
  }
}
"""

_PULUMI_TARGET = """\
import pulumi_aws as aws

bucket = aws.s3.Bucket("b", acl="public-read")
"""


def _tf_evidence(tmp_path: Path) -> dict:
    from oss_policy_kit.infrastructure.iac import scanner

    if not scanner.hcl2_available():  # pragma: no cover - depends on optional extra
        pytest.skip("python-hcl2 not installed")
    (tmp_path / "main.tf").write_text(_TF_TARGET, encoding="utf-8")
    return scanner.render_evidence_payload(scanner.run_scan(tmp_path), target=tmp_path)


def _k8s_evidence(tmp_path: Path) -> dict:
    from oss_policy_kit.infrastructure.k8s import scanner

    (tmp_path / "pod.yaml").write_text(_K8S_TARGET, encoding="utf-8")
    return scanner.render_evidence_payload(scanner.run_scan(tmp_path), target=tmp_path)


def _cfn_evidence(tmp_path: Path) -> dict:
    from oss_policy_kit.infrastructure.iac.cfn import scanner

    (tmp_path / "stack.yaml").write_text(_CFN_TARGET, encoding="utf-8")
    return scanner.render_evidence_payload(scanner.run_scan(tmp_path), target=tmp_path)


def _bicep_evidence(tmp_path: Path) -> dict:
    from oss_policy_kit.infrastructure.iac.bicep import scanner

    (tmp_path / "main.bicep").write_text(_BICEP_TARGET, encoding="utf-8")
    return scanner.render_evidence_payload(scanner.run_scan(tmp_path), target=tmp_path)


def _pulumi_evidence(tmp_path: Path) -> dict:
    from oss_policy_kit.infrastructure.iac.pulumi import scanner

    (tmp_path / "__main__.py").write_text(_PULUMI_TARGET, encoding="utf-8")
    return scanner.render_evidence_payload(scanner.run_scan(tmp_path), target=tmp_path)


_ALL_EVIDENCE_BUILDERS = pytest.mark.parametrize(
    "build_evidence",
    [_tf_evidence, _k8s_evidence, _cfn_evidence, _bicep_evidence, _pulumi_evidence],
    ids=["terraform", "k8s", "cfn", "bicep", "pulumi"],
)


# ---------------------------------------------------------------------------
# X7-03: SOURCE_DATE_EPOCH reproducibility
# ---------------------------------------------------------------------------


@_ALL_EVIDENCE_BUILDERS
def test_x7_03_scan_evidence_timestamps_honor_source_date_epoch(build_evidence, tmp_path: Path) -> None:
    """Both timestamp fields reflect the pinned SOURCE_DATE_EPOCH, not wall-clock."""

    payload = build_evidence(tmp_path)
    assert payload["scanned_at"] == _PINNED_TS
    assert payload["attested_at"] == _PINNED_TS


@_ALL_EVIDENCE_BUILDERS
def test_x7_03_two_runs_are_byte_identical(build_evidence, tmp_path: Path) -> None:
    """Two scans on an unchanged target under a pinned epoch serialize byte-identically."""

    first = json.dumps(build_evidence(tmp_path), indent=2, ensure_ascii=False, sort_keys=False)
    second = json.dumps(build_evidence(tmp_path), indent=2, ensure_ascii=False, sort_keys=False)
    assert first == second


def test_x7_03_epoch_override_changes_timestamp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Changing SOURCE_DATE_EPOCH changes the stamped timestamp (proves the env is honored)."""

    from oss_policy_kit.infrastructure.iac.cfn import scanner

    (tmp_path / "stack.yaml").write_text(_CFN_TARGET, encoding="utf-8")

    monkeypatch.setenv("SOURCE_DATE_EPOCH", "0")
    payload = scanner.render_evidence_payload(scanner.run_scan(tmp_path), target=tmp_path)
    assert payload["scanned_at"] == "1970-01-01T00:00:00Z"
    assert payload["attested_at"] == "1970-01-01T00:00:00Z"


# ---------------------------------------------------------------------------
# X6-02: evidence target privacy (basename only, no absolute path / username)
# ---------------------------------------------------------------------------


@_ALL_EVIDENCE_BUILDERS
def test_x6_02_target_is_basename_not_absolute(build_evidence, tmp_path: Path) -> None:
    """The evidence ``target`` is the directory basename, never the absolute path."""

    payload = build_evidence(tmp_path)
    target = payload["target"]
    assert target == tmp_path.name
    # A basename never contains a path separator, so no absolute path survives.
    assert "/" not in target
    assert "\\" not in target
    assert target  # minLength 1 satisfied


@_ALL_EVIDENCE_BUILDERS
def test_x6_02_no_username_or_drive_leak_in_full_payload(build_evidence, tmp_path: Path) -> None:
    """No absolute-path marker (``C:\\Users``, home dir, username) leaks anywhere in the JSON."""

    payload = build_evidence(tmp_path)
    blob = json.dumps(payload, ensure_ascii=False)
    # The absolute target directory string must not appear verbatim in the artifact.
    assert str(tmp_path.resolve()) not in blob
    assert str(tmp_path.parent.resolve()) not in blob
    lowered = blob.lower()
    assert "c:\\users" not in lowered
    assert "c:/users" not in lowered


# ---------------------------------------------------------------------------
# X6-04: broken-pipe handling in cli/main.py::main()
# ---------------------------------------------------------------------------


def _run_main_raising(exc: BaseException, monkeypatch: pytest.MonkeyPatch) -> None:
    """Invoke ``main()`` with ``app`` monkeypatched to raise ``exc``."""

    from oss_policy_kit.cli import main as main_mod

    def _boom(**_: object) -> None:
        raise exc

    monkeypatch.setattr(main_mod, "app", _boom)
    monkeypatch.setattr(sys, "argv", ["oss-policy-kit"])
    main_mod.main()


@pytest.mark.parametrize(
    "exc",
    [
        BrokenPipeError(errno.EPIPE, "Broken pipe"),
        OSError(errno.EINVAL, "Invalid argument"),
        OSError(errno.EPIPE, "Broken pipe"),
    ],
    ids=["broken-pipe", "einval-windows", "epipe-oserror"],
)
def test_x6_04_broken_pipe_exits_zero_quietly(
    exc: OSError, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A broken-pipe write error from ``app()`` exits 0 with no error banner."""

    with pytest.raises(SystemExit) as excinfo:
        _run_main_raising(exc, monkeypatch)
    assert excinfo.value.code == 0
    captured = capsys.readouterr()
    assert "Unexpected error" not in captured.err
    assert "Unexpected error" not in captured.out


def test_x6_04_unrelated_oserror_still_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    """A non-pipe OSError (e.g. ENOENT) is not swallowed — it must still surface."""

    error = OSError(errno.ENOENT, "No such file")
    with pytest.raises(OSError) as excinfo:
        _run_main_raising(error, monkeypatch)
    assert excinfo.value.errno == errno.ENOENT


def test_x6_04_is_broken_pipe_classifier() -> None:
    """The internal classifier recognizes the pipe errnos and rejects others."""

    from oss_policy_kit.cli.main import _is_broken_pipe

    assert _is_broken_pipe(BrokenPipeError())
    assert _is_broken_pipe(OSError(errno.EPIPE, "broken pipe"))
    assert _is_broken_pipe(OSError(errno.EINVAL, "invalid argument"))
    assert not _is_broken_pipe(OSError(errno.ENOENT, "missing"))


def test_x6_04_subprocess_profiles_reader_closes_early_is_clean() -> None:
    """`python -m oss_policy_kit profiles` stays clean when the reader closes the pipe early.

    Cross-platform stand-in for ``| head -1``: read one line then close the pipe, which
    breaks it exactly like ``head``/``less`` quitting. The producer must not print the
    generic error banner nor exit 120.
    """

    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join([str(ROOT / "src"), str(ROOT)])
    env["NO_COLOR"] = "1"
    env["TERM"] = "dumb"
    env["PYTHONUTF8"] = "1"

    producer = subprocess.Popen(  # noqa: S603 - fixed argv
        [sys.executable, "-m", "oss_policy_kit", "profiles"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        cwd=str(ROOT),
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert producer.stdout is not None
    assert producer.stderr is not None
    # Read a single line, then close the reader to break the pipe (like ``head`` quitting).
    producer.stdout.readline()
    producer.stdout.close()
    # Drain stderr directly (not via communicate(), whose reader thread would race on the
    # already-closed stdout pipe) and wait for the producer to finish unwinding.
    err = producer.stderr.read()
    producer.stderr.close()
    returncode = producer.wait(timeout=60)
    # The producer must not print the generic error banner nor the exit-120 shutdown noise.
    assert "Unexpected error" not in err
    assert "BrokenPipeError" not in err
    # Exit code is 0 (clean) or the platform's SIGPIPE code; never 120 (the generic catch).
    assert returncode != 120


# ---------------------------------------------------------------------------
# X2-F2: terminal width honors COLUMNS for non-TTY streams
# ---------------------------------------------------------------------------


def _non_tty_stream() -> io.StringIO:
    """A stream that is definitely not a TTY (``isatty`` returns False)."""

    return io.StringIO()


def test_x2_f2_terminal_width_uses_columns_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """A valid COLUMNS override wins over the 120 fallback for a non-TTY stream."""

    from oss_policy_kit.cli import terminal_ui

    monkeypatch.setenv("COLUMNS", "200")
    assert terminal_ui.terminal_width(_non_tty_stream()) == 200


def test_x2_f2_terminal_width_ignores_invalid_columns(monkeypatch: pytest.MonkeyPatch) -> None:
    """A blank/non-integer/non-positive COLUMNS falls back to the 120 default."""

    from oss_policy_kit.cli import terminal_ui

    for bad in ("", "   ", "not-a-number", "0", "-5"):
        monkeypatch.setenv("COLUMNS", bad)
        assert terminal_ui.terminal_width(_non_tty_stream()) == terminal_ui.DEFAULT_FALLBACK_COLUMNS


def test_x2_f2_terminal_width_clamps_columns(monkeypatch: pytest.MonkeyPatch) -> None:
    """A huge COLUMNS is clamped to MAX_COLUMNS, a tiny one raised to TTY_MIN_COLUMNS."""

    from oss_policy_kit.cli import terminal_ui

    monkeypatch.setenv("COLUMNS", "99999")
    assert terminal_ui.terminal_width(_non_tty_stream()) == terminal_ui.MAX_COLUMNS
    monkeypatch.setenv("COLUMNS", "3")
    assert terminal_ui.terminal_width(_non_tty_stream()) == terminal_ui.TTY_MIN_COLUMNS


def test_x2_f2_build_console_inherits_columns_width(monkeypatch: pytest.MonkeyPatch) -> None:
    """A long non-wrapping line under COLUMNS=200 is not wrapped at the 120 fallback."""

    from oss_policy_kit.cli import terminal_ui

    monkeypatch.setenv("COLUMNS", "200")
    stream = _non_tty_stream()
    console = terminal_ui.build_console(file=stream, width=None)
    # Rich may reserve one cell for the cursor, so the console width tracks COLUMNS
    # (200 or 199) — the point is it is derived from COLUMNS, not the 120 fallback.
    assert console.width >= 180
    assert console.width > terminal_ui.DEFAULT_FALLBACK_COLUMNS

    # A 150-char single token fits on one physical line at width ~200 and must not be
    # wrapped as it would be at the 120 fallback.
    long_token = "x" * 150
    console.print(long_token, highlight=False, markup=False, soft_wrap=False)
    rendered = stream.getvalue()
    assert long_token in rendered
