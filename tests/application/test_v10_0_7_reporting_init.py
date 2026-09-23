"""v10.0.7 regressions in the report writer and the ``init`` writer.

Three defects found by the clean-room validation of the published v10.0.6 wheel:

- **Concurrent runs lost reports.** Eight ``evaluate`` runs sharing one ``--output-dir``
  failed ~4.4% of the time with ``Cannot write to --output-dir: <access denied>``. The
  loser of a same-instant ``os.replace`` onto ``evaluation-report.json`` was reporting a
  handle held for a millisecond as if the adopter could not write to the directory at
  all. Both steps of the atomic write now retry that specific conflict -- and only that
  conflict, and only for a bounded window, so a standing denial still surfaces.

- **``--include-absolute-path`` meant two different things.** With the flag set the
  Markdown report printed every evidence reference in full while the JSON kept
  ``{"value": "<redacted-absolute>/SECURITY.md", "redacted": true}``. One flag, two
  disclosure levels, depending only on which file the reader opened. The JSON now
  restores the same references the Markdown does. The privacy-critical case -- no flag --
  was already correct and stays correct: both formats redact.

- **``init`` answered a relative ``--target`` with absolute paths.** ``init --format
  json`` echoed ``"target"`` plus a dozen paths under ``actions.created`` fully qualified
  -- home directory, account name and all -- in the output most likely to be pasted into
  a PR or a CI log (M-002). The action paths are now relative to the target, like
  ``evaluate``'s.

Every guard here was mutation-tested: the fix was reverted, the test was confirmed to
fail, and the fix was restored.
"""

from __future__ import annotations

import errno
import json
import os
import threading
from pathlib import Path
from typing import Any

import pytest

from oss_policy_kit.application import reporting as rp
from oss_policy_kit.application.init_planner import build_init_plan
from oss_policy_kit.application.init_writer import execute_init_plan
from oss_policy_kit.cli.init import _build_json_payload
from oss_policy_kit.domain.models import ControlResult, ControlStatus, ExecutionReport

# Synthetic rooted evidence paths: never a real home directory, so the assertions prove
# the prefix and the account segment are (or are not) stripped without depending on the
# host's own layout -- and without the 8.3 short-path trap that makes a Windows run pass
# an absolute-path assertion for the wrong reason.
_POSIX_EVIDENCE = "/synthetic-abs-root/ci-user/secret-repo/.github/workflows/ci.yml"
_WINDOWS_EVIDENCE = "Z:\\synthetic-win\\ci-user\\secret-repo\\SECURITY.md"
_RELATIVE_EVIDENCE = "docs/SECURITY.md"
_URL_EVIDENCE = "https://example.com/policy.md"


# ======================================================================================
# Concurrent report writes
# ======================================================================================


def _sharing_conflict(destination: Path) -> PermissionError:
    """The error Windows raises when another process is holding *destination*.

    ``winerror`` is set explicitly rather than left to the platform: the production
    predicate reads it through ``getattr``, so setting it here exercises the Windows
    branch on a POSIX CI run too. A branch only one platform can reach is a branch
    nobody checks.
    """

    exc = PermissionError(errno.EACCES, "Access is denied", str(destination))
    exc.winerror = 5  # type: ignore[attr-defined]
    return exc


def _replace_failing_n_times(monkeypatch: pytest.MonkeyPatch, failures: int) -> list[int]:
    """Make ``os.replace`` raise a sharing conflict *failures* times, then work.

    Returns a single-element list holding the call count, so a test can assert the
    retry budget was spent (or not spent).
    """

    calls = [0]
    real_replace = os.replace

    def flaky(src: Any, dst: Any, *args: Any, **kwargs: Any) -> None:
        calls[0] += 1
        if calls[0] <= failures:
            raise _sharing_conflict(Path(dst))
        real_replace(src, dst, *args, **kwargs)

    monkeypatch.setattr(rp.os, "replace", flaky)
    return calls


def test_a_sharing_conflict_on_the_final_rename_is_retried_until_it_clears(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The write that lost the race must land, not become "cannot write to --output-dir"."""

    calls = _replace_failing_n_times(monkeypatch, failures=3)
    dest = tmp_path / "evaluation-report.json"
    dest.write_text('{"previous": true}\n', encoding="utf-8")

    rp._atomic_write_text(dest, '{"contract_version": "reports/2.0"}\n')

    assert calls[0] == 4, "the rename was not retried past the transient conflict"
    assert json.loads(dest.read_text(encoding="utf-8")) == {"contract_version": "reports/2.0"}
    assert [p.name for p in tmp_path.iterdir()] == [dest.name], "a temp file was orphaned by the retry"


def test_a_standing_permission_denial_is_reported_not_retried_away(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A read-only output directory must still fail -- with its own error, not a swallowed one.

    This test previously simulated the denial by failing ``os.replace`` alone, and that
    was not a read-only directory: it was a held handle, where the rename is refused and
    an in-place write succeeds. The distinction is the whole of the fix this file also
    covers, so the denial is made real here -- both routes to the destination refuse,
    exactly as a read-only directory or a hostile ACL behaves.
    """

    calls = _replace_failing_n_times(monkeypatch, failures=999)
    dest = tmp_path / "evaluation-report.json"

    real_write_text = Path.write_text

    def denied(self: Path, *args: Any, **kwargs: Any) -> int:
        if self == dest:
            raise _sharing_conflict(self)
        return real_write_text(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "write_text", denied)

    with pytest.raises(PermissionError) as caught:
        rp._atomic_write_text(dest, "payload\n")

    assert caught.value.errno == errno.EACCES
    assert "Access is denied" in str(caught.value)
    assert calls[0] == len(rp._CONTENTION_RETRY_DELAYS) + 1, "the retry budget is not the documented one"
    assert not dest.exists(), "a failed write must leave the previous report untouched"
    assert list(tmp_path.iterdir()) == [], "a failed write orphaned its temp file"


def test_a_handle_held_open_on_the_report_does_not_fail_the_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The counterpart: a conflict that outlives the budget falls back to writing in place.

    On Windows any open handle on the destination blocks a rename for as long as the
    holder keeps it -- a dashboard, a CI artifact-upload step, an editor, a backup agent,
    OneDrive, an antivirus scanner. Measured before this fallback existed: one reader
    holding the report for 50 ms failed 12 of 12 sequential, non-concurrent ``evaluate``
    runs. That is a hard failure for the exact case the atomic write was written to
    protect.

    The reader pays a torn read; the operator would have paid their build. Note the
    denial test above is what keeps this from becoming a way to launder a real refusal:
    there, the in-place route is refused too, and the error surfaces.
    """

    calls = _replace_failing_n_times(monkeypatch, failures=999)
    dest = tmp_path / "evaluation-report.json"
    dest.write_text('{"previous": true}\n', encoding="utf-8")

    rp._atomic_write_text(dest, '{"contract_version": "reports/2.0"}\n')

    assert calls[0] == len(rp._CONTENTION_RETRY_DELAYS) + 1, "the budget was not spent before falling back"
    assert json.loads(dest.read_text(encoding="utf-8")) == {"contract_version": "reports/2.0"}
    assert [p.name for p in tmp_path.iterdir()] == [dest.name], "the fallback orphaned its temp file"


def test_an_error_that_is_not_contention_is_raised_on_the_first_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only a sharing conflict is worth waiting out; everything else must fail fast."""

    calls = [0]

    def missing_directory(src: Any, dst: Any, *args: Any, **kwargs: Any) -> None:
        calls[0] += 1
        raise FileNotFoundError(errno.ENOENT, "No such file or directory", str(dst))

    monkeypatch.setattr(rp.os, "replace", missing_directory)

    with pytest.raises(FileNotFoundError):
        rp._atomic_write_text(tmp_path / "evaluation-report.json", "payload\n")

    assert calls[0] == 1, "a non-contention error burned the retry budget instead of surfacing"


def test_a_sharing_conflict_creating_the_temp_file_does_not_downgrade_to_a_plain_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The in-place fallback is for the path-length case, not for a transient conflict.

    Degrading to ``Path.write_text`` under contention would give up atomicity against the
    very process being contended with -- the interleaved, half-written report the atomic
    write exists to prevent.
    """

    dest = tmp_path / "evaluation-report.json"
    real_create = rp._create_temp_exclusive
    creates = [0]
    replaces = [0]
    real_replace = os.replace

    def flaky_create(tmp: Path, text: str) -> None:
        creates[0] += 1
        if creates[0] <= 2:
            raise _sharing_conflict(tmp)
        real_create(tmp, text)

    def counted_replace(src: Any, dst: Any, *args: Any, **kwargs: Any) -> None:
        replaces[0] += 1
        real_replace(src, dst, *args, **kwargs)

    monkeypatch.setattr(rp, "_create_temp_exclusive", flaky_create)
    monkeypatch.setattr(rp.os, "replace", counted_replace)

    rp._atomic_write_text(dest, "payload\n")

    assert creates[0] == 3, "the temp-file creation was not retried"
    assert replaces[0] == 1, "the write fell back to a non-atomic in-place write under contention"
    assert dest.read_text(encoding="utf-8") == "payload\n"


def test_concurrent_writers_all_publish_a_whole_report(tmp_path: Path) -> None:
    """The end-to-end shape of the defect: many writers, one destination, no failures.

    This is the assertion that actually caught the bug and it only bites where the
    operating system produces the conflict -- on Windows this loop failed ~19% of its
    writes before the retry existed, on POSIX ``rename`` is atomic against a concurrent
    rename and it never failed at all. The monkeypatched tests above are what hold the
    line on every platform; this one proves the real thing works.
    """

    dest = tmp_path / "reports" / "evaluation-report.json"
    dest.parent.mkdir(parents=True)
    writers, rounds = 8, 25
    payload = "y" * 20_000
    failures: list[BaseException] = []
    at_the_line = threading.Barrier(writers)

    def write_repeatedly(worker: int) -> None:
        at_the_line.wait()
        for attempt in range(rounds):
            try:
                rp._atomic_write_text(dest, json.dumps({"worker": worker, "attempt": attempt, "pad": payload}) + "\n")
            except BaseException as exc:  # noqa: BLE001 - the failure itself is the finding
                failures.append(exc)

    threads = [threading.Thread(target=write_repeatedly, args=(w,)) for w in range(writers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert not failures, f"{len(failures)}/{writers * rounds} concurrent report writes failed: {failures[:3]}"
    # Whoever won last, the surviving report is one writer's complete output.
    survivor = json.loads(dest.read_text(encoding="utf-8"))
    assert survivor["pad"] == payload
    assert [p.name for p in dest.parent.iterdir()] == [dest.name], "temp files were orphaned"


def test_a_planted_temp_file_stops_the_write_and_is_left_untouched(tmp_path: Path) -> None:
    """Exclusive create is the anti-symlink guard; a retry must never turn it into a clobber."""

    planted = tmp_path / ".evaluation-report.json.deadbeef.tmp"
    planted.write_text("planted\n", encoding="utf-8")

    with pytest.raises(FileExistsError):
        rp._create_temp_exclusive(planted, "overwrite me\n")

    assert planted.read_text(encoding="utf-8") == "planted\n"
    assert not rp._is_sharing_conflict(FileExistsError(errno.EEXIST, "File exists")), (
        "a name that will not free itself must not be retried"
    )


def test_a_blocked_temp_name_refuses_the_write_rather_than_bypassing_the_temp_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``FileExistsError`` must not fall through into the path-length in-place fallback.

    It is an ``OSError``, so one missing except-clause turns "something is squatting on
    my temp name" into "write the destination directly" -- which is the bypass the
    exclusive create exists to refuse.
    """

    class _FixedToken:
        hex = "deadbeef" + "0" * 24

    monkeypatch.setattr(rp.uuid, "uuid4", lambda: _FixedToken())
    dest = tmp_path / "evaluation-report.json"
    dest.write_text("previous\n", encoding="utf-8")
    (tmp_path / ".evaluation-report.json.deadbeef.tmp").write_text("planted\n", encoding="utf-8")

    with pytest.raises(FileExistsError):
        rp._atomic_write_text(dest, "new\n")

    assert dest.read_text(encoding="utf-8") == "previous\n", "the blocked write reached the destination anyway"


def test_a_failed_temp_write_leaves_no_file_for_the_next_attempt_to_collide_with(tmp_path: Path) -> None:
    """Without the cleanup, a retry would hit its own leftovers and report the wrong error."""

    vanished = tmp_path / "gone" / ".evaluation-report.json.deadbeef.tmp"

    with pytest.raises(OSError):
        rp._create_temp_exclusive(vanished, "payload\n")

    assert not vanished.exists()
    assert not vanished.parent.exists()


def test_the_conflict_predicate_matches_the_two_windows_codes_and_nothing_else() -> None:
    """ERROR_ACCESS_DENIED (5) and ERROR_SHARING_VIOLATION (32) are the retryable pair."""

    for code in (5, 32):
        exc = OSError(errno.EACCES, "stand-in")
        exc.winerror = code  # type: ignore[attr-defined]
        assert rp._is_sharing_conflict(exc), f"winerror {code} should be treated as contention"

    for code in (2, 3, 206, 28):
        exc = OSError(errno.ENOENT, "stand-in")
        exc.winerror = code  # type: ignore[attr-defined]
        assert not rp._is_sharing_conflict(exc), f"winerror {code} is not contention and must not be retried"

    # No winerror (POSIX, or an exception the kit built itself): the type decides.
    assert rp._is_sharing_conflict(PermissionError(errno.EACCES, "Permission denied"))
    assert not rp._is_sharing_conflict(FileNotFoundError(errno.ENOENT, "No such file or directory"))
    assert not rp._is_sharing_conflict(FileExistsError(errno.EEXIST, "File exists"))


# ======================================================================================
# --include-absolute-path parity between the JSON and the Markdown report
# ======================================================================================


def _report_with_evidence(sources: list[str]) -> ExecutionReport:
    return ExecutionReport(
        schema_version="https://x/reports/2.0",
        generated_at="2026-06-15T12:00:00Z",
        kit_version="10.0.7",
        target_path="/synthetic-abs-root/ci-user/secret-repo",
        profile_id="github-level-1",
        profile_title="GitHub level 1",
        summary_by_status={"pass": 1},
        results=[
            ControlResult(
                control_id="GOV-SEC-001",
                title="Security policy present",
                category="governance",
                status=ControlStatus.PASS,
                profile="github-level-1",
                evidence_sources=list(sources),
                confidence="high",
                reason="ok",
                remediation="keep",
            ),
        ],
        operational_warnings=[],
    )


def _json_reference_values(report: ExecutionReport, *, include_absolute_path: bool) -> list[str]:
    payload = rp.report_to_dict(report, include_absolute_path=include_absolute_path)
    return [ref["value"] for ref in payload["controls"][0]["evidence"]["references"]]


def _markdown_evidence_bullets(report: ExecutionReport, tmp_path: Path, *, include_absolute_path: bool) -> list[str]:
    md = tmp_path / "evaluation-report.md"
    rp.write_markdown_report(report, md, include_absolute_path=include_absolute_path)
    detail = md.read_text(encoding="utf-8").split("## Detail", 1)[1]
    return [line.strip().removeprefix("- ").strip("`") for line in detail.splitlines() if line.startswith("  - `")]


def test_the_flag_reveals_the_same_evidence_in_both_report_formats(tmp_path: Path) -> None:
    """One flag, one disclosure level -- whichever file the reader opens."""

    report = _report_with_evidence([_POSIX_EVIDENCE, _WINDOWS_EVIDENCE, _RELATIVE_EVIDENCE, _URL_EVIDENCE])

    json_values = _json_reference_values(report, include_absolute_path=True)
    md_values = _markdown_evidence_bullets(report, tmp_path, include_absolute_path=True)

    assert json_values == md_values, "the JSON and Markdown reports disclosed different evidence under one flag"
    assert json_values == [_POSIX_EVIDENCE, _WINDOWS_EVIDENCE, _RELATIVE_EVIDENCE, _URL_EVIDENCE]
    assert "<redacted-absolute>" not in json.dumps(rp.report_to_dict(report, include_absolute_path=True))


def test_the_flag_clears_the_redacted_marker_it_no_longer_earns(tmp_path: Path) -> None:
    """A reference carrying the real path must not still be labelled ``redacted: true``."""

    report = _report_with_evidence([_POSIX_EVIDENCE])
    payload = rp.report_to_dict(report, include_absolute_path=True)
    reference = payload["controls"][0]["evidence"]["references"][0]

    assert reference == {"kind": "path", "value": _POSIX_EVIDENCE, "redacted": False}


def test_without_the_flag_both_formats_still_redact_every_rooted_reference(tmp_path: Path) -> None:
    """The privacy default is the case M-002 is about, and it must not have moved."""

    report = _report_with_evidence([_POSIX_EVIDENCE, _WINDOWS_EVIDENCE, _RELATIVE_EVIDENCE, _URL_EVIDENCE])

    json_values = _json_reference_values(report, include_absolute_path=False)
    md_values = _markdown_evidence_bullets(report, tmp_path, include_absolute_path=False)

    assert json_values == md_values
    assert json_values == [
        "<redacted-absolute>ci.yml",
        "<redacted-absolute>/SECURITY.md",
        _RELATIVE_EVIDENCE,
        _URL_EVIDENCE,
    ]
    # ``target_path`` is legitimately the target's own basename, so the leak check is
    # scoped to the references: nothing above the leaf may survive in either format.
    blob = "\n".join(json_values + md_values)
    assert "ci-user" not in blob
    assert "secret-repo" not in blob
    assert "synthetic" not in blob


def test_the_flag_leaves_urls_and_repo_relative_paths_exactly_as_they_were(tmp_path: Path) -> None:
    """Restoring the redacted references must not rewrite the ones that were never touched."""

    report = _report_with_evidence([_URL_EVIDENCE, _RELATIVE_EVIDENCE])

    assert _json_reference_values(report, include_absolute_path=True) == [_URL_EVIDENCE, _RELATIVE_EVIDENCE]
    assert _json_reference_values(report, include_absolute_path=False) == [_URL_EVIDENCE, _RELATIVE_EVIDENCE]


def test_a_repeated_evidence_path_is_restored_once_per_reference(tmp_path: Path) -> None:
    """Two references that redact to the same value must each get their own source back."""

    other = "/synthetic-abs-root/ci-user/other-repo/.github/workflows/ci.yml"
    report = _report_with_evidence([_POSIX_EVIDENCE, other])

    # Both redact to `<redacted-absolute>ci.yml`, so a naive first-match lookup would
    # hand the same source to both references and silently mislabel one of them.
    assert _json_reference_values(report, include_absolute_path=False) == [
        "<redacted-absolute>ci.yml",
        "<redacted-absolute>ci.yml",
    ]
    assert _json_reference_values(report, include_absolute_path=True) == [_POSIX_EVIDENCE, other]


def test_a_placeholder_evidence_source_stays_dropped_under_the_flag(tmp_path: Path) -> None:
    """The projection's placeholder filter still owns which references exist at all."""

    report = _report_with_evidence(["<placeholder>", _POSIX_EVIDENCE, "TBD"])

    assert _json_reference_values(report, include_absolute_path=True) == [_POSIX_EVIDENCE]
    assert _markdown_evidence_bullets(report, tmp_path, include_absolute_path=True) == [
        "<placeholder>",
        _POSIX_EVIDENCE,
        "TBD",
    ], "the Markdown bullet list is the raw source list; only the JSON filters placeholders"


# ======================================================================================
# init reports its actions relative to the target (M-002)
# ======================================================================================


def _github_repo(root: Path) -> Path:
    (root / ".github" / "workflows").mkdir(parents=True)
    (root / ".github" / "workflows" / "ci.yml").write_text("name: ci\non: [push]\n", encoding="utf-8")
    (root / "README.md").write_text("# demo\n", encoding="utf-8")
    return root


def _plan(target: Path, **overrides: Any) -> Any:
    kwargs: dict[str, Any] = {
        "target": target,
        "forced_profile": "github-level-1",
        "forced_platform": "github",
        "fail_on": "fail",
        "output_dir": "./oss-policy-reports",
        "with_waivers": True,
        "with_evidence": True,
        "with_workflow": True,
        "force": False,
        "dry_run": False,
    }
    kwargs.update(overrides)
    return build_init_plan(**kwargs)


def _all_action_paths(outcome: Any) -> list[Path]:
    return [*outcome.created, *outcome.skipped, *outcome.overwritten]


def test_init_reports_every_action_relative_to_the_target(tmp_path: Path) -> None:
    """A relative ``--target`` must not be answered with a dozen absolute paths."""

    repo = _github_repo(tmp_path / "acme-service")
    outcome = execute_init_plan(_plan(repo))

    paths = _all_action_paths(outcome)
    assert paths, "the fixture should have produced actions"
    absolute = [p for p in paths if p.is_absolute()]
    assert not absolute, f"init reported absolute paths: {absolute[:3]}"

    rendered = {p.as_posix() for p in paths}
    assert "oss-policy-kit.yaml" in rendered
    assert "waivers.yaml" in rendered
    assert ".github/workflows/oss-policy-check.yml" in rendered
    assert any(r.startswith(".oss-policy-kit/evidence/") for r in rendered), rendered

    # Every reported path still points at a real artifact, resolved against the target.
    for path in outcome.created:
        assert (repo / path).exists(), f"reported path does not resolve under the target: {path}"


def test_init_json_output_carries_no_absolute_action_path(tmp_path: Path) -> None:
    """The exact surface the defect names: ``init --format json``'s ``actions`` block."""

    repo = _github_repo(tmp_path / "acme-service")
    plan = _plan(repo)
    payload = _build_json_payload(plan=plan, outcome=execute_init_plan(plan), dry_run=False)

    actions = json.dumps(payload["actions"])
    assert str(tmp_path) not in actions, "the temp-root prefix leaked into init's machine output"
    for bucket in ("created", "skipped", "overwritten"):
        for entry in payload["actions"][bucket]:
            assert not Path(entry).is_absolute(), f"actions.{bucket} still carries an absolute path: {entry}"
    assert "oss-policy-kit.yaml" in payload["actions"]["created"]


def test_init_dry_run_previews_relative_paths_too(tmp_path: Path) -> None:
    """The preview an adopter reads before committing must not leak either."""

    repo = _github_repo(tmp_path / "acme-service")
    outcome = execute_init_plan(_plan(repo, dry_run=True))

    paths = _all_action_paths(outcome)
    assert paths
    assert not [p for p in paths if p.is_absolute()]
    assert any(p.as_posix().startswith(".oss-policy-kit/evidence/") for p in paths), paths
    assert not (repo / "oss-policy-kit.yaml").exists(), "a dry run wrote to disk"

    # The other two dry-run buckets render through the same helper: preview an
    # already-initialized repo, with and without --force.
    execute_init_plan(_plan(repo))
    kept = execute_init_plan(_plan(repo, dry_run=True))
    assert "oss-policy-kit.yaml" in {p.as_posix() for p in kept.skipped}
    assert not [p for p in kept.skipped if p.is_absolute()]

    replaced = execute_init_plan(_plan(repo, dry_run=True, force=True))
    assert "oss-policy-kit.yaml" in {p.as_posix() for p in replaced.overwritten}
    assert not [p for p in replaced.overwritten if p.is_absolute()]


def test_init_reports_skipped_and_overwritten_relatively_on_a_second_run(tmp_path: Path) -> None:
    """The idempotent re-run buckets go through the same rendering as the first run."""

    repo = _github_repo(tmp_path / "acme-service")
    execute_init_plan(_plan(repo))

    kept = execute_init_plan(_plan(repo))
    assert kept.skipped, "a second run without --force should keep existing files"
    assert not [p for p in kept.skipped if p.is_absolute()]
    assert "oss-policy-kit.yaml" in {p.as_posix() for p in kept.skipped}

    replaced = execute_init_plan(_plan(repo, force=True))
    assert replaced.overwritten, "--force should report overwritten files"
    assert not [p for p in replaced.overwritten if p.is_absolute()]
    assert "oss-policy-kit.yaml" in {p.as_posix() for p in replaced.overwritten}


def _tree(root: Path) -> dict[str, bytes]:
    # Directories too: an empty directory left behind by a preview is still a write.
    return {q.relative_to(root).as_posix(): q.read_bytes() if q.is_file() else b"" for q in sorted(root.rglob("*"))}


@pytest.mark.parametrize("force", [False, True], ids=["kept", "forced"])
@pytest.mark.parametrize("initialised", [False, True], ids=["fresh", "initialised"])
def test_a_dry_run_lists_exactly_what_the_run_then_does(tmp_path: Path, initialised: bool, force: bool) -> None:
    """The preview named the evidence directory, never the files in it.

    ``init --with-evidence --force --dry-run`` on an initialised repository printed
    ``+ .oss-policy-kit/evidence`` as if it were about to be created, and said nothing about
    the eight evidence files the same command without ``--dry-run`` replaces. An adopter
    reads the preview to learn what ``--force`` will destroy, and it hid exactly that.
    """

    repo = _github_repo(tmp_path / "acme-service")
    if initialised:
        execute_init_plan(_plan(repo))
    before = _tree(repo)

    preview = execute_init_plan(_plan(repo, force=force, dry_run=True))
    assert _tree(repo) == before, "a dry run changed the target"

    run = execute_init_plan(_plan(repo, force=force))
    for bucket in ("created", "skipped", "overwritten"):
        assert sorted(getattr(preview, bucket)) == sorted(getattr(run, bucket)), bucket
    assert any(q.as_posix().startswith(".oss-policy-kit/evidence/") for q in _all_action_paths(preview))


def test_a_path_outside_the_target_degrades_to_its_name_not_to_an_absolute_path(tmp_path: Path) -> None:
    """The fallback has to hold the same line the relativization does."""

    from oss_policy_kit.application.init_writer import _reported_path

    inside = _reported_path(tmp_path / "repo" / "oss-policy-kit.yaml", tmp_path / "repo")
    assert inside == Path("oss-policy-kit.yaml")

    outside = _reported_path(tmp_path / "elsewhere" / "leaked.yaml", tmp_path / "repo")
    assert not outside.is_absolute()
    assert outside == Path("leaked.yaml")
