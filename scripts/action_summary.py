#!/usr/bin/env python3
"""Render a GitHub Actions job summary + per-finding annotations from a report.

Used by the composite Action (``action.yml``). Pure standard library so it runs under any
Python the runner provides. Reads ``evaluation-report.json`` (reports/2.0) from argv[1],
appends a Markdown summary to ``$GITHUB_STEP_SUMMARY`` (falls back to stdout locally), and
prints ``::error`` / ``::warning`` workflow commands for ``fail`` / manual-review controls.

It NEVER changes the evaluation's exit code — the Action forwards that separately. Any error
here is non-fatal (the caller invokes it with ``|| true``).
"""

from __future__ import annotations

import html
import json
import os
import re
import sys
from collections import Counter
from typing import Any

_FAIL_STATES = ("FAIL",)
_REVIEW_STATES = ("UNKNOWN", "MANUAL_REVIEW_REQUIRED", "MANUAL-REVIEW-REQUIRED")
_STATE_ORDER = ("PASS", "FAIL", "UNKNOWN", "NOT_APPLICABLE", "ATTESTED")


def _state(control: dict[str, Any]) -> str:
    return str(control.get("state") or control.get("status") or "UNKNOWN").upper()


def _reason(control: dict[str, Any]) -> str:
    # reports/2.0 carries the failure reason in `message`; `title` is the control's purpose.
    text = control.get("message") or control.get("reason") or control.get("detail") or control.get("title") or ""
    return str(text).strip()


#: Markdown punctuation that could turn repository text into a link, image, or emphasis.
_MD_SPECIAL = re.compile(r"([\\`*_\[\]!~#])")


def _md_cell(text: str) -> str:
    """Repository text as plain words in a summary table cell.

    Messages quote the scanned repository (a workflow job name, for one), and GitHub renders the
    summary as Markdown with inline HTML. Tags and Markdown punctuation are escaped so that text
    shows as written instead of becoming a link or an image; ``|`` and line breaks would end the
    table row.
    """

    flat = " ".join(text.replace("|", "/").split())
    return _MD_SPECIAL.sub(r"\\\1", html.escape(flat, quote=False))


def _command_value(text: str) -> str:
    """Escape a workflow-command message the way GitHub's toolkit does.

    The runner splits commands on line breaks, including a bare ``\\r``, so an unescaped one in a
    message starts a new command. ``%`` is escaped first because it is the escape character.
    """

    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _command_property(text: str) -> str:
    """Escape a workflow-command property, which also ends at ``:`` or ``,``."""

    return _command_value(text).replace(":", "%3A").replace(",", "%2C")


def build_summary(report: dict[str, Any]) -> str:
    controls = report.get("controls") or report.get("results") or []
    counts = Counter(_state(c) for c in controls)
    profile_obj: Any = report.get("profile") or report.get("profile_id") or report.get("profile-id") or "profile"
    # reports/2.0 embeds the full profile object; older shapes use a bare id string.
    profile = profile_obj.get("id", "profile") if isinstance(profile_obj, dict) else profile_obj
    lines = [f"## oss-policy-kit — `{profile}`", "", "| Status | Count |", "|---|---:|"]
    for st in _STATE_ORDER:
        if counts.get(st):
            lines.append(f"| {st} | {counts[st]} |")
    failing = [c for c in controls if _state(c) in _FAIL_STATES]
    if failing:
        lines += ["", "### Failing controls", "", "| Control | Reason |", "|---|---|"]
        lines += [f"| `{c.get('id')}` | {_md_cell(_reason(c))} |" for c in failing]
    return "\n".join(lines) + "\n"


def emit_annotations(report: dict[str, Any], out: Any) -> None:
    for c in report.get("controls") or report.get("results") or []:
        st = _state(c)
        title = _command_property(str(c.get("id")))
        if st in _FAIL_STATES:
            out.write(f"::error title={title}::{_command_value(_reason(c) or 'control failed')}\n")
        elif st in _REVIEW_STATES:
            out.write(f"::warning title={title}::{_command_value(_reason(c) or 'manual review required')}\n")


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        sys.stderr.write("usage: action_summary.py <evaluation-report.json>\n")
        return 2
    try:
        with open(argv[1], encoding="utf-8") as fh:
            report = json.load(fh)
    except (OSError, ValueError) as exc:
        sys.stderr.write(f"action_summary: could not read report: {exc}\n")
        return 0  # non-fatal
    summary = build_summary(report)
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as fh:
            fh.write(summary)
    else:
        sys.stdout.write(summary)
    emit_annotations(report, sys.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
