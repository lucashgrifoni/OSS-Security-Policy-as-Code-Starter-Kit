"""Shared helpers for the scanner-evidence rule evaluators (IaC/K8s families).

Each ``_make_*_evaluator`` reads the same evidence shape (``files_scanned``,
``findings_by_rule``, ``findings``). Centralizing the list/count/sample plumbing
keeps every per-rule ``_eval`` closure flat (low cognitive complexity) while the
PASS/FAIL/NA messages stay in their family module.
"""

from __future__ import annotations

from typing import Any

from oss_policy_kit.application.evidence_projection import _redact_path
from oss_policy_kit.domain.models import ControlStatus, EvalOutcome


def unread_sources(
    data: dict[str, Any],
    limit: int = 3,
    *,
    only_resembling: str | None = None,
) -> tuple[list[str], int]:
    """Return ``(names to show, total)`` for the files a scanner could not parse.

    The names are redacted through the report's own path rule, because
    ``diagnostics.parse_errors[].file`` is INPUT: the kit's scanners write a repo-relative
    path there, but the evidence file is a JSON document a user or another tool may have
    written, and it lands verbatim in a control message, the Markdown report and
    findings.json. The first version of this trusted a code comment asserting the value was
    relative; an evidence file naming an absolute path under a user's home directory put that
    account name straight into the report (M-002).

    The total is returned separately so a caller cannot phrase a truncated list as a complete
    one -- which the first version did, saying "every candidate file failed to parse (a, b, c)"
    when there were nine.

    ``only_resembling`` keeps just the entries whose ``resembles`` matches, which is how a
    scanner says "this one still read as my technology after the parse failed". ``scan-k8s``
    reaches every ``**/*.yaml`` in a tree, so without the filter a broken workflow and an
    unparseable Pod are the same entry; with it they are not. ``None`` keeps every entry, which
    is what a scanner whose glob already names its technology wants, and what evidence written
    before the key existed produces anyway.
    """

    diagnostics = data.get("diagnostics")
    if not isinstance(diagnostics, dict):
        return [], 0
    errors = diagnostics.get("parse_errors")
    if not isinstance(errors, list):
        return [], 0

    # De-duplicate on the ORIGINAL path and redact after. Redaction keeps only the final
    # component, so `/a/main.tf` and `/b/main.tf` both become `<redacted-absolute>/main.tf`
    # -- de-duplicating on that collapsed two unread files into one and under-reported the
    # count in the same breath as the message that quotes it.
    originals: list[str] = []
    for entry in errors:
        if not isinstance(entry, dict):
            continue
        if only_resembling is not None and entry.get("resembles") != only_resembling:
            continue
        name = entry.get("file")
        if isinstance(name, str) and name and name not in originals:
            originals.append(name)
    return [_redact_path(n)[0] for n in originals[:limit]], len(originals)


def _files_read(data: dict[str, Any]) -> int:
    """How many candidate files the scan actually read.

    Not `len(files_scanned)`. Two scanners narrow that list to sources of their technology --
    `scan-pulumi` keeps only modules importing pulumi, `scan-cfn` only files that load as
    templates -- so a repository with ten ordinary Python files and one with a syntax error
    left it empty, and reading the emptiness as "nothing here was legible" withdrew the verdict
    of six controls over a repository that simply has no Pulumi in it.

    Falls back to `files_scanned` for the scanners whose list is already unfiltered, and to 0
    for evidence written before the field existed -- which restores the older, blunter reading
    rather than silently passing.
    """

    diagnostics = data.get("diagnostics")
    if isinstance(diagnostics, dict) and isinstance(diagnostics.get("files_read"), int):
        return int(diagnostics["files_read"])
    return len(files_scanned_list(data))


def _phrase(shown: list[str], total: int) -> str:
    """`a, b` or `a, b, c and 4 more` -- never a truncated list that reads as complete."""

    listed = ", ".join(shown)
    remaining = total - len(shown)
    return f"{listed} and {remaining} more" if remaining > 0 else listed


def unread_sources_note(data: dict[str, Any]) -> str:
    """A sentence naming the files the scanner skipped, to append to a clean reason.

    A PASS earned over part of the sources is *true* -- it says "no findings across N scanned
    sources" and means it. What it never said is that there were more sources than N. Stating
    the skipped files leaves the verdict intact and hands the reader the scope it applies to.

    Deliberately not a downgrade. See `absent_technology_outcome` for why.
    """

    shown, total = unread_sources(data)
    if not shown:
        return ""
    return f" The scanner could not parse {_phrase(shown, total)}, which this result does not cover."


def unread_sources_withdrawal(
    data: dict[str, Any],
    *,
    technology: str,
    why: str,
    regenerate_cmd: str,
    sources: list[str],
    only_resembling: str | None = None,
) -> EvalOutcome | None:
    """Withdraw a CLEAN verdict when a file that *is* this technology was never read.

    ADR-045 in the one place it had not reached: a control that cannot read its evidence
    answers ``manual-review-required``. Here the evidence is partial rather than absent, and
    partial was being reported as complete -- twelve Terraform controls at 100% over a
    ``.tf`` the scanner could not open, which declared ``acl = "public-read"``.

    The message those controls printed was true. "No IAC-TF-001 findings detected across 1
    scanned Terraform source" is exactly what happened, and it never claimed there was only
    one source. Truth is not the bar for a security verdict: the question ``IAC-TF-001`` is
    asked is whether this repository exposes object storage publicly, and it answered that
    over the file it could read.

    **Which unread files count is the whole question.** A guard shaped like this one was
    written before and was worse than the bug: it withdrew every Kubernetes control on the
    kit's own repository, because ``scan-k8s`` reaches every ``**/*.yaml`` in the tree and
    hits scratch files plus a fixture that is malformed on purpose. It fired on correct
    content, and a guard that fires on correct content is one somebody switches off.

    So two families answer from the candidate set and three from a mark the scanner leaves:

    ==============  ===============================  ====================================
    scanner         glob                             an unread candidate counts when
    ==============  ===============================  ====================================
    ``scan-iac``    ``**/*.tf``                      always; every candidate is Terraform
    ``scan-bicep``  ``**/*.bicep``                   always; every candidate is Bicep
    ``scan-k8s``    ``**/*.yaml`` ``**/*.yml``       it still carries apiVersion and kind
    ``scan-cfn``    ``.yaml .yml .json .template``   it still reads as a template
    ``scan-pulumi`` ``**/*.py``                      it still imports pulumi
    ==============  ===============================  ====================================

    ``only_resembling`` selects the second form. An unmarked entry stays the diagnostic it
    already was, and :func:`unread_sources_note` still states the scope of a PASS earned over
    part of the sources.

    The mark comes from raw text, because the parse is what failed and there is nothing else
    to read. That primitive once let ``workflow_parser`` grant a PASS from a commented-out
    step; here it runs in the opposite direction and can only make a verdict more cautious. A
    commented-out ``apiVersion:`` costs an operator a second look. The inverse error is a
    privileged pod reported as a clean cluster.

    Returns ``None`` when nothing counts, which is every ordinary repository -- so a family
    that adopts this keeps the verdict it reaches today.

    Callers put this in the ZERO-FINDINGS branch only. A rule with a finding is unaffected on
    purpose: unread sources can only ADD violations, so they never make an existing ``FAIL``
    less true, and replacing one with ``manual-review-required`` would turn a red pipeline
    green -- that state does not trip ``--fail-on fail``.
    """

    shown, total = unread_sources(data, only_resembling=only_resembling)
    if not shown:
        return None

    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason=(
            f"Nothing was found in the {technology} sources that parsed, but {total} did not parse "
            f"({_phrase(shown, total)}). {why}"
        ),
        remediation=(
            f"Fix the listed file(s) so they parse -- a committed merge-conflict marker, a syntax "
            f"error, or a non-UTF-8 encoding are the usual causes -- and re-run `{regenerate_cmd}`. "
            "Use `--fail-on degraded` to make this stop a pipeline."
        ),
        evidence_sources=sources,
        confidence="low",
    )


def absent_technology_outcome(
    data: dict[str, Any],
    *,
    technology: str,
    sources: list[str],
) -> EvalOutcome | None:
    """Refuse to declare a technology ABSENT when files existed and none could be read.

    A `.tf` file saved as UTF-16 -- one `git add` on Windows away -- made every Terraform control
    answer NOT_APPLICABLE, *"No Terraform / OpenTofu sources detected in repository"*, about a
    repository whose only Terraform file declared a public-read bucket and a security group open
    to `0.0.0.0/0`. The scanner had recorded the failure in `diagnostics.parse_errors`; nothing
    downstream read it.

    `not-applicable` reads like a shrug, but it is a positive claim about the repository, and it
    is the one state no summary counts -- the quietest place a false statement can sit. Zero
    files parsed plus at least one that failed is not "nothing here", it is "nothing legible".

    **Only this branch blocks.** A clean result over the files that *did* parse keeps its PASS
    and states its scope via `unread_sources_note`, and the first version of this guard got that
    wrong: it downgraded PASS too, and on this very repository all 16 Kubernetes controls turned
    UNKNOWN -- because `scan-k8s` globs `**/*.yaml` across the whole tree and hit four scratch
    files plus a fixture that is malformed *on purpose*. A guard that fires on correct content is
    a guard somebody switches off. Repositories carrying deliberately-broken YAML are ordinary;
    repositories where nothing at all parses are not.

    A rule with a real finding is unaffected either way: unread sources can only ADD violations,
    so they never make an existing FAIL less true.
    """

    shown, total = unread_sources(data)
    if not shown or _files_read(data) > 0:
        return None

    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason=(
            f"The {technology} scan could not read any file it looked at; {total} failed to "
            f"parse ({_phrase(shown, total)}). Whether this repository uses {technology} "
            "cannot be settled from evidence this incomplete."
        ),
        remediation=(
            "Check diagnostics.parse_errors in the evidence file. A file saved as UTF-16 or "
            "another non-UTF-8 encoding is the usual cause -- re-save it as UTF-8 and re-scan. "
            "Use `--fail-on degraded` to make this stop a pipeline."
        ),
        evidence_sources=sources,
        confidence="low",
    )


def files_scanned_list(data: dict[str, Any]) -> list[Any]:
    """Return the evidence ``files_scanned`` list (empty when absent or malformed)."""

    fs = data.get("files_scanned") or []
    return fs if isinstance(fs, list) else []


def rule_finding_count(data: dict[str, Any], rule_id: str) -> int:
    """Return the count of findings recorded for ``rule_id`` in ``findings_by_rule``."""

    by_rule = data.get("findings_by_rule") or {}
    if not isinstance(by_rule, dict):
        return 0
    return int(by_rule.get(rule_id, 0) or 0)


def sample_finding_files(data: dict[str, Any], rule_id: str, limit: int = 3) -> list[str]:
    """Return up to ``limit`` distinct source files that triggered ``rule_id``."""

    out: list[str] = []
    for f in data.get("findings", []) or []:
        if isinstance(f, dict) and f.get("rule_id") == rule_id:
            file_ = f.get("file")
            if isinstance(file_, str) and file_ and file_ not in out:
                out.append(file_)
        if len(out) >= limit:
            break
    return out
