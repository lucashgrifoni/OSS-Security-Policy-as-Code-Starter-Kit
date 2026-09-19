"""Text a scanned repository chooses must not give the report a destination to fetch.

The report prints a control's reason and remediation, the operational warnings, and a
waiver's owner and justification as prose. The target chooses more of that text than it
looks: `evaluators/ai.py` alone interpolates `{p.name}` and `{rel}` into a dozen reasons,
so a file named `[click](http://somewhere)` inside a scanned repository reaches the page.

Measured against a rendered report before the fix, three shapes worked. An inline link and
an autolink each produced a clickable `<a href>`. An image produced an `<img src>`, and
that one is the reason this is not only about clickable links: an image needs no click, so
opening the report reaches out to whoever wrote the filename.

Reference-style links and bare URLs did not work, the first because the newline that would
carry the definition is flattened and the second because CommonMark does not linkify bare
text. They are left alone rather than defended against, and the cases below record that
they were checked.

What the fix leaves reachable is deliberate. Emphasis still works: a `*` turns text italic
and gives nobody an address. Backticks still work, because three catalog controls quote
filenames with them. A bare `[` still works, because a shipped remediation reads
``runs-on: [self-hosted, ephemeral]`` and escaping it would show the reader a backslash.
"""

from __future__ import annotations

import json
import re

import pytest
from markdown_it import MarkdownIt

from oss_policy_kit.application.drift import DriftReport
from oss_policy_kit.application.reporting import _drift_markdown, _markdown_report_text
from oss_policy_kit.domain.models import ControlResult, ControlStatus, ExecutionReport

#: Anything a reader's browser would follow or fetch, clicked or not.
_DESTINATION = re.compile(r"<a href|<img[^>]*src")

#: Shapes that were measured producing a destination before the fix.
_WORKING_VECTORS = [
    pytest.param("[click](http://evil.invalid)", id="inline-link"),
    pytest.param("![i](http://evil.invalid/beacon.png)", id="image-beacon"),
    pytest.param("<http://evil.invalid>", id="autolink-http"),
    pytest.param("<mailto:someone@evil.invalid>", id="autolink-mailto"),
    pytest.param("<someone@evil.invalid>", id="autolink-bare-email"),
]

#: The lists below are printed as code spans, so the plain vectors are already inert there.
#: A payload carrying its own backtick is not: it ends the span and what follows is markup
#: again. Measured on the commit before this one, all three fields rendered the image.
_ESCAPES_A_CODE_SPAN = pytest.param("WAIVER`-1 ![q](http://evil.invalid/q.png) `z", id="backtick-closes-the-span")

#: Text the kit itself writes. Every one of these has to survive byte for byte.
_LEGITIMATE = [
    pytest.param("`SECURITY.md` not found at repository root.", id="backticks"),
    pytest.param("Add `ephemeral` to the list (e.g. `runs-on: [self-hosted, ephemeral]`)", id="bare-brackets"),
    pytest.param("the value must be < 80 characters", id="bare-less-than"),
    pytest.param("SBOM-like file(s) found but format not confirmed: a.json, b.json.", id="parentheses"),
]


def _report(
    *,
    reason: str = "r",
    remediation: str = "x",
    warning: str | None = None,
    profile_id: str = "github-level-1",
    profile_title: str = "GitHub level 1",
) -> ExecutionReport:
    result = ControlResult(
        control_id="GOV-SEC-001",
        title="Security policy present",
        category="governance",
        status=ControlStatus.FAIL,
        profile="github-level-1",
        evidence_sources=[],
        confidence="high",
        reason=reason,
        remediation=remediation,
    )
    return ExecutionReport(
        schema_version="https://x/reports/2.0",
        generated_at="2026-09-19T00:00:00Z",
        kit_version="10.0.24",
        target_path="repo",
        profile_id=profile_id,
        profile_title=profile_title,
        summary_by_status={"fail": 1},
        results=[result],
        operational_warnings=[warning] if warning else [],
    )


def _rendered(report: ExecutionReport) -> str:
    return MarkdownIt("commonmark").render(_markdown_report_text(report))


@pytest.mark.parametrize("payload", _WORKING_VECTORS)
def test_a_reason_cannot_give_the_report_a_destination(payload: str) -> None:
    html = _rendered(_report(reason=payload))

    assert not _DESTINATION.search(html), (
        f"a reason of {payload!r} put a destination in the report. The reason carries file "
        "names read out of the scanned repository, so the repository chose that address."
    )


@pytest.mark.parametrize("payload", _WORKING_VECTORS)
def test_a_remediation_cannot_give_the_report_a_destination(payload: str) -> None:
    assert not _DESTINATION.search(_rendered(_report(remediation=payload)))


@pytest.mark.parametrize("payload", _WORKING_VECTORS)
def test_an_operational_warning_cannot_give_the_report_a_destination(payload: str) -> None:
    """Warnings name the file that raised them, so their wording comes from the target too."""

    assert not _DESTINATION.search(_rendered(_report(warning=payload)))


@pytest.mark.parametrize("payload", _LEGITIMATE)
def test_the_text_the_kit_writes_is_unchanged(payload: str) -> None:
    """The other half. A fix that escaped everything would pass every case above it."""

    markdown = _markdown_report_text(_report(reason=payload))

    assert payload in markdown, (
        f"{payload!r} came back altered. This is text the kit itself writes, and a reader "
        "would see the escaping rather than the sentence."
    )


def test_the_vectors_that_do_not_work_are_recorded_as_checked() -> None:
    """Anti-drift: if CommonMark or the flattening changes, these stop being safe by luck."""

    assert not _DESTINATION.search(_rendered(_report(reason="http://evil.invalid")))
    assert not _DESTINATION.search(_rendered(_report(reason="[click][r]\n\n[r]: http://evil.invalid")))


@pytest.mark.parametrize("payload", _WORKING_VECTORS)
def test_the_sarif_rule_help_cannot_give_a_viewer_a_destination(payload: str, tmp_path) -> None:
    """SARIF carries a second Markdown surface, and it is outside the report entirely.

    `help.markdown` on the rule is Markdown by the SARIF specification, and it is built from
    the same remediation. A fix that covered only the report would leave the class open
    wherever the SARIF is uploaded.
    """

    from oss_policy_kit.application.sarif_writer import write_sarif_report

    destination = tmp_path / "out.sarif"
    write_sarif_report(_report(remediation=payload), destination)
    document = json.loads(destination.read_text(encoding="utf-8"))
    helps = [
        str((rule.get("help") or {}).get("markdown", ""))
        for run in document["runs"]
        for rule in run["tool"]["driver"].get("rules", [])
    ]

    assert helps, "the SARIF carried no rule help, so this case asserts nothing"
    for markdown in helps:
        assert not _DESTINATION.search(MarkdownIt("commonmark").render(markdown)), (
            f"the SARIF rule help renders a destination from {payload!r}"
        )


# --------------------------------------------------------------------------------------
# The header. Same defect, a route the first pass did not cover.
#
# `--profile` takes a path to a YAML file, and when the flag is omitted the profile comes
# from `oss-policy-kit.yaml` inside the target, resolved against the target. So
# `evaluate --target <cloned repo>` with no flags lets the repository choose both of the
# values below. Measured on the commit before this one, against a repository carrying its
# own config and profile: the rendered report held two `<img src>` beacons and two
# `<a href>` links. The id is the second of each pair, because a value the caller wraps in
# backticks closes its own span on the first backtick it contains.
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("payload", _WORKING_VECTORS)
def test_a_profile_title_cannot_give_the_report_a_destination(payload: str) -> None:
    html = _rendered(_report(profile_title=payload))

    assert not _DESTINATION.search(html), (
        f"a profile title of {payload!r} put a destination in the report. The title comes "
        "from the profile file, which a scanned repository can ship and select through its "
        "own oss-policy-kit.yaml."
    )


@pytest.mark.parametrize("payload", [*_WORKING_VECTORS, _ESCAPES_A_CODE_SPAN])
def test_a_profile_id_cannot_give_the_report_a_destination(payload: str) -> None:
    assert not _DESTINATION.search(_rendered(_report(profile_id=payload)))


def test_a_profile_id_cannot_escape_the_code_span_it_is_printed_in() -> None:
    """The header prints the id as code, and a backtick inside it used to end that."""

    hostile = "ai`-baseline ![z](http://evil.invalid/z.png) `x"

    html = _rendered(_report(profile_id=hostile))

    assert not _DESTINATION.search(html), "the id closed its span and the image rendered"
    assert "<code>" in html, "the id stopped being rendered as code, which is a separate regression"


# --------------------------------------------------------------------------------------
# The drift report. Control ids and waiver ids come out of the two report files `drift`
# is given, and expired waiver ids originate in the scanned repository's waiver file.
# --------------------------------------------------------------------------------------


def _drift(**kwargs: object) -> DriftReport:
    base: dict[str, object] = {
        "before_path": "before.json",
        "after_path": "after.json",
        "before_kit_version": "10.0.23",
        "after_kit_version": "10.0.24",
    }
    base.update(kwargs)
    return DriftReport(**base)  # type: ignore[arg-type]


@pytest.mark.parametrize("field_name", ["new_controls", "removed_controls", "expired_waivers"])
@pytest.mark.parametrize("payload", [*_WORKING_VECTORS, _ESCAPES_A_CODE_SPAN])
def test_a_drift_list_cannot_give_the_report_a_destination(field_name: str, payload: str) -> None:
    html = MarkdownIt("commonmark").render(_drift_markdown(_drift(**{field_name: [payload]})))

    assert not _DESTINATION.search(html), f"{field_name} carried {payload!r} through to a destination"


@pytest.mark.parametrize("payload", _WORKING_VECTORS)
def test_a_drift_profile_mismatch_line_cannot_give_the_report_a_destination(payload: str) -> None:
    report = _drift(profile_mismatch=True, before_profile_id=payload, after_profile_id="after")

    assert not _DESTINATION.search(MarkdownIt("commonmark").render(_drift_markdown(report)))


# --------------------------------------------------------------------------------------
# The guard that finds the next one. A list of known sinks is what missed these; this
# derives the list from the module instead, and fails on anything new that is not
# justified here by name.
# --------------------------------------------------------------------------------------

#: Interpolations into Markdown-shaped strings that legitimately need no escaping, with
#: the reason each one cannot carry target-chosen text. Anything not on this list has to
#: go through an `_md_*` helper.
_NEEDS_NO_ESCAPING = {
    # The kit's own clock and version, neither read from the target.
    "report.generated_at",
    "report.kit_version",
    # A ControlStatus value and an integer count.
    "k",
    "v",
    # Numbers.
    "ws.earned",
    "ws.possible",
    "ws.percent",
    "n",
    "len(report.regressions)",
    "len(report.improvements)",
    "len(report.other_changes)",
    "ss.get('check_count')",
    # Booleans the engine computes.
    "ss.get('loaded')",
    "ss.get('workflows_satisfied_codeql_signal')",
    # Already an escaped composition: `w` is built one line above from
    # `_md_prose(r.waiver.owner, in_table=True)`.
    "w",
    # Not the report at all: an OSError message. It matches only because the sentence
    # contains "-- evaluation-report.json".
    "detail",
}


def test_no_markdown_sink_interpolates_an_unescaped_value() -> None:
    """Derived from the module, so a sink added tomorrow is caught without a list edit."""

    import ast
    import inspect

    from oss_policy_kit.application import reporting

    tree = ast.parse(inspect.getsource(reporting))
    helpers = {"_md_prose", "_md_code", "_md_cell", "_md_line"}

    def is_escaped(node: ast.AST) -> bool:
        return any(
            isinstance(d, ast.Call) and isinstance(d.func, ast.Name) and d.func.id in helpers for d in ast.walk(node)
        )

    unescaped: dict[str, int] = {}
    for joined in ast.walk(tree):
        if not isinstance(joined, ast.JoinedStr):
            continue
        # Each literal piece is tested on its own. Joining them first manufactures markers
        # that are in none of them: `f"control #{index} is not an object"` joins to
        # "control # is not an object" and matches "# ", so two error messages in
        # `digest_for_report_payload` were reported as Markdown sinks. One of the two
        # values is genuinely target-controlled, so allowlisting it would have put a false
        # reason in the list below, which is worse than the false positive.
        chunks = [v.value for v in joined.values if isinstance(v, ast.Constant) and isinstance(v.value, str)]
        if not any(marker in chunk for chunk in chunks for marker in ("**", "| ", "- ", "`", "# ")):
            continue
        for value in joined.values:
            if isinstance(value, ast.FormattedValue) and not is_escaped(value.value):
                unescaped.setdefault(ast.unparse(value.value), value.lineno)

    unexpected = {expr: line for expr, line in unescaped.items() if expr not in _NEEDS_NO_ESCAPING}

    assert not unexpected, (
        "a Markdown-shaped string interpolates a value that no _md_* helper escaped: "
        + ", ".join(f"{expr!r} (line {line})" for expr, line in sorted(unexpected.items()))
        + ". Route it through _md_prose (prose) or _md_code (a code span), or add it to "
        "_NEEDS_NO_ESCAPING with the reason it cannot carry text the target chose."
    )


def test_the_guard_above_would_notice_a_new_sink() -> None:
    """A guard nobody has seen fail is decorative. This is the mutation, run in-process."""

    import ast

    source = 'lines.append(f"- **Profile**: {report.profile_title}")'
    tree = ast.parse(source)
    helpers = {"_md_prose", "_md_code", "_md_cell", "_md_line"}
    found = [
        ast.unparse(v.value)
        for j in ast.walk(tree)
        if isinstance(j, ast.JoinedStr)
        for v in j.values
        if isinstance(v, ast.FormattedValue)
        and not any(
            isinstance(d, ast.Call) and isinstance(d.func, ast.Name) and d.func.id in helpers for d in ast.walk(v.value)
        )
    ]

    assert found == ["report.profile_title"], "the detection the test above relies on does not fire"
    assert "report.profile_title" not in _NEEDS_NO_ESCAPING, "the allowlist would swallow the very sink this PR fixes"
