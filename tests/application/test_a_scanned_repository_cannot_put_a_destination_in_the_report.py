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

The first version of this file measured three shapes and missed a fourth: raw HTML.
CommonMark allows it inline, so `<img src="...">` in a reason is a tag rather than
Markdown syntax, and every case above passed while twelve beacons rendered from the same
fields. Two things let that through. The corpus held only syntax shapes, and the counter
looked for `<a href` and `<img ... src` alone, so a `<video src>` would not have been
counted even had it been tried. Both are wider now. So is one correction to the sweep:
`_md_line` and `_md_cell` handle line structure and `|`, and neutralise no destination,
yet the sweep counted them as escaping. Seventeen interpolations relied on that.
"""

from __future__ import annotations

import inspect
import json
import re

import pytest
from markdown_it import MarkdownIt

from oss_policy_kit.application.drift import DriftReport
from oss_policy_kit.application.reporting import _drift_markdown, _markdown_report_text
from oss_policy_kit.domain.models import ControlResult, ControlStatus, ExecutionReport, WaiverRecord

#: Anything a reader's browser would follow or fetch, clicked or not: a rendered tag carrying
#: an attribute that takes an address, or an event handler, which needs no address to act.
#: The report renders no tag with any attribute at all, so none of these is ever its own.
_DESTINATION = re.compile(
    r"<[A-Za-z][^>]*\s(?:src|href|srcset|poster|data|action|formaction|background|xlink:href|on[a-z]+)\s*=",
    re.IGNORECASE,
)

#: Shapes that were measured producing a destination before the fix.
_WORKING_VECTORS = [
    pytest.param("[click](http://evil.invalid)", id="inline-link"),
    pytest.param("![i](http://evil.invalid/beacon.png)", id="image-beacon"),
    pytest.param("<http://evil.invalid>", id="autolink-http"),
    pytest.param("<mailto:someone@evil.invalid>", id="autolink-mailto"),
    pytest.param("<someone@evil.invalid>", id="autolink-bare-email"),
    pytest.param('<img src="http://evil.invalid/raw.png">', id="raw-html-img"),
    pytest.param('<a href="http://evil.invalid">click</a>', id="raw-html-anchor"),
    pytest.param('<iframe src="http://evil.invalid/f"></iframe>', id="raw-html-iframe"),
    pytest.param('<video src="http://evil.invalid/v.mp4"></video>', id="raw-html-video"),
    pytest.param('<svg><image href="http://evil.invalid/s.png"/></svg>', id="raw-html-svg-image"),
    pytest.param("<IMG SRC=http://evil.invalid/u.png>", id="raw-html-uppercase-unquoted"),
    pytest.param('<svg onload="fetch(1)">', id="raw-html-event-handler"),
]

#: Aimed at the code-span detector rather than at the renderer. Each one tries to make a tag
#: look as though it sits inside a code span, where an escape is not applied.
_TALKS_THE_DETECTOR_OUT_OF_IT = [
    pytest.param('\\`<img src="http://evil.invalid/b1.png">\\`', id="escaped-backticks-around-a-tag"),
    pytest.param('``<img src="http://evil.invalid/b2.png">`', id="backtick-runs-of-different-length"),
    # The inverse, and the one that tells an exact match from "at least as long". A run of
    # one is not closed by a run of two, so the renderer reads the tag as a tag; a detector
    # that closed on any longer run would read it as code and leave it unescaped.
    pytest.param('`<img src="http://evil.invalid/b6.png">``', id="a-run-of-one-is-not-closed-by-two"),
    pytest.param('<img src="http://evil.invalid/b3.png" alt="`">`', id="tag-comes-before-the-backtick"),
    pytest.param('`x` <img src="http://evil.invalid/b4.png"> `y`', id="between-two-real-spans"),
    pytest.param('`unclosed <img src="http://evil.invalid/b5.png">', id="backtick-with-no-partner"),
    # Found by the property test during the 10.0.25 release validation, after #322 merged. The
    # pair is a real code span, and the renderer still read the tag inside it as a tag: the
    # `[` makes markdown-it look ahead for a link label, the lookahead meets the unpaired
    # backtick and caches that no closer exists, and the cached answer then undoes the pair.
    pytest.param(
        '[see `<img src="http://evil.invalid/b7.png">` for `details', id="an-unpaired-backtick-undoes-an-earlier-pair"
    ),
    # The same with an unpaired run of two: escaping only its first backtick leaves a raw
    # run of one with no partner, which poisons the cache exactly as before.
    pytest.param(
        '[see `<img src="http://evil.invalid/b8.png">` for ``details', id="an-unpaired-run-of-two-undoes-it-too"
    ),
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
    # A `<` that opens a tag, but inside a code span, where the renderer prints it as
    # written. Twenty-four spans in the kit's own text have this shape.
    pytest.param("Add `uses: step-security/harden-runner@<sha>` as the first step", id="placeholder-in-a-span"),
    pytest.param("Add signing (`cosign sign --yes <image>@<digest>`) or provenance", id="two-placeholders-one-span"),
]


def _report(
    *,
    reason: str = "r",
    remediation: str = "x",
    warning: str | None = None,
    profile_id: str = "github-level-1",
    profile_title: str = "GitHub level 1",
    waiver_owner: str | None = None,
    waiver_justification: str = "accepted",
) -> ExecutionReport:
    waiver = (
        WaiverRecord(
            control_id="GOV-SEC-001",
            justification=waiver_justification,
            owner=waiver_owner,
            status="active",
            expires_at=None,
            applies_to=None,
        )
        if waiver_owner is not None
        else None
    )
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
        waiver=waiver,
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


#: The helpers that take a destination away, as opposed to the ones that only keep a value
#: on one line. `_md_prose` escapes what would open a link, an image, an autolink or a tag;
#: `_md_code` prints the value as code, where none of those is parsed. `_md_line` and
#: `_md_cell` were in this set until the sweep was found trusting them with a job they never
#: had: they strip newlines and escape `|`, and a tag passes through both untouched.
_NEUTRALISES_DESTINATIONS = frozenset({"_md_prose", "_md_code"})


def test_no_markdown_sink_interpolates_an_unescaped_value() -> None:
    """Derived from the module, so a sink added tomorrow is caught without a list edit."""

    import ast
    import inspect

    from oss_policy_kit.application import reporting

    tree = ast.parse(inspect.getsource(reporting))
    helpers = _NEUTRALISES_DESTINATIONS

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

    source = 'lines.append(f"- **Profile**: {report.profile_title}")\nout.append(f"### {_md_line(r.title)}")'
    tree = ast.parse(source)
    helpers = _NEUTRALISES_DESTINATIONS
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

    assert found == ["report.profile_title", "_md_line(r.title)"], (
        "the detection the test above relies on does not fire, or it counts a structure-only "
        f"helper as protection again: {found}"
    )
    assert "report.profile_title" not in _NEEDS_NO_ESCAPING, "the allowlist would swallow the very sink this PR fixes"


# --------------------------------------------------------------------------------------
# Raw HTML, the shape the first version never tried, and the fields it was measured in.
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("payload", _WORKING_VECTORS)
@pytest.mark.parametrize("field", ["owner", "justification"])
def test_a_waiver_cannot_give_the_report_a_destination(payload: str, field: str) -> None:
    """A waivers file can live inside the scanned repository, and both fields print as prose."""

    report = (
        _report(waiver_owner=payload) if field == "owner" else _report(waiver_owner="o", waiver_justification=payload)
    )

    assert not _DESTINATION.search(_rendered(report)), f"a waiver {field} of {payload!r} rendered a destination"


@pytest.mark.parametrize("payload", _TALKS_THE_DETECTOR_OUT_OF_IT)
def test_the_code_span_detector_cannot_be_talked_out_of_escaping(payload: str) -> None:
    """The escape skips code spans, so each of these tries to make a tag look like one.

    The detector has to read backticks the way the renderer does. Where it reads a span that
    the renderer does not, a tag goes through unescaped, which is why every shape here is
    one where the two readings could plausibly part.
    """

    html = _rendered(_report(reason=payload))

    assert not _DESTINATION.search(html), f"{payload!r} put a tag past the escape: {html}"


def test_a_placeholder_inside_a_code_span_is_printed_as_written() -> None:
    """The other side of skipping spans: the reader sees `<sha>`, with no backslash in it."""

    html = _rendered(_report(remediation="Add `uses: step-security/harden-runner@<sha>` as the first step"))

    assert "<code>uses: step-security/harden-runner@&lt;sha&gt;</code>" in html, html
    assert "\\" not in html, "an escape was applied inside a code span, where it shows as a backslash"


def test_the_two_remediations_that_lost_their_placeholder_now_show_it() -> None:
    """Two shipped remediations wrote a placeholder outside a code span.

    To the renderer `<platform>` was a tag, which the browser drops, so the reader was told
    to record provenance in `.oss-policy-kit/evidence/-provenance-artifact.json` and to run
    `scorecard --repo=/ --format=json`. Both are code spans now, which keeps the placeholder
    and reads as the command and path they are.
    """

    from oss_policy_kit.application.evaluators import governance

    source = inspect.getsource(governance)

    assert "`scorecard --repo=<org>/<repo> --format=json`" in source
    assert "`.oss-policy-kit/evidence/<platform>-provenance-artifact.json`" in source
    for remediation, expected in (
        ("Run `scorecard --repo=<org>/<repo> --format=json` now", "--repo=&lt;org&gt;/&lt;repo&gt;"),
        ("record it in `.oss-policy-kit/evidence/<platform>-x.json`", "&lt;platform&gt;-x.json"),
    ):
        assert expected in _rendered(_report(remediation=remediation))
