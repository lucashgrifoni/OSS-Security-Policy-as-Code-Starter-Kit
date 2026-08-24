"""A "documented" control needs a heading, not the words somewhere in the file.

Three controls decided whether a repository documents something by lowercasing SECURITY.md or
README.md and testing whether a phrase appeared anywhere in it. That let each of these earn a
conformance PASS:

* a heading somebody commented out -- ``<!-- ## AI Security Considerations -->`` is a draft, and
  it satisfied the same control as a published section;
* a heading with nothing under it, which is a placeholder;
* the bare word "limitations" in an ordinary sentence, so any README mentioning a limitation of
  anything satisfied an EU AI Act Annex IV §1 claim about intended purpose and limitations.

The fix reads Markdown structure: ATX and setext headings, HTML comments removed, fenced code
blocks skipped, and a non-empty body required.

Both directions are asserted. Two fixes earlier in this release removed a false positive by
removing a true finding with it, so every case below is paired with a real documented section
that must keep passing.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from oss_policy_kit.application.evaluators import (
    eval_llm_218a_po_001,
    eval_llm_ai_act_001,
    eval_llm_ai_act_003,
)
from oss_policy_kit.application.evaluators._shared import _markdown_sections
from oss_policy_kit.domain.models import ControlStatus

_REAL = """## AI Security Considerations
Every tool call runs in a sandbox with an explicit allowlist.

## Intended purpose
Classifying inbound support tickets for internal staff only.

## Risk management
Reviewed quarterly against the register in RISKS.md.
"""

_COMMENTED_OUT = """<!--
## AI Security Considerations
## Intended purpose
## Risk management
-->
Nothing written yet.
"""

_EMPTY_SECTIONS = """## AI Security Considerations

## Intended purpose

## Risk management
"""

_PROSE_ONLY = """# The app
Known limitations of the parser are tracked in the issue list, and risk management
is handled by the platform team. See also model security elsewhere.
"""

_INSIDE_CODE_FENCE = """# Template guide
Copy this into your own SECURITY.md:

```markdown
## AI Security Considerations
## Intended purpose
## Risk management
```
"""

_SETEXT = """Intended purpose
================
Classifying inbound support tickets.

AI Security Considerations
==========================
Tool calls are sandboxed.

Risk management
===============
Reviewed quarterly.
"""

_EVALUATORS = (
    ("LLM-218A-PO-001", eval_llm_218a_po_001),
    ("LLM-AI-ACT-001", eval_llm_ai_act_001),
    ("LLM-AI-ACT-003", eval_llm_ai_act_003),
)

#: (label, SECURITY.md body, the document really documents the sections)
_DOCUMENTS: tuple[tuple[str, str, bool], ...] = (
    ("real-sections", _REAL, True),
    ("setext-headings", _SETEXT, True),
    ("commented-out", _COMMENTED_OUT, False),
    ("empty-sections", _EMPTY_SECTIONS, False),
    ("prose-only", _PROSE_ONLY, False),
    ("inside-code-fence", _INSIDE_CODE_FENCE, False),
)


@pytest.mark.parametrize(("label", "body", "documented"), _DOCUMENTS, ids=[d[0] for d in _DOCUMENTS])
@pytest.mark.parametrize(("control_id", "evaluate"), _EVALUATORS, ids=[e[0] for e in _EVALUATORS])
def test_a_section_counts_only_when_it_is_a_section(
    tmp_path: Path, label: str, body: str, documented: bool, control_id: str, evaluate: object
) -> None:
    (tmp_path / "SECURITY.md").write_text(body, encoding="utf-8")

    outcome = evaluate(SimpleNamespace(repo_root=tmp_path))  # type: ignore[operator]

    if documented:
        assert outcome.status is ControlStatus.PASS, (
            f"{control_id}/{label}: the document really carries the section and the control no "
            f"longer credits it ({outcome.status.value}). Removing a false positive must not "
            f"remove a true finding: {outcome.reason}"
        )
    else:
        assert outcome.status is not ControlStatus.PASS, (
            f"{control_id}/{label}: this is not a documented section, and the control reported a "
            f"conformance claim from it: {outcome.reason}"
        )


def test_the_parser_separates_a_heading_from_the_words_in_a_sentence() -> None:
    """The unit under the parametrised tests, on the shapes that produced the false passes."""

    assert _markdown_sections("## Intended purpose\nbody\n") == [("intended purpose", "body")]
    assert _markdown_sections("<!--\n## Intended purpose\nbody\n-->\n") == []
    assert _markdown_sections("# App\nKnown limitations are listed.\n") == [("app", "Known limitations are listed.")]

    # A heading with an empty body is visible to the parser and rejected by the caller, which is
    # what lets one function serve "is there a heading" and "does it say anything".
    headings = dict(_markdown_sections("## Intended purpose\n\n## Other\nbody\n"))
    assert headings["intended purpose"].strip() == ""
    assert headings["other"].strip() == "body"

    # Closing hashes are decoration, not part of the heading text.
    assert _markdown_sections("### Intended purpose ###\nbody\n") == [("intended purpose", "body")]


#: The ordinary shape of a real security document: the section heading, then the material
#: organised under sub-headings. The splitter closed a section at the NEXT heading of ANY level,
#: so the parent's body was empty and `_documents_section` rejected it -- three EU AI Act and
#: LLM conformance controls lost a PASS that `HEAD` awarded, on a document that really does
#: publish the section. Nesting is not a placeholder; it is how anyone writes more than a
#: paragraph.
_NESTED = """## AI Security Considerations
### Prompt injection
Tool calls run in a sandbox with an explicit allowlist.

### Output handling
Every completion is moderated before it is returned.

## Intended purpose
### Scope
Classifying inbound support tickets for internal staff only.

## Risk management
### Cadence
Reviewed quarterly against the register in RISKS.md.
"""

#: The counterpart the nesting fix must not swallow: a heading whose subsection is ALSO empty
#: says nothing, and a placeholder must stay a placeholder however deeply it is nested.
_NESTED_BUT_EMPTY = """## AI Security Considerations
### Prompt injection

## Intended purpose
### Scope

## Risk management
### Cadence
"""

_NESTED_CONTROLS = (
    ("LLM-218A-PO-001", eval_llm_218a_po_001),
    ("LLM-AI-ACT-001", eval_llm_ai_act_001),
    ("LLM-AI-ACT-003", eval_llm_ai_act_003),
)


@pytest.mark.parametrize(("control_id", "evaluate"), _NESTED_CONTROLS, ids=[c[0] for c in _NESTED_CONTROLS])
def test_a_section_documented_in_subsections_is_still_documented(
    tmp_path: Path, control_id: str, evaluate: object
) -> None:
    (tmp_path / "SECURITY.md").write_text(_NESTED, encoding="utf-8")

    outcome = evaluate(SimpleNamespace(repo_root=tmp_path))  # type: ignore[operator]

    assert outcome.status is ControlStatus.PASS, (
        f"{control_id}: this document publishes the section and puts its material under "
        f"sub-headings, and the control stopped crediting it ({outcome.status.value}). Removing "
        f"a false positive must not remove a true finding: {outcome.reason}"
    )


@pytest.mark.parametrize(("control_id", "evaluate"), _NESTED_CONTROLS, ids=[c[0] for c in _NESTED_CONTROLS])
def test_a_nested_placeholder_is_still_a_placeholder(tmp_path: Path, control_id: str, evaluate: object) -> None:
    (tmp_path / "SECURITY.md").write_text(_NESTED_BUT_EMPTY, encoding="utf-8")

    outcome = evaluate(SimpleNamespace(repo_root=tmp_path))  # type: ignore[operator]

    assert outcome.status is not ControlStatus.PASS, (
        f"{control_id}: nothing is written under any of these headings, and the control turned "
        f"the outline into a conformance claim: {outcome.reason}"
    )


def test_a_section_body_runs_to_the_next_heading_of_the_same_or_shallower_level() -> None:
    """The unit rule. A deeper heading is part of its parent; a sibling ends it."""

    nested = dict(_markdown_sections("## Parent\n### Child\nreal content\n"))
    assert nested["parent"].strip() != "", "a subsection's content is the parent's content too"
    assert nested["child"].strip() == "real content"

    siblings = dict(_markdown_sections("## First\n\n## Second\nbody\n"))
    assert siblings["first"].strip() == "", "a sibling heading ends the section, so this one is empty"
    assert siblings["second"].strip() == "body"

    # A shallower heading ends a deeper one, which is what keeps an outline from swallowing the
    # rest of the document.
    outdent = dict(_markdown_sections("### Deep\ndeep body\n# Top\ntop body\n"))
    assert outdent["deep"].strip() == "deep body"
    assert outdent["top"].strip() == "top body"
