"""No string, through `_md_prose`, renders as a tag, a link, or an image.

`_md_prose` skips code spans on purpose, because inside one the renderer prints `<` as
written and an escape there would show the reader a backslash. That makes the correctness
of the fix depend on reading backticks exactly as the renderer does, and the example
tests can only try the shapes someone thought of. The first version of this function
passed every example it had while twelve beacons rendered from a shape nobody had tried.

So this asks the renderer. Every generated string goes through `_md_prose`, into the two
places the report puts prose, and is parsed by the same CommonMark implementation the
example tests use. The oracle is the token stream, not a regex over HTML: an
`html_inline`, `html_block`, `link_open` or `image` token is a failure whatever it would
have rendered as.

The alphabet is weighted toward the characters where the two readings could part:
backticks in runs, backslashes, `<` followed by each thing that can open markup, and
fragments of tags and attributes.

Some shapes are too specific for 400 random draws to assemble, and mutation testing found
two of them: a complete comment, and a run of one backtick followed later by a run of
two. Those are pinned with `@example`, so they run on every execution instead of when the
draw happens to line up. A comment opens no destination, which is why no destination test
saw it go missing; it is still markup the value was never meant to become.
"""

from __future__ import annotations

from hypothesis import example, given, settings
from hypothesis import strategies as st
from markdown_it import MarkdownIt

from oss_policy_kit.application.reporting import _md_prose

_MD = MarkdownIt("commonmark")

#: Token types that mean the value became markup rather than text.
_MARKUP = frozenset({"html_inline", "html_block", "link_open", "image"})

_PIECES = st.sampled_from(
    [
        "<",
        ">",
        "/",
        "!",
        "?",
        "`",
        "``",
        "```",
        "\\",
        "\\`",
        "=",
        '"',
        "'",
        " ",
        "@",
        ":",
        "[",
        "]",
        "(",
        ")",
        "|",
        "-",
        "*",
        "a",
        "img",
        "svg",
        "src",
        "href",
        "on",
        "x",
        "http://e.invalid/p",
        "<!--",
        "-->",
        "<?",
        "<![CDATA[",
        "<a ",
        "<img ",
        "</a>",
    ]
)
_TEXT = st.lists(_PIECES, max_size=30).map("".join)


def _markup_tokens(markdown: str) -> list[str]:
    found = []
    for token in _MD.parse(markdown):
        if token.type in _MARKUP:
            found.append(token.type)
        found.extend(child.type for child in token.children or [] if child.type in _MARKUP)
    return found


@settings(max_examples=400, deadline=None)
@given(_TEXT)
@example("<!-- x -->")
@example("<!DOCTYPE x>")
@example("<?x?>")
@example("<![CDATA[x]]>")
@example("</a>")
@example('`<img src="u">``')
def test_prose_never_becomes_markup(value: str) -> None:
    for markdown in (
        f"- **Reason**: {_md_prose(value)}",
        f"| a | {_md_prose(value, in_table=True)} |",
    ):
        assert not _markup_tokens(markdown), f"{value!r} rendered as markup through {markdown!r}"


@settings(max_examples=200, deadline=None)
@given(st.text(alphabet=st.characters(blacklist_characters="<[`\\\r\n", blacklist_categories=("Cc", "Cf", "Cs"))))
def test_text_with_nothing_to_escape_is_left_exactly_as_written(value: str) -> None:
    """The other side. With no character that can open markup, the escape changes nothing."""

    assert _md_prose(value) == value
