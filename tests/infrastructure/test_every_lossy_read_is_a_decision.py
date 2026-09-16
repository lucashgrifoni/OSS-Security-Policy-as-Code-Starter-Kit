"""A read that decodes with ``errors="replace"`` turns bad bytes into text, silently.

That is the right answer for some files and the wrong one for any file whose CONTENT decides a
control verdict: mojibake contains no `runs-on:`, no `AWS_SECRET_ACCESS_KEY`, and a control
that concludes an absence from it states something false about the repository.

This is the residue of that program, made explicit. The sweep is derived from the source, so a
new lossy read cannot join the list by being forgotten -- it fails here until someone writes
down why it is safe.

Why the sites below are accepted, measured rather than argued. Every one of them is on a path
that produces INFORMATION, not a verdict, or is on a parser whose lossy text cannot survive
the parse that follows it:

- `aws_ci_parser::load_committed_codepipeline_document` and `::_scan_codepipeline_export`
  read a committed CodePipeline export through `json.loads` or `load_yaml_file`. Both parse
  immediately after, and neither returns a value built from the lossy text: a document that
  does not parse becomes None or a recorded parse error.
- `profile_hints` reads pyproject.toml to suggest things. A lost hint is a lost sentence.
- `emit_insights` extracts a contact address; losing it leaves the field absent, which is not
  a claim about the repository.
- `git_remote` extracts the owner/repo slug; losing it means the slug is unknown, and every
  caller already handles None.

Two readers that used to be on this list are gone from it, which is the point of keeping the
list at all. `aws_ci_parser`'s buildspec read and `azure_pipeline_parser`'s pipeline read now
go through `decode_source_detail`, so a UTF-16 CI file is HONOURED rather than turned into
mojibake. Measured across aws-level-1, aws-level-3, azure-level-1 and
azure-release-hardening-3: a UTF-16 config now produces verdicts identical to the UTF-8 one,
where before `AWS-SECRET-038` lost a real FAIL to a control default. An encoding the decoder
detects but cannot honour is recorded in `parse_errors` instead of scanned.

The evaluator layer is deliberately absent from this list. A control reading repository content
goes through `decode_source` or `decode_source_detail`, which honour the encoding the file
declares and report a wide file they cannot honour instead of guessing at it.
"""

from __future__ import annotations

import ast
from collections import Counter

from tests.conftest import ROOT

_SRC = ROOT / "src"
_READERS = frozenset({"read_text", "read_bytes", "open"})

#: (path relative to src/, function name) -> how many accepted lossy reads it holds.
#: Counted, not set-compared: aws_ci_parser has three, and all three are accepted for the
#: same reason.
_ACCEPTED_LOSSY = Counter(
    {
        ("oss_policy_kit/application/profile_hints.py", "_append_pyproject_tooling_notes"): 1,
        ("oss_policy_kit/cli/emit_insights.py", "_security_md_email"): 1,
        ("oss_policy_kit/infrastructure/aws_ci_parser.py", "_scan_codepipeline_export"): 1,
        ("oss_policy_kit/infrastructure/aws_ci_parser.py", "load_committed_codepipeline_document"): 1,
        ("oss_policy_kit/infrastructure/git_remote.py", "read_github_repo_slug_from_git_config"): 1,
    }
)

#: A floor under what the sweep finds, so a change to the AST matching below cannot quietly
#: reduce this file to asserting that an empty set equals an empty set.
_MINIMUM_READS_SCANNED = 20


def _enclosing_functions(tree: ast.AST) -> dict[int, str]:
    """Line number -> the name of the INNERMOST function containing it.

    Assigned widest-span-first so the innermost definition wins whatever order the walk
    returns. Keying on walk order instead would make the owner of a line inside a nested
    function depend on traversal, and this file exists to be deterministic.
    """

    spans = [
        (node.lineno, node.end_lineno or node.lineno, node.name)
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    owner: dict[int, str] = {}
    for start, end, name in sorted(spans, key=lambda s: s[0] - s[1]):
        for line in range(start, end + 1):
            owner[line] = name
    return owner


def _is_lossy(call: ast.Call) -> bool:
    for kw in call.keywords:
        if kw.arg == "errors":
            try:
                return ast.literal_eval(kw.value) == "replace"
            except (ValueError, SyntaxError):
                return False
    return False


def _sweep() -> tuple[Counter[tuple[str, str]], int]:
    found: Counter[tuple[str, str]] = Counter()
    scanned = 0
    for path in sorted(_SRC.rglob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError:  # pragma: no cover - a file that will not parse fails elsewhere
            continue
        owner = _enclosing_functions(tree)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not (isinstance(func, ast.Attribute) and func.attr in _READERS):
                continue
            scanned += 1
            if _is_lossy(node):
                rel = path.relative_to(_SRC).as_posix()
                found[(rel, owner.get(node.lineno, "<module>"))] += 1
    return found, scanned


def test_the_sweep_has_something_to_sweep() -> None:
    """The anti-vacuum floor: a matcher that stops matching passes everything below."""

    _, scanned = _sweep()

    assert scanned >= _MINIMUM_READS_SCANNED, f"only {scanned} reads matched; the AST pass is broken"


def test_every_lossy_read_is_one_somebody_wrote_down() -> None:
    found, _ = _sweep()

    added = found - _ACCEPTED_LOSSY
    removed = _ACCEPTED_LOSSY - found

    assert not added, (
        "a read here decodes with errors='replace', which turns bad bytes into text that "
        "contains none of what a control looks for:\n  "
        + "\n  ".join(f"{path}::{func}" for (path, func), _ in sorted(added.items()))
        + "\n\nUse decode_source or decode_source_detail if the content decides a verdict, or "
        "add it to _ACCEPTED_LOSSY with the reason it cannot."
    )
    assert not removed, (
        "these accepted lossy reads are gone, which is good: drop them from _ACCEPTED_LOSSY "
        "so the list keeps describing the tree.\n  "
        + "\n  ".join(f"{path}::{func}" for (path, func), _ in sorted(removed.items()))
    )


def test_no_evaluator_reads_lossily() -> None:
    """The rule the accepted list must never be used to weaken.

    A control reading repository content goes through the decode helpers. If one of these ever
    appears under the evaluator package, the accepted list is being used to register exactly
    the thing the programme exists to remove.
    """

    found, _ = _sweep()
    offenders = [
        f"{path}::{func}" for (path, func) in found if path.startswith("oss_policy_kit/application/evaluators")
    ]

    assert not offenders, "an evaluator decodes lossily:\n  " + "\n  ".join(offenders)
