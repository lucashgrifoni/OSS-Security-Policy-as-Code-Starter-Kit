"""Defensive reading of user-controlled SARIF / evidence / scorecard / waiver / config input.

Two related jobs live here. The size caps below are the local CI denial-of-service
hardening described next. On top of them, :data:`BAD_INPUT_ERRORS`,
:func:`bad_input_detail` and :func:`load_capped_document` are the single shared
answer to "what can an ordinary bad file throw, and how do we say so" — so a hostile
document (nested past the parser stack, an integer literal past CPython's
4300-digit conversion limit, permission denied, wrong encoding) is a usage error
with exit 2, never the exit 3 the contract reserves for a defect in the kit.

Local CI denial-of-service hardening (backlog: v6 input size limits). Several
loaders read an entire user-controlled file before parsing; an oversized file in
an adopter repository can inflate memory use or slow CI. Impact is local to the
evaluator/CLI process (not RCE), so the response is a clear refusal:

- Evaluator paths return ``(None, reason, ...)`` so the control degrades to
  ``manual-review-required`` / ``not-evaluated`` instead of crashing.
- CLI paths raise :class:`InvalidInputError` (exit 2) via ``read_text_capped``.

Defaults are deliberately generous (real SARIF can be large; evidence files are
small attestations). There is no override flag yet — add one only when a concrete
adopter use case appears (per the backlog acceptance criteria).
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import yaml

from oss_policy_kit.domain.errors import InvalidInputError

#: Evidence/scorecard/waiver JSON or YAML — small attestations.
MAX_EVIDENCE_BYTES = 5 * 1024 * 1024  # 5 MiB
#: SARIF documents (scanner output) — can be larger than evidence files.
MAX_SARIF_BYTES = 20 * 1024 * 1024  # 20 MiB
#: ``oss-policy-kit.yaml`` — a handful of scalar fields; nothing legitimate is large.
MAX_CONFIG_BYTES = 1 * 1024 * 1024  # 1 MiB

#: Bracket-nesting depth allowed in any user-controlled document. Real evidence, config
#: and scanner output sit under ten levels; 200 is generous enough that no honest file
#: is refused.
#:
#: Catching ``RecursionError`` is not sufficient on its own, and the difference is not
#: theoretical: CPython 3.12 separates the Python recursion limit from the C stack guard,
#: so the C JSON scanner blows its stack around 3000 levels on Windows' 1 MB stack and
#: parses the same document happily on Linux' 8 MB one. A guard that only fires on one
#: platform is not a guard -- an adopter on Linux got no refusal at all. PyYAML's composer
#: is pure Python and does hit the limit identically everywhere, which is why only the
#: JSON path diverged. This check makes the answer the same on every platform, and the
#: ``RecursionError`` handling stays as the backstop for block-style YAML, whose depth is
#: expressed by indentation rather than brackets.
MAX_JSON_DEPTH = 200

#: Nodes a user-controlled document may expand to once YAML aliases are resolved.
#:
#: The two limits above measure the document as WRITTEN -- bytes on disk, and bracket nesting.
#: A YAML alias bomb is invisible to both by construction: it is a few hundred bytes and its
#: bracket depth is one. What makes it expensive is that PyYAML resolves an alias to the *same
#: object*, so a document that reads as a tree is really a DAG, and any walker without a notion
#: of node identity re-descends every shared node once per path that reaches it.
#:
#: Measured on this tree at fan-out 8, a 315-byte file expanded to 2.1M nodes and cost the
#: GitLab parser 1.0s; 357 bytes cost 11.1s; 399 bytes did not finish inside a 20s cap. The
#: parse stayed flat at ~0.02s throughout, which is what places the cost in the traversal
#: rather than in PyYAML.
#:
#: One million is deliberately far above anything honest. The largest YAML this project ships
#: is the 226-control catalogue at ~57 KB, which expands to about 3.7k nodes -- roughly 270
#: times under this limit -- and the median YAML file in the repository is 31 nodes.
MAX_EXPANDED_NODES = 1_000_000


def expanded_node_count(node: Any, *, cap: int = MAX_EXPANDED_NODES) -> int:
    """Nodes reachable from *node* with aliases expanded, saturating just past *cap*.

    Sizes are memoised per object, so the count itself costs one visit per *distinct* node and
    stays proportional to the file rather than to what it expands to -- counting a bomb is
    cheap even though walking it is not. Memoising the size is not the same as skipping a
    repeat: a shared child is charged to every parent that references it, which is the whole
    point. Were it charged once, an alias would be free and this would measure nothing.

    A YAML document can legitimately be cyclic (``x: &a [*a]`` loads without complaint), so a
    node already on the current path is charged as a leaf. That keeps a cycle finite here and
    leaves it to be refused by the cap, rather than turning into a stack overflow inside a
    guard whose job is to prevent exactly that class of failure.
    """

    memo: dict[int, int] = {}
    on_path: set[int] = set()

    def size(value: Any) -> int:
        if not isinstance(value, (dict, list)):
            return 1
        key = id(value)
        if key in memo:
            return memo[key]
        if key in on_path:
            return 1
        on_path.add(key)
        if isinstance(value, dict):
            total = 1 + len(value) + sum(size(v) for v in value.values())
        else:
            total = 1 + sum(size(v) for v in value)
        on_path.discard(key)
        memo[key] = min(total, cap + 1)
        return memo[key]

    return size(node)


def overexpanded_reason(node: Any, *, label: str, cap: int = MAX_EXPANDED_NODES) -> str | None:
    """Return a refusal message when *node* expands past *cap*, else ``None``."""

    if expanded_node_count(node, cap=cap) <= cap:
        return None
    return (
        f"{label} expands to more than {cap} nodes once its YAML aliases are resolved; "
        "refusing to walk it to avoid local CI time/memory exhaustion. "
        "Reduce the anchor/alias nesting in the file."
    )


def _advance_json_string(ch: str, escaped: bool) -> tuple[bool, bool]:
    """Step the in-string scanner; return ``(still_in_string, escaped_next)``."""

    if escaped:
        return True, False
    if ch == "\\":
        return True, True
    if ch == '"':
        return False, False
    return True, False


def max_json_nesting_depth(raw: str) -> int:
    """Max bracket-nesting depth of *raw*, ignoring brackets inside string literals."""

    depth = 0
    max_depth = 0
    in_string = False
    escaped = False
    for ch in raw:
        if in_string:
            in_string, escaped = _advance_json_string(ch, escaped)
            continue
        if ch == '"':
            in_string = True
        elif ch in "{[":
            depth += 1
            max_depth = max(max_depth, depth)
        elif ch in "}]":
            depth -= 1
    return max_depth


def too_deep_reason(raw: str, *, label: str, max_depth: int = MAX_JSON_DEPTH) -> str | None:
    """Return a refusal message when *raw* nests past *max_depth*, else ``None``."""

    if max_json_nesting_depth(raw) <= max_depth:
        return None
    # Deliberately the same "nested too deeply" wording ``bad_input_detail`` produces for
    # RecursionError: which layer catches the document is an implementation detail, and an
    # adopter should read one explanation for one problem.
    return f"{label} is nested too deeply to parse safely (more than {max_depth} levels)."


def _file_size(path: Path) -> int | None:
    """Return file size in bytes, or None when it cannot be stat-ed."""
    try:
        return path.stat().st_size
    except OSError:
        return None


def oversize_reason(path: Path, max_bytes: int, *, label: str) -> str | None:
    """Return a human-readable refusal message if *path* exceeds *max_bytes*, else None.

    No file content is read. Use this at evaluator boundaries that must not raise.
    """
    size = _file_size(path)
    if size is None or size <= max_bytes:
        return None
    return (
        f"{label} file '{path.name}' is {size} bytes, exceeding the "
        f"{max_bytes}-byte limit; refusing to read it to avoid local CI "
        "memory/time exhaustion. Reduce the file or split the input."
    )


def read_text_capped(
    path: Path,
    max_bytes: int,
    *,
    label: str,
    encoding: str = "utf-8-sig",
    errors: str = "strict",
) -> str:
    """Read *path* as text, but refuse files larger than *max_bytes*.

    Raises :class:`InvalidInputError` (CLI exit 2) when the file is oversized.
    """
    reason = oversize_reason(path, max_bytes, label=label)
    if reason is not None:
        raise InvalidInputError(reason)
    return path.read_text(encoding=encoding, errors=errors)


#: Every failure an ordinary bad input file can raise while being read and parsed.
#: ``OSError`` is missing / permission-denied / is-a-directory; ``ValueError`` covers
#: ``json.JSONDecodeError``, ``UnicodeDecodeError``, and CPython's 4300-digit integer
#: string-conversion limit; ``yaml.YAMLError`` is malformed YAML; ``RecursionError``
#: is a document nested deeper than the parser's stack — it derives from
#: ``RuntimeError``, so none of the others catch it, which is exactly how it kept
#: escaping as an exit-3 "unexpected internal error". None of these is a defect in
#: the kit, so none of them may reach the CLI's last-resort handler.
BAD_INPUT_ERRORS: tuple[type[Exception], ...] = (OSError, ValueError, yaml.YAMLError, RecursionError)

#: Substring of CPython's ``int(str)`` limit message (``ValueError``), used only to
#: replace the interpreter-internal "use sys.set_int_max_str_digits()" advice with
#: something an adopter can act on.
_INT_LIMIT_MARKER = "integer string conversion"


def bad_input_detail(exc: BaseException) -> str:
    """Return the "why" clause for a read/parse failure, in words an adopter can act on.

    Never embeds a path: ``str(OSError)`` and the ``OSError`` repr both carry the
    absolute filename, which would leak the cwd / home directory / OS username
    (M-002). The integer-limit case also drops CPython's
    ``use sys.set_int_max_str_digits()`` advice, which is about the interpreter, not
    about the file the user has to fix.
    """

    if isinstance(exc, RecursionError):
        return "it is nested too deeply to parse safely"
    if isinstance(exc, UnicodeDecodeError):
        return f"it is not valid UTF-8 text ({exc.reason})"
    if isinstance(exc, OSError):
        return f"it could not be read ({exc.strerror or 'unreadable'})"
    if isinstance(exc, yaml.YAMLError):
        return f"it is invalid YAML ({exc})"
    if _INT_LIMIT_MARKER in str(exc):
        return "it contains a number longer than the 4300 digits Python will convert"
    return f"it could not be parsed ({exc})"


def is_bad_input(exc: BaseException) -> bool:
    """True when *exc* describes input we could not read, not a defect in the kit.

    This is the classifier the CLI's last-resort handlers use, and it exists because
    guarding read sites one at a time does not converge. An AST sweep of ``src/`` found
    **128** parses of repository-controlled input, 76 of them inside no ``try`` at all,
    across evaluators, scanners and parsers. Three separate releases "fixed" this class
    by walking a list of sites, and each time a site was missed -- most recently the
    evaluators' own evidence reader, which turned a 1 KB file inside a scanned repository
    into an exit 3.

    So the guarantee moves to the boundary, where it holds no matter how many sites
    exist. Per-site handling still matters -- it is what lets ONE unreadable file degrade
    ONE control instead of ending the run -- but it is no longer what stands between an
    adopter and a crash.

    Deliberately narrower than :data:`BAD_INPUT_ERRORS`. Every type below is a statement
    about the input:

    - ``OSError`` -- a filesystem condition (missing, a directory, permission denied,
      no space). Never a logic error.
    - ``RecursionError`` -- a document nested past the parser's stack.
    - ``UnicodeDecodeError`` -- bytes that are not the declared encoding.
    - ``yaml.YAMLError`` -- malformed YAML.
    - CPython's 4300-digit integer-conversion ``ValueError``, identified by its message.

    A bare ``ValueError`` is NOT included. ``BAD_INPUT_ERRORS`` catches it at reader
    boundaries where the surrounding code proves the value came from a file, but here
    there is no such proof, and swallowing it would relabel a genuine defect as the
    adopter's fault -- the opposite of what exit 3 is for.
    """

    if isinstance(exc, OSError | RecursionError | UnicodeDecodeError | yaml.YAMLError):
        return True
    return isinstance(exc, ValueError) and _INT_LIMIT_MARKER in str(exc)


def bad_input_reason(exc: BaseException, *, label: str, name: str) -> str:
    """Return a full user-safe explanation of why reading *name* failed.

    *name* must be a bare file name, for the same M-002 reason as
    :func:`bad_input_detail`.
    """

    return f"{label} '{name}' was rejected: {bad_input_detail(exc)}."


def load_capped_document(
    path: Path,
    max_bytes: int,
    *,
    label: str,
    parser: Callable[[str], Any] = yaml.safe_load,
    encoding: str = "utf-8-sig",
) -> Any:
    """Size-cap, read, and parse *path*, mapping every bad-input failure to exit 2.

    The one defensive read for user-controlled documents: oversize, unreadable,
    permission-denied, wrongly-encoded, unparseable, too-deeply-nested, and
    over-long-integer inputs all raise :class:`InvalidInputError`. A loader that
    routes its reads through here cannot emit exit 3 for ordinary bad input.
    """

    reason = oversize_reason(path, max_bytes, label=label)
    if reason is not None:
        raise InvalidInputError(reason)
    try:
        text = path.read_text(encoding=encoding)
    except BAD_INPUT_ERRORS as exc:
        raise InvalidInputError(bad_input_reason(exc, label=label, name=path.name)) from exc
    too_deep = too_deep_reason(text, label=f"{label} '{path.name}'")
    if too_deep is not None:
        raise InvalidInputError(too_deep)
    try:
        document = parser(text)
    except BAD_INPUT_ERRORS as exc:
        raise InvalidInputError(bad_input_reason(exc, label=label, name=path.name)) from exc
    # Checked after parsing, not before: expansion is a property of the object graph, and the
    # size and depth guards above both measure the text, where an alias bomb is invisible.
    overexpanded = overexpanded_reason(document, label=f"{label} '{path.name}'")
    if overexpanded is not None:
        raise InvalidInputError(overexpanded)
    return document
