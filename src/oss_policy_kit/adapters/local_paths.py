"""Safe path resolution for repository targets."""

from pathlib import Path

from oss_policy_kit.application.input_limits import bad_input_detail
from oss_policy_kit.domain.errors import InvalidInputError


def resolve_existing_dir(path_str: str) -> Path:
    """Resolve user-supplied path to an absolute directory."""

    candidate = Path(path_str).expanduser()
    try:
        resolved = candidate.resolve()
    except OSError as exc:
        raise InvalidInputError(f"Invalid path: {path_str} ({bad_input_detail(exc)})") from exc
    if not resolved.is_dir():
        # M-002: echo the string the user typed, never ``resolved`` — ``Path.resolve()``
        # makes a relative target absolute and would leak cwd/home/OS username.
        raise InvalidInputError(f"Not a directory or does not exist: {path_str}")
    return resolved
