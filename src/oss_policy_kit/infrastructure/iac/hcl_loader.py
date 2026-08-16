"""Adapter around ``python-hcl2`` so evaluators never see the parser directly.

Design notes:

- Parser is a soft dependency. ``hcl2_available()`` is the only call sites
  reach for; importing this module never raises if ``hcl2`` is missing.
- Returned dicts are normalized: hcl2 6.x decorates string values and keys
  with surrounding double-quotes (``'\"public-read\"'`` instead of
  ``'public-read'``); we strip them once at the boundary so downstream
  rule code stays simple.
- Failures during parse become :class:`HclLoadError`; callers translate
  that into ``manual-review-required`` evidence rather than a traceback.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from oss_policy_kit.infrastructure.source_text import decode_source

try:  # pragma: no cover - exercised via integration paths
    import hcl2 as _hcl2  # type: ignore[import-untyped]

    _HCL2_AVAILABLE = True
except Exception:  # noqa: BLE001 - we want any import error to mean "not available"
    _hcl2 = None
    _HCL2_AVAILABLE = False


class HclLoadError(RuntimeError):
    """Raised when an HCL file cannot be parsed.

    Carries the source path so the CLI can surface a per-file diagnostic
    without losing track of which file failed.
    """

    def __init__(self, path: Path, original: Exception) -> None:
        super().__init__(f"failed to parse {path}: {original}")
        self.path = path
        self.original = original


def hcl2_available() -> bool:
    """Return whether ``python-hcl2`` is importable.

    Used by ``oss-policy-kit scan-iac`` to honestly report
    ``status: not_available`` when the optional extra isn't installed,
    instead of crashing. Mirrors the Semgrep adapter contract.
    """

    return _HCL2_AVAILABLE


def _strip_quotes(value: Any) -> Any:
    """Recursively strip the wrapping double-quotes hcl2 6.x adds to strings."""

    if isinstance(value, str):
        if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
            return value[1:-1]
        return value
    if isinstance(value, list):
        return [_strip_quotes(v) for v in value]
    if isinstance(value, dict):
        return {_strip_quotes(k): _strip_quotes(v) for k, v in value.items() if k != "__is_block__"}
    return value


def load_hcl_file(path: Path) -> dict[str, Any]:
    """Parse one HCL file and return a normalized dict.

    The dict is shaped exactly like ``hcl2.load(...)`` but with quote
    decoration removed and the synthetic ``__is_block__`` markers dropped.
    """

    if not _HCL2_AVAILABLE or _hcl2 is None:
        raise HclLoadError(path, RuntimeError("python-hcl2 is not installed"))
    try:
        # Decode by BOM before handing text to hcl2. An editor that saved this as UTF-16
        # left a file a human still reads as Terraform, and reading it as UTF-8 raised
        # UnicodeDecodeError -- which every control then reported as "this repository has
        # no Terraform", a claim about the repository rather than about the read.
        raw = _hcl2.loads(decode_source(path.read_bytes()))
    except FileNotFoundError as exc:  # pragma: no cover - caller checks existence
        raise HclLoadError(path, exc) from exc
    except Exception as exc:  # noqa: BLE001 - surface any parse failure as HclLoadError
        raise HclLoadError(path, exc) from exc
    return _strip_quotes(raw)  # type: ignore[no-any-return]
