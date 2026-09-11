"""``oss-policy-kit emit-insights`` subcommand.

PR-8 (Onda 2, V6-03) — first cut of the OpenSSF Security Insights 1.0 emitter.

v0.1 surface (v6.0.0):

- Walks the target repository for clone-visible security signals (SECURITY.md,
  CONTRIBUTING.md, CODEOWNERS, Dependabot/Renovate config, repository URL via
  ``git remote -v``).
- Emits a YAML document conforming to **OpenSSF Security Insights 1.0**
  (https://security-insights.openssf.org/).
- ``--validate`` does structural validation against the required-field set
  (no external schema bundle needed).

This subcommand intentionally does **not**:

- Re-evaluate gates. It is emit-only; pair with ``evaluate`` when a gate
  decision is needed.
- Fetch external data. Works from the local clone plus optional evidence
  files.
- Add new controls to the catalog. The emitter re-projects existing
  signals into the Security Insights vocabulary.

Designed for adopters that already use the kit and want to publish a
``security-insights.yml`` consumed by Scorecard v6, CLOMonitor, OSPS
Baseline Scanner, and ASPM platforms.

See ``docs/insights-emission.md`` for adopter guidance and ADR-011 for
the design rationale.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Any

import typer
import yaml

from oss_policy_kit.application.insights_evidence import INSIGHTS_SCHEMA_VERSION as _INSIGHTS_SCHEMA_VERSION
from oss_policy_kit.cli.common import app, exit_for_unexpected, markup_safe, stderr_console, write_stdout_text
from oss_policy_kit.cli.help_text import CMD_PANEL_EXPORT
from oss_policy_kit.domain.errors import InvalidInputError, OssPolicyKitError
from oss_policy_kit.domain.models import utc_now

_GITHUB_DIR = ".github"

_DEFAULT_OUTPUT = Path("security-insights.yml")


def _now_iso8601_z() -> str:
    # Route through the SDE-honouring clock so ``last-updated`` / ``last-reviewed``
    # are pinned under ``SOURCE_DATE_EPOCH`` and the emitted security-insights.yml
    # is byte-identical across re-runs (reproducible builds).
    return utc_now().strftime("%Y-%m-%dT%H:%M:%SZ")


def _find_first(root: Path, candidates: tuple[str, ...]) -> Path | None:
    for rel in candidates:
        p = root / rel
        if p.is_file():
            return p
    return None


def _git_remote_url(root: Path) -> str | None:
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "remote", "get-url", "origin"],
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            text=True,
            check=False,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    url = out.stdout.strip()
    if not url:
        return None
    # Normalise SSH ``git@github.com:org/repo.git`` to HTTPS.
    #
    # The repetitions are bounded. Unbounded, the greedy host class and the lazy path class
    # backtrack against each other and the cost is quadratic in the length of the remote URL,
    # which comes out of the checkout's own git configuration. Measured, CPU time for one
    # match: 125 ms at 32 KB, 2.56 s at 128 KB, 42.9 s at 512 KB, x4.0 per doubling. Bounded
    # it is 4.6 ms / 17.6 ms / 78 ms, x2.0. The bounds are above the formats: a DNS name
    # cannot exceed 255 octets, and 1024 is far past any repository path.
    m = re.match(r"git@([^:\n]{1,255}):([^\n]{1,1024}?)(?:\.git)?$", url)
    if m:
        return f"https://{m.group(1)}/{m.group(2)}"
    if url.endswith(".git"):
        url = url[:-4]
    return url


_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")


def _security_md_email(security_md: Path | None) -> str | None:
    if security_md is None:
        return None
    try:
        text = security_md.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    m = _EMAIL_RE.search(text)
    return m.group(0) if m else None


def _has_dependabot_or_renovate(root: Path) -> bool:
    return (
        (root / _GITHUB_DIR / "dependabot.yml").is_file()
        or (root / _GITHUB_DIR / "dependabot.yaml").is_file()
        or (root / "renovate.json").is_file()
        or (root / _GITHUB_DIR / "renovate.json").is_file()
        or (root / ".renovaterc").is_file()
        or (root / ".renovaterc.json").is_file()
    )


def _build_insights_document(target: Path) -> dict[str, Any]:
    """Construct an OpenSSF Security Insights 1.0 document from clone-visible signals."""
    root = target.resolve()
    now = _now_iso8601_z()
    remote_url = _git_remote_url(root)

    security_md = _find_first(
        root,
        ("SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md"),
    )
    contributing_md = _find_first(root, ("CONTRIBUTING.md", ".github/CONTRIBUTING.md", "docs/CONTRIBUTING.md"))
    codeowners = _find_first(root, ("CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"))

    header: dict[str, Any] = {
        "schema-version": _INSIGHTS_SCHEMA_VERSION,
        "last-updated": now,
        "last-reviewed": now,
    }
    if remote_url is not None:
        header["url"] = remote_url
        header["project-url"] = remote_url

    doc: dict[str, Any] = {
        "header": header,
        "project-lifecycle": {
            "status": "active",
            "bug-fixes-only": False,
        },
    }

    if contributing_md is not None:
        doc["contribution-policy"] = {
            "accepts-pull-requests": True,
            "accepts-automated-pull-requests": True,
            "contributing-policy": (
                f"{remote_url}/blob/main/{contributing_md.relative_to(root).as_posix()}"
                if remote_url is not None
                else contributing_md.relative_to(root).as_posix()
            ),
        }

    if codeowners is not None:
        project_admins = doc.setdefault("project-administrators", [])
        project_admins.append({"name": "see CODEOWNERS", "affiliation": codeowners.relative_to(root).as_posix()})

    if security_md is not None:
        email = _security_md_email(security_md)
        security_policy_url = (
            f"{remote_url}/blob/main/{security_md.relative_to(root).as_posix()}"
            if remote_url is not None
            else security_md.relative_to(root).as_posix()
        )
        vr: dict[str, Any] = {
            "accepts-vulnerability-reports": True,
            "security-policy": security_policy_url,
        }
        if email is not None:
            vr["email-contact"] = email
        doc["vulnerability-reporting"] = vr
        sc: list[dict[str, Any]] = []
        if email is not None:
            sc.append({"type": "email", "value": email})
        if sc:
            doc["security-contacts"] = sc

    if _has_dependabot_or_renovate(root):
        doc["dependencies"] = {
            "env-dependencies-policy": {
                "comment": (
                    "Automated dependency-update tooling detected (Dependabot or Renovate). "
                    "See DEP-UPDATE-001 in the kit catalog for the underlying signal."
                ),
            },
        }

    return doc


_INSIGHTS_REQUIRED_TOP_LEVEL: tuple[str, ...] = ("header", "project-lifecycle")
_INSIGHTS_REQUIRED_HEADER: tuple[str, ...] = ("schema-version", "last-updated")


def _validate_insights_structure(doc: dict[str, Any]) -> list[str]:
    """Return list of structural-validation error messages (empty on success).

    Lightweight check — does NOT replace validation against the official
    OpenSSF Security Insights 1.0 JSON Schema, but catches missing required
    fields and obvious shape mistakes.
    """
    errs: list[str] = []
    for k in _INSIGHTS_REQUIRED_TOP_LEVEL:
        if k not in doc:
            errs.append(f"top-level field missing: {k}")
    header = doc.get("header")
    if not isinstance(header, dict):
        errs.append("header must be an object")
        return errs
    for k in _INSIGHTS_REQUIRED_HEADER:
        if k not in header:
            errs.append(f"header.{k} missing")
    sv = header.get("schema-version")
    if sv is not None and sv != _INSIGHTS_SCHEMA_VERSION:
        errs.append(f"header.schema-version must be {_INSIGHTS_SCHEMA_VERSION!r}; got {sv!r}")
    lifecycle = doc.get("project-lifecycle")
    if not isinstance(lifecycle, dict) or "status" not in lifecycle:
        errs.append("project-lifecycle.status missing")
    return errs


_FRAGMENT_BANNER = (
    "# Security Insights fragment generated by `oss-policy-kit emit-insights --merge`.\n"
    "# Contains ONLY fields the kit can back from the clone (no volatile timestamps,\n"
    "# no assumed project-lifecycle). Merge into your security-insights.yml; re-running\n"
    "# is idempotent. Review before committing.\n"
)


def _build_insights_fragment(target: Path) -> dict[str, Any]:
    """A merge-idempotent Security Insights fragment: only clone-backed fields.

    Derived from :func:`_build_insights_document`, with the volatile / assumed fields
    removed so the output is stable across runs and safe to merge into an existing
    ``security-insights.yml``:

    - drops ``header.last-updated`` / ``header.last-reviewed`` (regenerated every run);
    - drops ``project-lifecycle`` (a kit default assumption, not a clone-visible truth).

    Everything that remains is backed by a real clone-visible signal (a present
    SECURITY.md/CONTRIBUTING/CODEOWNERS, a git remote, or detected dependency tooling).
    """
    doc = _build_insights_document(target)
    header = doc.get("header")
    if isinstance(header, dict):
        header.pop("last-updated", None)
        header.pop("last-reviewed", None)
    doc.pop("project-lifecycle", None)
    return doc


def _run_emit_insights(target: Path, output: Path, validate: bool, merge: bool) -> None:
    target_path = target.resolve()
    if not target_path.is_dir():
        # Echo the user-supplied string, never target.resolve(): the absolute
        # path leaks the auditor's home directory / username (M-002).
        raise InvalidInputError(f"--target {target} is not a directory.")

    if merge:
        fragment = _build_insights_fragment(target_path)
        yaml_text = _FRAGMENT_BANNER + yaml.safe_dump(fragment, sort_keys=True, allow_unicode=True)
        output.write_text(yaml_text, encoding="utf-8")
        write_stdout_text(f"emit-insights: wrote merge fragment {output}\n")
        return

    doc = _build_insights_document(target_path)
    if validate:
        errs = _validate_insights_structure(doc)
        if errs:
            c = stderr_console()
            for e in errs:
                c.print(f"[red]insights validation error:[/red] {e}")
            raise typer.Exit(code=1)

    yaml_text = yaml.safe_dump(doc, sort_keys=False, allow_unicode=True)
    output.write_text(yaml_text, encoding="utf-8")
    write_stdout_text(f"emit-insights: wrote {output}\n")


@app.command("emit-insights", rich_help_panel=CMD_PANEL_EXPORT)
def emit_insights_cmd(
    target: Path = typer.Option(
        Path("."),
        "--target",
        help="Path to the repository to analyse. Defaults to current directory.",
    ),
    output: Path = typer.Option(
        _DEFAULT_OUTPUT,
        "--output",
        help="Path to write the OpenSSF Security Insights 1.0 YAML.",
    ),
    validate: bool = typer.Option(
        False,
        "--validate",
        help="Structurally validate the emitted document before writing. Exit 1 on validation failure.",
    ),
    merge: bool = typer.Option(
        False,
        "--merge",
        help=(
            "Emit a merge-idempotent FRAGMENT (only clone-backed fields, no volatile timestamps or "
            "assumed lifecycle) to merge into an existing security-insights.yml, instead of a full "
            "standalone document."
        ),
    ),
) -> None:
    """Emit an OpenSSF Security Insights 1.0 YAML document for the target repository.

    PR-8 (Onda 2, V6-03) — see docs/insights-emission.md for adopter guidance.
    With --merge, emit a partial fragment (clone-backed fields only) instead.

    Exit codes: 0 success; 1 validation failure (--validate); 2 usage error
    (bad --target or unwritable --output); 3 unexpected internal error.
    """
    try:
        _run_emit_insights(target, output, validate, merge)
    except OssPolicyKitError as exc:
        stderr_console().print(f"[red]Error:[/red] {markup_safe(exc.message)}")
        raise typer.Exit(code=2) from exc
    except typer.Exit:
        raise
    except OSError as exc:
        stderr_console().print(
            f"[red]Error:[/red] cannot write output ({markup_safe(exc.strerror or 'filesystem error')})."
        )
        raise typer.Exit(code=2) from exc
    # Last-resort user message, no traceback leak.
    except Exception as exc:  # noqa: BLE001
        exit_for_unexpected(exc)
