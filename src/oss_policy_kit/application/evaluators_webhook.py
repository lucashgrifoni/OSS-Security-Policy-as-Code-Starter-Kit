"""Evaluators for the v5.7 ``SEC-WEBHOOK-*`` controls.

Clone-visible **signal**-level checks for two common webhook-receiver
weaknesses: (1) missing signature validation; (2) missing replay defense.

The kit reads only source text — it cannot prove a webhook is *correctly*
secured, only that recognized signature / replay primitives are present
alongside webhook route declarations. Both controls ship as
``lifecycle: experimental`` and ``assurance: signal`` to match.

Rules:

- **SEC-WEBHOOK-001** — Webhook signature validation present. The kit
  looks for *both* (a) a route or handler that mentions ``webhook`` (path
  or function name) AND (b) any known signature-verification primitive
  (HMAC SHA-256 of payload, ``X-Hub-Signature-256``, ``Stripe-Signature``,
  ``X-Signature-Ed25519``, ``X-Signature``, ``compute_signature``,
  ``hmac.compare_digest``, …). If a webhook route is present but no
  signature primitive surfaces, the control returns
  ``manual-review-required`` with explicit remediation. If no webhook
  route is detected, the control returns ``not-applicable``.

- **SEC-WEBHOOK-002** — Webhook replay defense. The kit looks for *both*
  (a) a webhook route AND (b) a recognized replay primitive: timestamp
  tolerance check (``X-Webhook-Timestamp``, ``Stripe-Signature t=``),
  nonce / event-id seen-store usage (``SETNX``, ``setex``, ``ttl``,
  ``redis.set``, dedupe table), or replay-window comparison.

Both controls run in a single best-effort scan that walks up to 400
source files of recognized server-side languages (``.py``, ``.js``,
``.ts``, ``.go``, ``.rb``, ``.java``, ``.cs``, ``.php``, ``.rs``) and
reads up to 16 KiB per file.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

from oss_policy_kit.domain.models import ControlStatus, EvalOutcome

_SCAN_FILE_LIMIT = 400
_SCAN_BYTES_PER_FILE = 16 * 1024
_SCAN_EXTS: frozenset[str] = frozenset(
    {".py", ".js", ".ts", ".mjs", ".cjs", ".tsx", ".go", ".rb", ".java", ".cs", ".php", ".rs"}
)
_SKIP_DIRS: frozenset[str] = frozenset(
    {".git", ".venv", "venv", "node_modules", "dist", "build", "__pycache__", ".oss-policy-kit", ".terraform"}
)

# Route / handler signal: case-insensitive substring or regex match.
_WEBHOOK_ROUTE_HINTS: tuple[str, ...] = (
    "/webhook",
    "/webhooks",
    "webhook_handler",
    "webhookhandler",
    "handle_webhook",
    "handlewebhook",
    "webhook_endpoint",
    '@app.post("/webhook',
    "@app.post('/webhook",
    '@router.post("/webhook',
    "@router.post('/webhook",
    'app.post("/webhook',
    "app.post('/webhook",
    'router.post("/webhook',
    "router.post('/webhook",
    "@functions.http",  # GCP / Azure functions sometimes routed as webhooks
)

# Signature validation primitive hints.
_SIGNATURE_HINTS: tuple[str, ...] = (
    "x-hub-signature-256",
    "x-hub-signature",
    "stripe-signature",
    "x-signature-ed25519",
    "x-signature-timestamp",
    "x-twilio-signature",
    "x-slack-signature",
    "x-shopify-hmac",
    "x-line-signature",
    "x-paystack-signature",
    "x-svix-signature",
    "x-bunny-signature",
    "x-signature",
    "compute_signature",
    "verify_signature",
    "verifysignature",
    "validate_signature",
    "hmac.compare_digest",
    "compare_digest",
    "constant_time_compare",
    "constanttimecompare",
    "createhmac",
    "createhmac(",
    "crypto.createhmac",
    "hmac.new",
    "hmac_sha256",
    "hmacsha256",
)

# Replay-defense primitive hints.
_REPLAY_HINTS: tuple[str, ...] = (
    "x-webhook-timestamp",
    "stripe-signature",  # Stripe encodes 't=<unix>' in the same header
    "t=",  # for Stripe-style t=<unix> parsing
    "webhook_timestamp",
    "replay_window",
    "replaywindow",
    "tolerance",
    "max_age",
    "max-age",
    "setnx",
    "set_nx",
    "redis.set",
    "redis.setex",
    "client.setex",
    "deliveryid",
    "delivery_id",
    "x-github-delivery",
    "event_id",
    "eventid",
    "idempotency",
    "idempotency_key",
    "idempotency-key",
    "nonce",
)


def _iter_candidate_paths(repo_root: Path) -> Iterable[Path]:
    """Yield up to ``_SCAN_FILE_LIMIT`` source files in the clone (skipping noisy dirs)."""

    seen = 0
    try:
        for path in repo_root.rglob("*"):
            try:
                rel = path.relative_to(repo_root)
            except ValueError:
                continue
            parts = rel.parts
            if any(p in _SKIP_DIRS for p in parts):
                continue
            if not path.is_file():
                continue
            if path.suffix.lower() not in _SCAN_EXTS:
                continue
            yield path
            seen += 1
            if seen >= _SCAN_FILE_LIMIT:
                return
    except OSError:
        return


def _scan_signals(repo_root: Path) -> tuple[bool, str | None, bool, str | None, bool, str | None]:
    """Return ``(has_route, route_hint, has_signature, sig_hint, has_replay, replay_hint)``.

    Returned hints are repo-relative POSIX paths of one matching file (the
    first one found). Empty hints when the corresponding signal is absent.
    """

    has_route = False
    has_signature = False
    has_replay = False
    route_hint: str | None = None
    sig_hint: str | None = None
    replay_hint: str | None = None
    for path in _iter_candidate_paths(repo_root):
        try:
            head = path.read_bytes()[:_SCAN_BYTES_PER_FILE].decode("utf-8", errors="ignore").lower()
        except OSError:
            continue
        rel = path.relative_to(repo_root).as_posix()
        if not has_route and any(hint in head for hint in _WEBHOOK_ROUTE_HINTS):
            has_route = True
            route_hint = rel
        if not has_signature and any(hint in head for hint in _SIGNATURE_HINTS):
            has_signature = True
            sig_hint = rel
        if not has_replay and any(hint in head for hint in _REPLAY_HINTS):
            has_replay = True
            replay_hint = rel
        if has_route and has_signature and has_replay:
            break
    return has_route, route_hint, has_signature, sig_hint, has_replay, replay_hint


def eval_sec_webhook_001(ctx: Any) -> EvalOutcome:
    """SEC-WEBHOOK-001: webhook signature validation present (clone-side signal)."""

    repo_root: Path = ctx.repo_root
    has_route, route_hint, has_signature, sig_hint, _has_replay, _replay_hint = _scan_signals(repo_root)
    if not has_route:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No webhook route or handler detected in repository; control is not applicable.",
            remediation="No action required. Add a webhook receiver to enable signature validation evaluation.",
            evidence_sources=[],
            confidence="high",
        )
    if has_signature:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=(
                f"Detected webhook route (e.g. {route_hint!r}) alongside a signature validation primitive "
                f"(e.g. {sig_hint!r})."
            ),
            remediation=(
                "Keep the signature secret stored as a runtime secret (not in source), and verify with "
                "constant-time comparison."
            ),
            evidence_sources=[],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason=(
            f"Webhook route detected ({route_hint!r}) but no signature validation primitive surfaced from a clone."
        ),
        remediation=(
            "Verify the incoming webhook signature on every request (e.g. validate X-Hub-Signature-256 / "
            "Stripe-Signature / X-Signature-Ed25519 using hmac.compare_digest or equivalent constant-time "
            "comparison). Document the verification helper alongside the route."
        ),
        evidence_sources=[],
        confidence="medium",
    )


def eval_sec_webhook_002(ctx: Any) -> EvalOutcome:
    """SEC-WEBHOOK-002: webhook replay defense present (clone-side signal)."""

    repo_root: Path = ctx.repo_root
    has_route, route_hint, _has_signature, _sig_hint, has_replay, replay_hint = _scan_signals(repo_root)
    if not has_route:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No webhook route or handler detected in repository; control is not applicable.",
            remediation="No action required. Add a webhook receiver to enable replay defense evaluation.",
            evidence_sources=[],
            confidence="high",
        )
    if has_replay:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=(
                f"Detected webhook route (e.g. {route_hint!r}) alongside a replay-defense primitive "
                f"(e.g. {replay_hint!r})."
            ),
            remediation=(
                "Ensure the timestamp tolerance is short (e.g. 5 minutes) and the dedupe store survives restarts "
                "(persistent storage or distributed cache with TTL)."
            ),
            evidence_sources=[],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason=(
            f"Webhook route detected ({route_hint!r}) but no replay-defense primitive (timestamp tolerance, "
            "nonce / event-id dedupe, idempotency key) surfaced from a clone."
        ),
        remediation=(
            "Add replay protection: validate a request timestamp within a tolerance window and reject duplicate "
            "event IDs (X-GitHub-Delivery, Stripe event.id, X-Idempotency-Key) using a TTL-bounded store."
        ),
        evidence_sources=[],
        confidence="medium",
    )


def build_webhook_evaluators() -> dict[str, Callable[[Any], EvalOutcome]]:
    return {
        "SEC-WEBHOOK-001": eval_sec_webhook_001,
        "SEC-WEBHOOK-002": eval_sec_webhook_002,
    }
