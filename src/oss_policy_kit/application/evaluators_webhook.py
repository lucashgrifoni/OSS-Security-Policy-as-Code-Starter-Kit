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

_HMAC_COMPARE_DIGEST = "hmac.compare_digest"

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
    _HMAC_COMPARE_DIGEST,
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


# ---------------------------------------------------------------------------
# v6.0.0 — SEC-WEBHOOK-HMAC-001..ROTATE-006 family (PR-5).
#
# Six new signal-grade controls bundled into webhook-security-2. Each control
# scans the repo for a focused hint set. Routing is shared: every control
# returns NOT_APPLICABLE when no webhook route is detected; PASS when the
# control's primitive is found; MANUAL_REVIEW_REQUIRED when the route exists
# but the primitive does not.
#
# See ADR-004 for the design rationale.
# ---------------------------------------------------------------------------

_HMAC_PRIMITIVE_HINTS: tuple[str, ...] = (
    "hmac.new",
    "createhmac",
    "crypto.createhmac",
    _HMAC_COMPARE_DIGEST,
    "hmac_sha256",
    "hmacsha256",
    "compute_signature",
    "verify_signature",
    "verifysignature",
    "validate_signature",
)

_TIMING_SAFE_HINTS: tuple[str, ...] = (
    _HMAC_COMPARE_DIGEST,
    "compare_digest",
    "constant_time_compare",
    "constanttimecompare",
    "crypto.timingsafeequal",
    "timingsafeequal",
    "subtle.timingsafeequal",
    "secrets.compare_digest",
)

_REPLAY_PRIMITIVE_HINTS: tuple[str, ...] = (
    "x-webhook-timestamp",
    "webhook_timestamp",
    "replay_window",
    "tolerance",
    "max_age",
    "x-github-delivery",
    "event_id",
    "nonce",
)

_BODY_CAP_HINTS: tuple[str, ...] = (
    "content-length",
    "content_length",
    "max_body_size",
    "max-body-size",
    "request_max_size",
    "client_max_body_size",
    "body_limit",
    "limits.max_body",
    "bodylimit",
    "bodyparser.json({ limit",
    "express.json({ limit",
    "request.body.size",
)

_IDEMP_HINTS: tuple[str, ...] = (
    "idempotency",
    "idempotency_key",
    "idempotency-key",
    "x-idempotency-key",
    "deliveryid",
    "delivery_id",
    "x-github-delivery",
    "setnx",
    "set_nx",
    "redis.set",
    "redis.setex",
    "client.setex",
)

_ROTATE_ENV_HINTS: tuple[str, ...] = (
    "os.environ",
    "process.env.",
    "getenv(",
    "config.get(",
    "secrets.get(",
    "vault.read",
    "vault.kv",
    "azure.identity",
    "secretsmanager",
    "aws_secretsmanager",
)

_ROTATE_MULTI_SECRET_HINTS: tuple[str, ...] = (
    "old_secret",
    "previous_secret",
    "secret_rotation",
    "secrets_rotation",
    "rotation_window",
    "rotation_period",
    "rotated_secret",
    "_secret_v1",
    "_secret_v2",
    "current_secret",
)


def _scan_for_any(repo_root: Path, hints: tuple[str, ...]) -> str | None:
    """Return the first repo-relative POSIX path containing any of ``hints``, or None."""
    for path in _iter_candidate_paths(repo_root):
        try:
            head = path.read_bytes()[:_SCAN_BYTES_PER_FILE].decode("utf-8", errors="ignore").lower()
        except OSError:
            continue
        if any(h in head for h in hints):
            return path.relative_to(repo_root).as_posix()
    return None


def _webhook_route_check(ctx: Any) -> tuple[Path, str | None]:
    """Return (repo_root, route_hint_or_None)."""
    repo_root: Path = ctx.repo_root
    return repo_root, _scan_for_any(repo_root, _WEBHOOK_ROUTE_HINTS)


def _focused_check(
    ctx: Any,
    *,
    control_id: str,
    title: str,
    primitive_hints: tuple[str, ...],
    pass_remediation: str,
    review_remediation: str,
) -> EvalOutcome:
    """Shared scaffold for the v6 SEC-WEBHOOK-* family."""
    repo_root, route_hint = _webhook_route_check(ctx)
    if route_hint is None:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason=f"No webhook route or handler detected; {control_id} is not applicable.",
            remediation="No action required. This control activates when a webhook receiver is present.",
            evidence_sources=[],
            confidence="high",
        )
    primitive_hint = _scan_for_any(repo_root, primitive_hints)
    if primitive_hint is not None:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=(
                f"Detected webhook route (e.g. {route_hint!r}) alongside the {title} primitive "
                f"(e.g. {primitive_hint!r})."
            ),
            remediation=pass_remediation,
            evidence_sources=[],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason=(f"Webhook route detected ({route_hint!r}) but the {title} primitive did not surface from a clone."),
        remediation=review_remediation,
        evidence_sources=[],
        confidence="medium",
    )


def eval_sec_webhook_hmac_001(ctx: Any) -> EvalOutcome:
    """SEC-WEBHOOK-HMAC-001: HMAC verification helper detected alongside webhook route."""
    return _focused_check(
        ctx,
        control_id="SEC-WEBHOOK-HMAC-001",
        title="HMAC verification",
        primitive_hints=_HMAC_PRIMITIVE_HINTS,
        pass_remediation="Keep the HMAC verification step ahead of any business logic in the handler.",
        review_remediation=(
            "Call an HMAC helper (e.g. hmac.new + hmac.compare_digest in Python, "
            "crypto.createHmac in Node) before processing the webhook payload."
        ),
    )


def eval_sec_webhook_timing_002(ctx: Any) -> EvalOutcome:
    """SEC-WEBHOOK-TIMING-002: timing-safe comparison helper detected."""
    return _focused_check(
        ctx,
        control_id="SEC-WEBHOOK-TIMING-002",
        title="timing-safe comparison",
        primitive_hints=_TIMING_SAFE_HINTS,
        pass_remediation=(
            "Confirm the timing-safe comparison is used on the HMAC verification path, "
            "not only on session-token paths elsewhere in the codebase."
        ),
        review_remediation=(
            "Replace == on the signature comparison with hmac.compare_digest (Python), "
            "crypto.timingSafeEqual (Node), or the equivalent constant-time primitive for "
            "the runtime."
        ),
    )


def eval_sec_webhook_replay_003(ctx: Any) -> EvalOutcome:
    """SEC-WEBHOOK-REPLAY-003: timestamp or nonce-based replay defense detected."""
    return _focused_check(
        ctx,
        control_id="SEC-WEBHOOK-REPLAY-003",
        title="replay defense",
        primitive_hints=_REPLAY_PRIMITIVE_HINTS,
        pass_remediation=(
            "Keep the replay tolerance short (recommended <= 5 minutes) and document it in the webhook receiver README."
        ),
        review_remediation=(
            "Reject events with timestamps outside a short tolerance window (Stripe-style "
            "t=<unix> or X-Webhook-Timestamp), or maintain a TTL-bounded seen-event store "
            "keyed by event id."
        ),
    )


def eval_sec_webhook_body_004(ctx: Any) -> EvalOutcome:
    """SEC-WEBHOOK-BODY-004: explicit body-size cap detected at framework or proxy level."""
    return _focused_check(
        ctx,
        control_id="SEC-WEBHOOK-BODY-004",
        title="body-size cap",
        primitive_hints=_BODY_CAP_HINTS,
        pass_remediation=(
            "Confirm the body cap is at a layer the attacker cannot bypass (proxy-side or "
            "framework-side, not application-side after the buffer fills)."
        ),
        review_remediation=(
            "Cap the webhook body size at the framework or reverse-proxy layer (e.g. "
            "express.json({ limit: '1mb' }), starlette / fastapi max_request_size, "
            "Nginx client_max_body_size). Default to 1-2 MB unless the payload type "
            "demands more."
        ),
    )


def eval_sec_webhook_idemp_005(ctx: Any) -> EvalOutcome:
    """SEC-WEBHOOK-IDEMP-005: idempotency key extraction or seen-event store detected."""
    return _focused_check(
        ctx,
        control_id="SEC-WEBHOOK-IDEMP-005",
        title="idempotency / dedupe",
        primitive_hints=_IDEMP_HINTS,
        pass_remediation=(
            "Persist the idempotency / event-id store across restarts (DB, Redis with TTL, "
            "or DynamoDB). In-memory dedupe loses entries on cold start."
        ),
        review_remediation=(
            "Extract a per-event identifier (X-GitHub-Delivery, Stripe event.id, "
            "X-Idempotency-Key) and check / insert into a TTL-bounded dedupe store before "
            "executing any side effect."
        ),
    )


def eval_sec_webhook_rotate_006(ctx: Any) -> EvalOutcome:
    """SEC-WEBHOOK-ROTATE-006: secret sourced from env/vault + multi-secret rotation signal."""
    repo_root, route_hint = _webhook_route_check(ctx)
    if route_hint is None:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No webhook route or handler detected; SEC-WEBHOOK-ROTATE-006 is not applicable.",
            remediation="No action required. This control activates when a webhook receiver is present.",
            evidence_sources=[],
            confidence="high",
        )
    env_hint = _scan_for_any(repo_root, _ROTATE_ENV_HINTS)
    rotation_hint = _scan_for_any(repo_root, _ROTATE_MULTI_SECRET_HINTS)
    if env_hint is not None and rotation_hint is not None:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=(
                f"Webhook route ({route_hint!r}): secret sourced from environment / vault "
                f"({env_hint!r}) and a multi-secret rotation pattern ({rotation_hint!r}) was detected."
            ),
            remediation="Document the rotation window and the cut-over procedure in the receiver README.",
            evidence_sources=[],
            confidence="low",
        )
    if env_hint is not None:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=(
                f"Webhook route ({route_hint!r}): secret appears env-sourced ({env_hint!r}) but no "
                "multi-secret rotation signal (old_secret / previous_secret / rotated_secret) was found."
            ),
            remediation=(
                "Accept both the current and previous secret during a documented rotation window so "
                "in-flight deliveries do not break. Remove the previous secret after the window."
            ),
            evidence_sources=[],
            confidence="low",
        )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason=(
            f"Webhook route ({route_hint!r}) but the secret does not appear to be env / vault-sourced; "
            "no rotation pattern detected either."
        ),
        remediation=(
            "Load the webhook secret from a runtime secret manager (env, Vault, AWS Secrets Manager, "
            "Azure Key Vault) rather than from source, and accept multiple secrets during a documented "
            "rotation window."
        ),
        evidence_sources=[],
        confidence="low",
    )


def build_webhook_evaluators() -> dict[str, Callable[[Any], EvalOutcome]]:
    return {
        "SEC-WEBHOOK-001": eval_sec_webhook_001,
        "SEC-WEBHOOK-002": eval_sec_webhook_002,
        "SEC-WEBHOOK-HMAC-001": eval_sec_webhook_hmac_001,
        "SEC-WEBHOOK-TIMING-002": eval_sec_webhook_timing_002,
        "SEC-WEBHOOK-REPLAY-003": eval_sec_webhook_replay_003,
        "SEC-WEBHOOK-BODY-004": eval_sec_webhook_body_004,
        "SEC-WEBHOOK-IDEMP-005": eval_sec_webhook_idemp_005,
        "SEC-WEBHOOK-ROTATE-006": eval_sec_webhook_rotate_006,
    }
