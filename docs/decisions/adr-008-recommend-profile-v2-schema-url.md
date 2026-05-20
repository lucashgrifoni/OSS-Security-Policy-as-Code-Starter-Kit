# ADR-008 — `recommend-profile/v2.schema_version`: absolute URL (breaking)

- **Status**: proposed (v6.0.0, breaking)
- **Date**: 2026-05-18
- **Context window**: v6.0.0 planning, Onda 4 (PR-15)
- **Related**: existing `recommend-profile` CLI, `profile-recommendation/v2` shape

## Context

The `recommend-profile` CLI subcommand emits a JSON document with a top-level `schema_version` field. The current value is `"oss-policy-kit/profile-recommendation/v2"` — a slash-delimited shorthand. Two design concerns motivated revisiting it:

1. **Consumer ergonomics**: adopters writing tooling against the JSON have asked for a resolvable URL they can fetch the schema from. A shorthand like `oss-policy-kit/profile-recommendation/v2` requires the consumer to know which repository hosts the schema.
2. **Cross-kit consistency**: other kit-emitted JSON contracts (`reports/1.0`, `batch/0.1`, `evidence-*/v1`) use absolute URLs (`https://github.com/.../reports/1.0`, `https://schemas.lucashgrifoni.io/...`). `recommend-profile/v2` is the odd one out.

The minimal change is to set `schema_version` to a stable absolute URL, e.g. `"https://schemas.lucashgrifoni.io/oss-policy-kit/recommend-profile/v2.json"`.

This is a **breaking** change for any consumer that string-matches the exact value (`schema_version == "oss-policy-kit/profile-recommendation/v2"`). A consumer that checks for prefix `oss-policy-kit/profile-recommendation/v` would also break.

## Decision

**Change the `schema_version` value to the absolute URL** in v6.0.0. Tag the change as a documented breaking change in `CHANGELOG.md` under `## [6.0.0]`. Provide:

- A **migration note** in `v6.0.0-migration-guide.md` with the before / after JSON example.
- **Backward-compatible parsing** in the kit's own consumers (e.g. `diff-reports`, internal tests) for **one minor** (v6.0.x) — they accept either the old shorthand or the new URL when they consume their own `recommend-profile` output.
- **Removal of the backward-compat parsing** in v6.1.0.

The schema content itself does **not** change in v6.0.0; only the `schema_version` field changes. Consumers that ignore `schema_version` (parse by structure) are unaffected.

The change is identified as **M-003** in the migration matrix (M-001 and M-002 were earlier migrations in the v5.x line).

## Alternatives considered

1. **Keep the shorthand.** Rejected: inconsistent with the rest of the kit's contracts.
2. **Add both — keep `schema_version` shorthand AND add a parallel `schema_url` field.** Rejected: doubles the surface; consumers would not know which to trust as canonical. The simplest contract is one field.
3. **Defer to v6.1.0 or later.** Rejected: breaking changes batched into a major are cheaper than spreading them across minors. v6.0.0 is the natural window.

## Consequences

**Positive**

- All kit-emitted JSON contracts now use absolute-URL `schema_version` values consistently.
- Consumers can fetch the schema directly from the URL.

**Negative / cost**

- Any consumer that string-matches `schema_version == "oss-policy-kit/profile-recommendation/v2"` breaks.
- Adopters need a migration note (provided).

**Mitigations**

- One-minor backward-compat parsing in the kit's own consumers.
- Explicit M-003 entry in the migration guide with before / after JSON.
- Tests cover both the old shorthand (for the backward-compat parser path) and the new URL (the canonical path).

## References

- v6.0.0 execution plan §6.1 PR-15
- v6.0.0 proposal §5 O-16
- Existing `recommend-profile/v2` contract
- Convention reference: `reports/1.0` URL pattern in `src/oss_policy_kit/application/engine.py`
