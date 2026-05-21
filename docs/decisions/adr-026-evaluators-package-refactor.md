# ADR-026 - Split `evaluators.py` monolith into an `evaluators/` package

- **Status**: accepted (v6.1.0 maturation, M8)
- **Date**: 2026-05-21
- **Context window**: v6.1.0 maturation, prompt 07 (M8); follows M7 (`load_evidence_schema`)
- **Related**: ADR-013 (reports/2.0), the `evaluators_*` boundary modules

## Context

`src/oss_policy_kit/application/evaluators.py` had grown to ~8,800 lines / ~375 KB
holding 150 `eval_*` functions, 92 private helpers, 78 module constants, the
`EvalContext` class, and the `EVALUATOR_REGISTRY`. It was the single biggest
maintainability barrier in the codebase: slow to type-check, hard to review, a
frequent merge-conflict hot spot, and intimidating to new contributors. Several
`evaluators_*` boundary modules already existed alongside it for dynamically-built
rule packs (IaC, k8s, containers, fuzzing, webhook), but the core monolith still
concentrated the bulk of the logic.

## Decision

Convert the module into a package `application/evaluators/` with:

- **`_shared.py`** — all imports, module constants, private helpers, and the
  `EvalContext` class, moved verbatim. It exposes everything through `__all__` so
  family modules can `from ._shared import *` and keep identical behavior with no
  changes to function bodies.
- **Family modules** by control family — `governance.py`, `cicd.py`, `github.py`,
  `azure.py`, `aws.py`, `gitlab.py`, `supply_chain.py`, `ai.py`, `cra.py` — each
  holding the `eval_*` functions for that family, moved verbatim.
- **`__init__.py`** — re-exports the shared namespace and every family, then builds
  `EVALUATOR_REGISTRY` (the original dict literal plus the existing boundary-module
  loaders and the entry-point plugin loader) exactly as before.

The split was performed by a deterministic script that copied exact source spans
(no retyping, no logic edits). The one genuine cross-family reference
(`SLSA-SRC-005` / `SLSA-SRC-008` delegating to `AUDIT-STREAM-060`) is handled with
an explicit import from `governance` into `supply_chain` (acyclic; governance does
not import back).

`from ._shared import *` is an intentional re-export pattern; `ruff` `F403`/`F405`
are silenced for the package via a scoped `per-file-ignores` entry, while `mypy`
(strict) still catches genuinely undefined names — as it did during this refactor,
flagging the cross-family reference above.

## Alternatives considered

1. **Leave the monolith.** Rejected — it was the project's top maintainability debt.
2. **One internal `_core.py` + thin `__init__`.** Rejected — renames the file without
   delivering the by-family readability/merge-conflict win.
3. **Explicit per-family imports instead of `from ._shared import *`.** Rejected for
   now — it would require computing and maintaining the exact shared-symbol set per
   module; the star re-export keeps the move purely mechanical and behavior-identical.

## Consequences

- No behavior change: the `EVALUATOR_REGISTRY` ID set is byte-identical (212 controls);
  evaluation reports for `examples/hardened-repo` and `examples/vulnerable-repo` are
  byte-identical (only the `generated_at` timestamp differs); the full test suite
  passes with **zero changes under `tests/`**; entry-point plugins still load.
- Public imports are preserved: `from oss_policy_kit.application.evaluators import
  EVALUATOR_REGISTRY, EvalContext, eval_<id>` continue to work.
- `mypy` type-checks a set of smaller modules; code review and merges over evaluator
  changes are now scoped to a family file instead of the monolith.
- Trade-off: `F403`/`F405` are ignored within the package (documented above).

## References

- v6.1.0 maturation plan, prompt 07 (M8); prompt 06 (M7) consolidated the schema
  loaders first to keep this move clean.
