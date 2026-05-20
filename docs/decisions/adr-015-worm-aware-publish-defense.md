# ADR-015 - Worm-aware publish defense controls

- **Status**: proposed (v6.0.0 Cycle 2)
- **Date**: 2026-05-19
- **Context window**: v6.0.0 Cycle 2, PR-19
- **Related**: ADR-014 (`oss-publish-readiness-1`), `docs/shai-hulud-defense.md`

## Context

Supply-chain worms in the npm, PyPI, and container ecosystem have made publish-time controls a first-order OSS security concern. The kit already has Trusted Publishing checks through `oss-publish-readiness-1`, but those checks focus on identity-bound publishing and provenance. They do not directly surface clone-visible signs of worm activity such as suspicious package install hooks, manifest rewrites without lockfile refresh, or unscoped publish workflows.

The kit cannot observe runtime exfiltration, package-registry account state, or downstream package contents from a repository clone. It can still provide useful signal-grade checks for maintainers before a release.

## Decision

Ship a `WORM-*` control family and bundle it into `oss-publish-readiness-1`:

| Control | Decision signal |
|---|---|
| `WORM-POSTINSTALL-001` | `package.json` `scripts.postinstall` is absent or does not contain credential-harvest / network-execute primitives such as `curl`, `wget`, `process.env`, `base64 -d`, `eval`, or encoded PowerShell. |
| `WORM-LOCKFILE-DRIFT-001` | Known manifest and lockfile pairs are updated atomically; the manifest is not newer than the lockfile by more than 60 seconds. |
| `WORM-PUBLISH-SCOPE-001` | Workflows that publish to npm, PyPI, crates, or similar registries are explicitly scoped to main/master/release branches or version tags. |

All three controls are `lifecycle: experimental`, `assurance: signal`, and advisory by default. They are intended to catch suspicious patterns early, not to certify that a package is clean.

## Alternatives considered

1. **One combined worm-readiness control.** Rejected because the three signals have different false-positive profiles and remediation paths.
2. **Runtime egress detection.** Rejected for this kit because egress telemetry requires a runner, EDR, or sandbox integration outside clone-visible policy evaluation.
3. **Wait for package-registry APIs.** Rejected because maintainers need immediate local checks, while registry-side provenance and incident metadata are uneven across ecosystems.

## Consequences

**Positive**

- `oss-publish-readiness-1` now covers Trusted Publishing plus common worm rewrite / publish-trigger failure modes.
- Maintainers get precise remediation text tied to the observable condition.
- The controls preserve the kit's honesty model: clone-visible signals are useful but not conclusive.

**Negative / cost**

- The checks are heuristic and can false-positive on legitimate postinstall hooks or unusual publish workflows.
- `mtime`-based lockfile drift is a local signal; it is not a substitute for reviewing commit history or registry audit logs.

**Mitigations**

- Keep the controls advisory and experimental at v6.0.0.
- Document limitations in `docs/shai-hulud-defense.md`.
- Add tests for fail/pass/not-applicable paths and profile wiring.

## References

- v6.0.0 Cycle 2 plan, PR-19
- `docs/shai-hulud-defense.md`
- ADR-014 (`oss-publish-readiness-1`)
