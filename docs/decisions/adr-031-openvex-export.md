# ADR-031 - Add OpenVEX export alongside CycloneDX VEX (v6.6.0)

- **Status**: accepted (v6.6.0, ADDITIVE / non-breaking) — shipped as the `emit-vex` command; status line flipped 2026-09-15 after confirming the command is in the released CLI
- **Date**: 2026-05-26
- **Context window**: v7.x roadmap horizon — "Contract modernization & ecosystem interoperability", shipped early as a v6.x additive minor (roadmap decision §11.1: defer the breaking reports/2.0 flip one cycle; ship low-risk interop first)
- **Related**: ADR-002 (emit-vex scope), ADR-001 (SCA scanner choice), `docs/vex-emission.md`, the maintainer's local roadmap (not published) (v7.x); local OpenVEX backlog note

## Context

`emit-vex` emits **CycloneDX VEX 1.6 only** (`cli/emit_vex.py`: `_BOM_FORMAT="CycloneDX"`,
`_VEX_VERSION="1.6"`, with structural `--validate`). OpenVEX is the leaner, widely
adopted VEX format (Go toolchain, Kubescape, Edgebit; `vexctl`; Chainguard's OpenVEX
feed) and is on the path to ISO/IEC 5962. Multi-format VEX (OpenVEX / CycloneDX VEX /
CSAF) is a real consumer pain point. Supporting OpenVEX widens the interoperability of
the same waiver/exploitability data the kit already models, with no new evidence source.

This is **additive**: a new value of a new flag. It does not change the existing
CycloneDX output, flags, or exit-code semantics, so it ships as a minor (v6.6.0), not a
major. The roadmap places OpenVEX in the v7.x interop horizon, but §11.1 chose to ship
the contract-safe interop items as v6.x minors before spending the v7.0.0 major on the
breaking reports/2.0 flip.

Two impedance mismatches between the kit's internal model and OpenVEX must be resolved
explicitly, because both are lossy or under-specified relative to the source data:

1. **`products` is required per OpenVEX statement.** The kit's VEX is vulnerability-only
   (no product/component identity), which CycloneDX VEX tolerates but OpenVEX does not.
2. **The justification vocabulary is not 1:1.** CycloneDX defines seven
   `analysis.justification` values; OpenVEX defines five.

## Decision

In **v6.6.0**, add `emit-vex --format {cyclonedx,openvex}`, defaulting to `cyclonedx`
(so existing invocations are unchanged). `--validate` extends to validate the OpenVEX
structure (lightweight required-field / enum check, paralleling the CycloneDX validator;
not a bundled JSON Schema).

### Status mapping (internal → OpenVEX `status`)

| Kit `analysis.state` | OpenVEX `status` |
|---|---|
| `in_triage` (default, no waiver) | `under_investigation` |
| `not_affected` (waiver matched) | `not_affected` |

(The kit emits only these two states today; `affected`/`fixed` mappings are reserved for
when richer states are produced, and are not authored speculatively.)

### Justification mapping (CycloneDX `analysis.justification` → OpenVEX `justification`)

| CycloneDX | OpenVEX |
|---|---|
| `code_not_present` | `vulnerable_code_not_present` |
| `code_not_reachable` | `vulnerable_code_not_in_execute_path` |
| `requires_configuration` | `vulnerable_code_cannot_be_controlled_by_adversary` |
| `requires_dependency` | `vulnerable_code_cannot_be_controlled_by_adversary` |
| `requires_environment` | `vulnerable_code_cannot_be_controlled_by_adversary` |
| `protected_by_compensating_control` | `inline_mitigations_already_exist` |
| `inline_mitigations_already_exist` | `inline_mitigations_already_exist` |

The mapping is **lossy** (three CycloneDX values collapse to one OpenVEX value); the
equivalence table is documented in `docs/vex-emission.md` so the loss is visible, not
silent. When a `not_affected` finding has **no** mapped justification (waiver carried no
`vex_justification`), the free-text waiver detail is emitted as the OpenVEX
`impact_statement` — which satisfies the OpenVEX rule that `not_affected` requires either
a `justification` or an `impact_statement`. Assurance honesty is preserved: nothing is
auto-classified beyond what the waiver author already asserted.

### Product identity (the `products` requirement)

Add an optional `--product <id>` flag (e.g. a purl such as `pkg:pypi/acme@1.2.3`). When
supplied, it becomes the statement `products[].@id`. When **omitted**, the kit emits a
documented placeholder `@id` (`pkg:generic/UNKNOWN`) and prints a loud stderr warning
that the document is structurally valid but the product identity must be filled in before
distribution. This keeps the zero-config ergonomics the CycloneDX path enjoys while
being honest that the placeholder is not a real product assertion. (Deriving product
identity from an SBOM is explicitly out of scope — the kit does not build SBOMs;
ADR-002.)

### Document shape

OpenVEX top-level: `@context` (`https://openvex.dev/ns/v0.2.0`), `@id`, `author`
(`oss-policy-kit emit-vex`), `timestamp` (UTC ISO-8601), `version`, `tooling`, and
`statements[]`. Each statement carries `vulnerability.name`, `products[].@id`, `status`,
and the mapped `justification` / `impact_statement` as above. The change is validated by
`cli-api-ui-contract-validator` (new flag value, no contract break) and by golden
fixtures that normalize the non-deterministic `timestamp` and `@id`.

## Alternatives considered

1. **Stay CycloneDX-only.** Rejected — leaves the kit unable to feed the OpenVEX-native
   toolchain (vexctl, Kubescape) that a large share of consumers run.
2. **Require `--product` for OpenVEX.** Rejected (maintainer decision §11.1 follow-up) —
   breaks the zero-config ergonomics; the placeholder-plus-warning path is honest enough
   and keeps the common case frictionless.
3. **Add CSAF in the same change.** Rejected — CSAF is a third format with its own
   complexity; defer to a separate backlog item gated on real demand.
4. **Full OpenVEX JSON Schema validation bundled now.** Rejected for v6.6.0 — matches the
   existing CycloneDX choice (structural validation, lean dependency); schema-level
   validation can follow as an additive option, the same way it is tracked for CycloneDX.

## Consequences

- The same waiver/exploitability data is emittable as both CycloneDX VEX 1.6 and OpenVEX,
  widening downstream interoperability with no new evidence source.
- The CycloneDX path is byte-for-byte unchanged; `--format` defaults to `cyclonedx`.
- The lossy justification mapping and the placeholder product identity are documented and
  warned about, not hidden — preserving the kit's assurance-honesty guard-rail.
- Trade-off: the kit now maintains two VEX renderers and a vocabulary-equivalence table
  that must track upstream OpenVEX spec changes; mitigated by structural validation and
  golden fixtures, and by pinning the emitted `@context` to a specific OpenVEX version.

## References

- OpenVEX spec & `vexctl` — <https://github.com/openvex/spec>, <https://github.com/openvex/vexctl>
- State of VEX (OpenSSF, 2026-01) — <https://openssf.org/blog/2026/01/08/signal-in-the-noise-an-industry-wide-perspective-on-the-state-of-vex/>
- CycloneDX VEX capabilities — <https://cyclonedx.org/capabilities/vex/>
- ADR-002 (emit-vex scope), `docs/vex-emission.md`
- the maintainer's local roadmap (not published) (v7.x horizon); roadmap plan §3.7, §6 (v7.x); backlog `openvex-export-2026-05-25.md`
