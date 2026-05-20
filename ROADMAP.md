# Roadmap

This roadmap is intentionally short. It describes planned direction, not shipped capability. The current public release remains the version listed in `README.md` and `CHANGELOG.md`.

## Now - v6.0.0 GA

- Finish local v6.0.0 branch review and push strategy.
- Keep `reports/1.0` as the default while shipping opt-in `reports/2.0`.
- Ship the v6.0.0 profile expansion already landed locally: AI/LLM advisory coverage, EU AI Act Article 11 readiness, SLSA Source L1, GitLab L2, `emit-insights`, `export-evidence`, and `oss-publish-readiness-1`.
- Complete Cycle 2 Tier 1 items that are safe before GA: worm-aware publish defense, EPSS/KEV prioritization, OSPS/Scorecard v6 alignment, EU AI Act Annex IV expansion, and EU CRA Article 13/14 signals.
- Publish release evidence: PyPI dist attestations, signed GHCR image, SBOM, changelog, migration guide, and sample reports.

## Next - v6.x

- Refactor the large evaluator module into smaller family modules without changing control IDs or report contracts.
- Add property-based tests for control/profile YAML, waivers, and report schema edge cases.
- Add a navigable control catalog on GitHub Pages with filters by family, lifecycle, assurance, and profile membership.
- Add first-adopter tutorial assets: screenshots, sample outputs, and short demo GIFs.
- Add public comparison docs against Scorecard, zizmor, OSV-Scanner, Chainloop, OPA/Conftest, Kyverno, and adjacent ASPM tooling.
- Expand security review evidence: threat model for v6 surfaces, supply-chain pipeline audit, and stronger leak-detection rules.

## Later - v7+

- Explore CEL/Rego export as an integration layer for policy engines.
- Add SPDX SBOM export alongside CycloneDX-focused flows.
- Add `diff-catalogs` for control/profile deltas between kit versions.
- Add optional structured JSON logging and richer CLI explain/progress commands.
- Add Codespaces/Gitpod sandbox support.
- Publish maintainer/community signals such as `CITATION.cff`, `FUNDING.yml`, contributor paths, and case studies when there is real adoption evidence.

## Non-goals

- The kit will not claim certification, compliance, or absence of vulnerabilities.
- The kit will not replace scanner engines, runtime egress enforcement, evidence stores, or platform control planes.
- The kit will keep clone-visible signals separate from evidence-backed assertions.
