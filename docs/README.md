# Documentation Index

Use this page as the documentation entry point for the OSS Security Policy as Code Starter Kit.

Public project site:

- [GitHub Pages site](https://lucashgrifoni.github.io/OSS-Security-Policy-as-Code-Starter-Kit/)

Repository entry points:

- [README.md](../README.md) - product overview, install paths, CLI contract, result interpretation
- [CHANGELOG.md](../CHANGELOG.md) - released changes by version
- [at-a-glance.md](at-a-glance.md) - compact public capability and v6 development-count snapshot
- [release-state.md](release-state.md) - current public release line and v6.0.0 release boundary

## For Users

- [tutorial-first-pr-gate.md](tutorial-first-pr-gate.md) - first-time adopter path from install to a PR gate
- [quickstart-15-min.md](quickstart-15-min.md) - compact quickstart and compatibility notes
- [validation-walkthrough.md](validation-walkthrough.md) - full step-by-step demo with screenshots (CLI help, profile discovery, fixture comparison, controls table, CI gating)
- [sample-reports/](sample-reports/README.md) - generated hardened and vulnerable example reports
- [cli-reference.md](cli-reference.md) - full CLI reference (subcommands, flags, exit codes, examples)
- [results-guide.md](results-guide.md) - how to interpret report statuses (`pass`, `fail`, `manual-review-required`, `self-attested`, ...)
- [adoption-guide.md](adoption-guide.md) - choose a baseline and understand expected outcomes
- [recommended-adoption-playbook.md](recommended-adoption-playbook.md) - copy/paste adoption path for a standard Python repository
- [profiles/overview.md](profiles/overview.md) - bundled profiles matrix, assurance mix, daily/extreme/advisory usage classes, and **zero `fail`** vs **all-pass**
- [profiles/github.md](profiles/github.md) / [profiles/aws.md](profiles/aws.md) / [profiles/azure.md](profiles/azure.md) - operator guides by platform family
- [profiles/ai-agent.md](profiles/ai-agent.md) - advisory source-side baseline for AI agent and MCP server repositories
- [release-playbook-hardgate.md](release-playbook-hardgate.md) - evaluate a release hard-gate with real CLI commands
- [profiles/deferred-followups.md](profiles/deferred-followups.md) - items intentionally left out of this phase (flags, schema, new controls)
- [packaging-and-release.md](packaging-and-release.md) - supported distribution channels and local install/build commands
- [supply-chain-verification.md](supply-chain-verification.md) - PyPI, GHCR, cosign, and attestation verification commands
- [container-image.md](container-image.md) - the published container image: tags, signing, SBOM, and verification
- [sigstore-rekor-v2.md](sigstore-rekor-v2.md) - Sigstore Rekor v2 tile-based transparency-log notes
- [scorecard-mapping.md](scorecard-mapping.md) - how Scorecard fits as supplemental evidence
- [osps-mapping.md](osps-mapping.md) - mapping notes between this kit and OSS baseline concepts

## For Maintainers

- [release-readiness.md](release-readiness.md) - release gate, public launch checks, patch release routine, and repository operations
- [secret-leak-response.md](secret-leak-response.md) - runbook for handling credentials or other sensitive values committed to a repository
- [dev-environment.md](dev-environment.md) - local development setup, test loop, lint/type-check, and cache cleanup
- [testing-strategy.md](testing-strategy.md) - test layers (unit, application, integration, infrastructure, cli, property, contract), how to run each, and the coverage/complexity gates

## Reference

- [architecture.md](architecture.md) - package structure, trust model, and evidence boundaries
- [controls-catalog.md](controls-catalog.md) - generated bundled controls catalog (category, assurance, weight, profile membership)
- [collector-parity.md](collector-parity.md) - what each platform collector retrieves today (GitHub vs Azure vs AWS) and what intentionally stays self-attested
- [framework-alignment.md](framework-alignment.md) - master cross-framework mapping (Scorecard, OSPS, OWASP CICD Top 10, SLSA v1.0, NIST SSDF, S2C2F, CIS SSCS, AWS Well-Architected, Azure DevOps Security)
- [policy-data-lifecycle.md](policy-data-lifecycle.md) - lifecycle states for controls and profiles

## Migration guides

Most recent first; older guides are kept for adopters upgrading across several versions.

- [v6.0.0](v6.0.0-migration-guide.md)
- [v5.9.0](v5.9.0-migration-guide.md)
- [v5.2.0](v5.2.0-migration-guide.md)
- [v5.1.0](v5.1.0-migration-guide.md)
- [v4 → v5](v5.0.0-migration-guide.md)
- [v3 → v4](v4.0.0-migration-guide.md)
- [v3.0.0 release notes](v3.0.0-migration-guide.md)

## Scope Reminder

This repository intentionally keeps public docs focused on:

- how to use the kit
- how to adopt the templates
- how to validate and release the package
- how to operate the repository responsibly

Historical planning notes and internal working prompts are not part of the public documentation set.
