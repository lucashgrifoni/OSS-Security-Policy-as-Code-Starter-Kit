# Project governance

This document explains how the OSS Security Policy as Code Starter Kit is maintained, who decides what changes go in, and how new contributors can become maintainers.

## Project status

This is a volunteer-maintained, single-maintainer OSS project. It is not backed by a foundation, sponsor, or company. Contributions are welcome through standard GitHub workflows; there is no separate steering committee.

## Maintainers

| Role | Holder | Scope |
| --- | --- | --- |
| Lead maintainer | Lucas Grifoni ([@lucashgrifoni](https://github.com/lucashgrifoni)) | All technical and release decisions; merge rights on `master`; releases on PyPI; security disclosure handling |

The project may add additional maintainers as contribution patterns warrant. The criteria are listed in [Becoming a maintainer](#becoming-a-maintainer).

## Decision making

For day-to-day technical decisions (bug fixes, doc updates, additive controls, new evaluators that follow existing patterns), the maintainer decides. PRs that match an existing pattern, do not break the JSON / SARIF report contracts, do not add hard dependencies, and pass CI are merged after review.

For changes that touch any of the following, an issue must be opened first to discuss intent and impact, and the maintainer reserves final say:

- breaking changes to the JSON report contracts (`reports/1.0`, `reports/0.3`, `reports/0.2`)
- changes to bundled profile semantics (composition, posture, or the `--fail-on` recommendation)
- new hard runtime dependencies (anything in `[project] dependencies`)
- changes to the trust / honesty contracts described in `docs/architecture.md`
- new evidence schemas (additions are fine; renames are breaking)
- removal of any control id from the catalog

When in doubt, open an issue with the `proposal` label before writing code.

## Release process

Releases follow [Semantic Versioning](https://semver.org/):

- **Patch** (`vX.Y.Z+1`): bug fixes, doc updates, internal refactor with byte-equivalent reports.
- **Minor** (`vX.Y+1.0`): new controls, new profiles, new optional dependencies, new CLI subcommands. Backwards-compatible by definition.
- **Major** (`vX+1.0.0`): removal of any public surface (catalog ids, CLI flags, JSON report contracts, profile ids).

Each release ships:

- a tagged commit on `master` (`vX.Y.Z`)
- a GitHub Release with curated notes (see `docs/release-readiness.md` and `docs/release-playbook-hardgate.md`)
- a corresponding PyPI package (`oss-policy-kit==X.Y.Z`)
- distribution artifacts (wheel + sdist) attached to the GitHub Release for offline installs
- a CycloneDX SBOM artifact in the release workflow

The current release-readiness gate runs the full test suite, the bundled hygiene scanner (`scripts/check_public_hygiene.py`), and a security CI workflow. See `docs/release-readiness.md`.

## Contribution flow

1. Open an issue describing what you want to change, ideally before writing code. For trivial doc fixes you can skip this and open a PR directly.
2. Fork the repository, branch from `master`, keep changes scoped.
3. Run `pytest` locally before opening the PR. If you touch CLI behavior, run a smoke against `examples/hardened-repo` and `examples/vulnerable-repo`.
4. Open a pull request against `master`. Reference the issue in the PR body.
5. The maintainer reviews. Expect comments on test coverage, honesty contracts, and report-shape stability.

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for code style and test expectations.

## Becoming a maintainer

Maintainership is offered to contributors who have demonstrated, over time, all of the following:

- merged at least three substantive PRs (not just doc fixes) in the past six months
- shown good judgment on backward-compatibility trade-offs in PR review threads
- understanding of the kit's honesty contracts (deterministic vs signal vs evidence-backed; report contract versioning; profile posture honesty)
- sustained engagement (responding to issues, reviewing other PRs)

The lead maintainer extends the invitation. New maintainers join with the same merge rights as existing maintainers. There is no probation period, but mismatches in judgment can be resolved by the lead maintainer reverting merge rights with explanation.

## Code of conduct

All participants in this project — contributors, reviewers, issue authors — are expected to follow the [Contributor Covenant Code of Conduct v2.1](CODE_OF_CONDUCT.md).

## Security

Vulnerabilities are reported through the channel described in [`SECURITY.md`](SECURITY.md). The maintainer handles triage, fix, and coordinated disclosure. There is no formal SLA on a volunteer-maintained project, but reports are reviewed in a reasonable timeframe.

## Forking

The project is Apache-2.0 licensed; forks are welcome. If you maintain a fork that materially diverges (different scope, different governance, different release cadence), please rename the package on publication so users can distinguish.

## License

This project is licensed under the Apache License, Version 2.0. See [`LICENSE`](LICENSE) for the full text.
