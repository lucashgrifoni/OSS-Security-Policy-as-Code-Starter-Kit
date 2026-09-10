# Security policy

## Supported versions

Security fixes are generally applied to the latest supported default branch. Release tags may exist for packaging and changelog traceability, but this repository is maintained primarily on the default branch.

## Reporting a vulnerability

### Preferred channel

GitHub private vulnerability reporting is enabled on this repository. Use it:

- Repository: `https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit`
- Entry point: **Security** tab -> **Report a vulnerability**
- Direct link: <https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/security/advisories/new>

That form opens a private advisory visible only to you and the maintainer. It is the only
channel this project asks you to use; nothing here requires you to find a private address
on your own.

Do not open a public issue for an undisclosed vulnerability.

### What to include

Include, when possible:

- a concise description of the issue
- steps to reproduce
- impact notes
- affected versions, commits, or files
- proof-of-concept details only when necessary to reproduce safely

### Response expectations

This is a volunteer-maintained OSS project. Reports will be reviewed in a reasonable timeframe, but no formal SLA is guaranteed.

### Coordinated disclosure

Please allow reasonable time for validation and remediation before public disclosure, unless immediate disclosure is required by law or the issue is already being actively exploited in public.

## Sensitive data exposure

If a credential, key, or other sensitive value is committed to this repository, follow [docs/secret-leak-response.md](docs/secret-leak-response.md). Rotate the credential at the issuer first; rewriting Git history does not invalidate a secret already published.

Preventive scanning is provided by [templates/workflows/secret-scanning.yml](templates/workflows/secret-scanning.yml), which downstream consumers of this kit can copy into `.github/workflows/`.

## Posture, and what the Scorecard does not measure

The repository publishes an [OpenSSF Scorecard](https://securityscorecards.dev/viewer/?uri=github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit). Some of its checks score zero or near zero and will stay that way; they are listed here so the score is read correctly rather than as an unaddressed defect.

| Check | Score | Why it is where it is |
|---|---|---|
| Code-Review | 0 | One maintainer. A pull request cannot be reviewed by its author, and there is nobody else. Every change still passes the 13 required status checks, a required commit signature, and a linear-history rule before it reaches `master`. |
| Contributors | 0 | The check counts contributors from several organizations. This project has one. |
| Branch-Protection | 3 | The ruleset requires signatures, 13 status checks, linear history and no force-push. It does not require a review (see above) and it allows the repository owner to bypass — which is how a solo maintainer merges at all. |

What the score *does* reflect: SAST, signed releases, pinned dependencies, token permissions, dangerous-workflow analysis, fuzzing, and a vulnerability-free dependency tree are each measured and each at or near the maximum. A drop in any of those is a regression worth reporting.

### Findings that are open on purpose

Three classes of alert stay open in code scanning. All three are accurate about what they measure and none of them describes a defect that can be closed here.

**Pinned-Dependencies on three CI installs.** Exactly three `pip install` commands resolve versions this repository has not committed to. Naming them rather than describing them is deliberate: the count moved twice on 2026-09-02, and on both occasions a prose description was what let it move unnoticed.

| File | Command |
| --- | --- |
| `.github/workflows/github-ci-cd.yml` | `python -m pip install -e ".[dev]"` (quality job) |
| `.github/workflows/github-ci-cd.yml` | `python -m pip install -e ".[dev]"` (build-and-publish job) |
| `.github/workflows/security-ci-cd.yml` | `python -m pip install -e .` (pip-audit job) |

The two `dev` installs resolve the dev tool ranges `pyproject.toml` declares. A lock for them would have to be regenerated inside every Dependabot pull request that bumps a dev tool, and a lock that drifts from `pyproject.toml` fails silently rather than loudly: CI would test one version of ruff or mypy while the project declares another, and a green run would stop meaning what it says. That is a worse outcome than the finding, which covers tools that run only in CI, in a job that holds no secrets.

This acceptance is a bet that a version change lands loudly rather than quietly, and on 2026-09-02 it paid out in the pleasant direction: CI resolved mypy 2.3.1 and passed, while a contributor machine still on mypy 1.20.1 reported an error in `application/evaluators/cicd.py` that CI does not see. An older checker being stricter is the harmless case. A newer one being *laxer* would have been a false green, and nothing here would have caught it — which is the residual risk this acceptance carries, stated rather than implied.

The third is the editable install in the `pip-audit` job, and pinning it would defeat the job. That job exists to audit the runtime closure the ranges in `pyproject.toml` actually resolve to; installing a frozen lock would audit the lock instead, and report clean on precisely the day a newly published range-satisfying version became vulnerable.

Everything shipped to a user *is* hash-pinned — the container image installs from `.github/requirements/`, which Dependabot watches. The three are enforced as a closed set by `tests/infrastructure/test_every_unpinned_pip_install_is_a_decision.py`, which applies Scorecard's own rule to every workflow and the `Dockerfile`: a fourth unpinned install fails the build in the pull request that adds it, rather than arriving later as an alert. Do not add to that list without adding the reason here.

**Base-image CVEs in `pip`.** A job scans the base image pinned by digest in the `Dockerfile` and reports six CVEs in the `pip 25.0.1` that Debian's Python image ships. The published image does not contain them: the runtime stage uninstalls pip from both interpreters, and a scan of the built image reports no fixable vulnerability at any severity. Bumping the digest does not clear them either, because the current upstream image ships the same pip. They describe the image this project builds *from*, which is worth knowing, not the image it publishes.

**Base-image CVEs in `libpcre2-8-0`.** The same job reports five advisories against `libpcre2-8-0 10.42-1`, which Debian fixes in `10.42-1+deb12u1`. Unlike the pip six, this is a system library that a Python image genuinely ships, so it cannot be answered by removing it. The runtime stage runs `apt-get upgrade` instead, and measured on 2026-09-09 that moves exactly this one package: the built image carries `10.42-1+deb12u1` and Trivy reports zero fixable vulnerabilities against it, at any severity, where the base image it was built from reports eleven.

The alerts stay open regardless, and it is worth being precise about why, because it is not the reason that applies to pip. They are raised against the *base* image by digest, so no change in this repository moves them — including the fix that already shipped. Refreshing the pin does not help either: the current upstream `python:3.12-slim-bookworm` digest carries the same `10.42-1`. The consequence is that the alert list cannot be used to tell whether this is handled, so `tests/infrastructure/test_the_runtime_stage_keeps_the_base_image_cves_out.py` is what holds the two runtime commands in place. Deleting either one would put these CVEs back into the published image without changing a single alert.

## Scope

Reports should target this repository and its distributed artifacts:

- the Python CLI
- bundled policy data
- schemas
- templates
- documentation and workflow material that directly affects the distributed project

## Out of scope examples

- vulnerabilities in downstream repositories that only consume this kit
- generic security questions unrelated to this codebase
- issues in third-party services not operated by this repository
