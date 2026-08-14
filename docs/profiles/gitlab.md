# GitLab CI profile family

> **GitLab is a first-class platform family.** It mirrors the GitHub / Azure / AWS
> structure: a three-rung ladder (`gitlab-level-1/2/3`) **and** a parallel
> release-hardening track (`gitlab-release-hardening-1/2/3`), backed by a dedicated
> `.gitlab-ci.yml` parser, twelve native controls (`GL-PIPE-001..012`), an evidence
> collector (`collect-evidence --platform gitlab`), and scaffold templates
> (`scaffold-evidence --platform gitlab`). See [ADR-003](../decisions/adr-003-gitlab-ci-support.md).

## The ladder at a glance

| Profile | Controls | Posture | Recommended `--fail-on` |
|---|---:|---|---|
| `gitlab-level-1` | 16 | starter ladder | `fail` |
| `gitlab-level-2` | 22 | advisory ladder | `degraded` |
| `gitlab-level-3` | 29 | hard-gate (extreme) | `fail` (+ `collect-evidence`) |
| `gitlab-release-hardening-1` | 19 | release ladder | `fail` |
| `gitlab-release-hardening-2` | 29 | release ladder | `degraded` |
| `gitlab-release-hardening-3` | 36 | release hard-gate (extreme) | `fail` (+ `collect-evidence`) |

> Counts come from `python -m oss_policy_kit profiles --format json --family gitlab`
> against this build; that JSON is the canonical source of truth.

## Native GitLab CI controls (`GL-PIPE-001..012`)

The bundled `gitlab_ci_parser` walks `.gitlab-ci.yml` (root or under `.gitlab/`):

| Control | What it detects | Tier |
|---|---|---|
| `GL-PIPE-001` | Pipeline files present and parseable | L1 |
| `GL-PIPE-002` | `image:` references pinned; **mutable tags (`:latest`, `:edge`, `:stable`, `:main`, `:master`, `:nightly`, `:lts`) fail high** | L1 |
| `GL-PIPE-003` | `script:` containing `curl ... \| sh` / `wget ... \| sh` | L1 |
| `GL-PIPE-004` | Jobs declaring `inherit: secrets: true` (broad secret exposure) | L1 |
| `GL-PIPE-005` | `include:` entries pointing to an unpinned remote URL | L1 |
| `GL-PIPE-006` | Trigger restrictions (`rules:` / `only:` / `except:` / `when:`) | L1 |
| `GL-PIPE-007` | OIDC `id_tokens:` for cloud / registry access (GitLab GA Jan 2026) | L2 |
| `GL-PIPE-008` | Self-hosted runner scoping via `tags:` | L2 |
| `GL-PIPE-009` | Audit-event streaming / external export documented | L2 |
| `GL-PIPE-010` | Environment approval rules for protected envs | L2 |
| `GL-PIPE-011` | MR review rules enforce code-review approvals (evidence: `gitlab-mr-rules.json`) | L2 |
| `GL-PIPE-012` | Artifact retention (`expire_in:`) or signed-release posture | L2 |

### What the parser does NOT cover (yet)

- `extends:` job inheritance is not recursively resolved.
- Remote `include:` files are **not** fetched (the kit stays hermetic — no outbound HTTP).
- Parent-child pipelines (`trigger:`) are not unfolded.
- `rules:if` expressions are not evaluated symbolically.

For deeper pipeline AST analysis, pair the profiles with poutine SARIF
(`SAST-POUTINE-067`) — `gitlab-release-hardening-3` already bundles that control.

## Release-hardening track

The release track layers release discipline on top of each ladder rung, mirroring
`github-/azure-/aws-release-hardening-*`:

- **`gitlab-release-hardening-1`** — `gitlab-level-1` + protected-branch evidence
  (`PLAT-BRPROT-015`) + cross-platform release hygiene (`SEC-GITIGNORE-051`,
  `SEC-PINLOCK-052`).
- **`gitlab-release-hardening-2`** — `gitlab-level-2` + protected-branch evidence,
  evidence freshness (`GOV-EVIDFRESH-054`), and container image posture
  (`CONT-IMAGE-001..003`).
- **`gitlab-release-hardening-3`** — strictest bundled GitLab release gate:
  `gitlab-level-3` hard-gate core **plus** container posture, pipeline-AST scan
  evidence (`SAST-POUTINE-067`), and release-archive retention (`RELEASE-ARCHIVE-063`).
  GitHub-specific signals (`GH-PLAT-*`, `CI-WFCALLSHA-055`) are intentionally excluded.

## Evidence: scaffold and collect

`gitlab-level-3` and the release-hardening track include evidence-backed controls.
GitLab evidence comes from two paths, the same as the other families:

```bash
# Manual templates (fill in by hand):
python -m oss_policy_kit scaffold-evidence --target . --platform gitlab
# -> .oss-policy-kit/evidence/{branch-protection,gitlab-mr-rules,org-mfa-posture}.json

# API-backed collection (read-only):
export GITLAB_TOKEN=glpat-...            # read_api (+ group read for MFA posture)
export GITLAB_URL=https://gitlab.com     # optional; set for self-managed instances
python -m oss_policy_kit collect-evidence --target . --platform gitlab --repo group/project
```

The GitLab collector retrieves three evidence files:

| Evidence file | GitLab API source | Consumed by |
|---|---|---|
| `branch-protection.json` | `/projects/:id/protected_branches` + `/approvals` | `PLAT-BRPROT-015` |
| `gitlab-mr-rules.json` | `/projects/:id/approval_rules` + `/approvals` | `GL-PIPE-011` |
| `org-mfa-posture.json` | `/groups/:id` (`require_two_factor_authentication`) | `ORG-MFA-001` |

**`gitlab-mr-rules.json` is validated against its schema.** Since v10.0.15, `GL-PIPE-011`
checks the file against
[`reports/schema/evidence-gitlab-mr-rules.schema.json`](../../reports/schema/evidence-gitlab-mr-rules.schema.json)
before reading it, so `schema_version`, `attested_at`, `attested_by`, `project` and
`min_approvers` are all required and `min_approvers` must be a whole number. A file that
does not match reports `manual-review-required` naming the problem; a file still carrying
`REPLACE_ME` placeholders from `scaffold-evidence` reports `not-evaluated` rather than
counting. `min_approvers: 0` is a **FAIL** — the evidence is readable and says merge requests
need no approval.

Before v10.0.15 the schema shipped but nothing loaded it, so a one-key document, an untouched
scaffold, and a non-integer count all reported PASS.

**Collector-partial boundary (honest parity with Azure/AWS):** SBOM and provenance
artifact digests (`PROV-VERIFY-061`, SBOM quality) stay self-attested or
pipeline-emitted — they are not collectable from a generic REST call. `org-mfa-posture.json`
is only emitted when the project lives under a **group** namespace; personal-namespace
projects skip it. `enforce_admins` reflects a merge-only default branch (no direct push);
GitLab **instance** administrators are never fully restricted by project settings.

## Quickstart

```bash
# 1. From the repo root with a .gitlab-ci.yml
python -m oss_policy_kit recommend-profile --target .
# Expected: gitlab-level-1 recommended when a .gitlab-ci.yml exists
#           (gitlab-release-hardening-2 once GitLab-shaped evidence is present)

# 2. Run as a release gate
python -m oss_policy_kit evaluate --target . --profile gitlab-level-3 --fail-on degraded \
    --output-dir oss-policy-reports

# 3. Inspect drift between two evaluations
python -m oss_policy_kit diff-reports \
    --before main/evaluation-report.json \
    --after pr-branch/evaluation-report.json \
    --format markdown
```

## Caveats

- **Mutable tag detection** catches the canonical mutable tags; custom internal
  conventions (e.g. a `:dev` registry tag) are not detected.
- **Remote includes are tracked, not fetched.** Pin to a commit / ref where possible.
- **`extends:` inheritance is shallow.** Inspect the resolved pipeline in the GitLab UI
  if a fail is unexpected.
- **L3 / release-hardening-3 are evidence-heavy.** Without `collect-evidence --platform gitlab`
  (or hand-filled evidence files), several controls land on `manual-review-required` —
  that is honest, not a defect. See the [L3 evidence-heavy caveat](overview.md#l3-evidence-heavy-caveat-read-before-wiring-a-hard-gate).

## Further reading

- [Profiles overview](overview.md)
- [ADR-003 — GitLab CI support](../decisions/adr-003-gitlab-ci-support.md)
- [Framework alignment](../framework-alignment.md)
