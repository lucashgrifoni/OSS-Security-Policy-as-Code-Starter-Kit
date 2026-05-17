# GitLab CI profile family

> **New in v5.9.0.** The GitLab CI surface is intentionally narrow: one starter profile (`gitlab-level-1`) and six controls (`GL-PIPE-001..006`) covering the most common static-analysis findings for `.gitlab-ci.yml`. The remaining six controls (`GL-PIPE-007..012` — OIDC tokens, self-hosted-runner restrictions, audit-log streaming, etc.) and the `-level-2` / `-level-3` ladder profiles ship in subsequent minors. See [ADR-003](../decisions/adr-003-gitlab-ci-support.md) for the broader design.

## Profile: `gitlab-level-1`

- **Posture:** starter ladder, `--fail-on fail` recommended.
- **Audience:** teams whose primary CI runs on GitLab.com or self-hosted GitLab (Community or Enterprise).
- **Total controls:** 16. Six GitLab-specific (`GL-PIPE-001..006`) plus the cross-platform governance controls (`GOV-SEC-001`, `GOV-CON-002`, `GOV-COWN-003`, `GOV-LIC-004`, `GOV-DISC-013`, `GOV-WAIV-014`, `REL-CHANGE-012`) and an evidence-freshness check (`GOV-EVIDFRESH-054`).
- **Experimental controls:** all six `GL-PIPE-*` (38% of the profile). These will graduate to `stable` once adopter feedback is in.

### What the parser covers

The bundled `gitlab_ci_parser` walks `.gitlab-ci.yml` (root or under `.gitlab/`) and looks for:

| Control | What it detects | Severity |
|---|---|---|
| `GL-PIPE-001` | Pipeline files present and parseable | deterministic |
| `GL-PIPE-002` | `image:` references pinned. **Mutable tags (`:latest`, `:edge`, `:stable`, `:main`, `:master`, `:nightly`, `:lts`) fail with `high` confidence** — they drift between pipeline runs and break reproducibility. | signal (tag-only) → deterministic (digest) |
| `GL-PIPE-003` | `script:` containing `curl ... \| sh` or `wget ... \| sh` | signal |
| `GL-PIPE-004` | Jobs declaring `inherit: secrets: true` (broad secret exposure) | deterministic |
| `GL-PIPE-005` | `include:` entries pointing to a remote URL (no local pinning) | signal |
| `GL-PIPE-006` | Coarse trigger-restriction signal — at least one job declares `rules:`, `only:`, `except:`, or `when:` | signal |

### What the parser does NOT cover (yet)

- `extends:` job inheritance is not recursively resolved.
- Remote `include:` files are NOT fetched (the kit stays hermetic — no outbound HTTP).
- `parent-child pipelines` (`trigger:` keyword) are not unfolded.
- `rules:if` expressions are not evaluated symbolically.
- `id_tokens:` OIDC usage detection is deferred to `GL-PIPE-007` (not shipped in v5.9.0).
- Self-hosted-runner `tags:` analysis is deferred to `GL-PIPE-008`.

### Quickstart

```bash
# 1. From the repo root with a .gitlab-ci.yml
python -m oss_policy_kit recommend-profile --target .
# Expected: gitlab-level-1 recommended when a .gitlab-ci.yml exists

# 2. Run as a release gate
python -m oss_policy_kit evaluate --target . --profile gitlab-level-1 --fail-on fail \
    --output-dir oss-policy-reports

# 3. Inspect drift between two evaluations
python -m oss_policy_kit diff-reports \
    --before main/evaluation-report.json \
    --after pr-branch/evaluation-report.json \
    --format markdown
```

### Evidence dependencies

`gitlab-level-1` does **not** require any `.oss-policy-kit/evidence/*.json` files. It is a clone-visible profile — all signals come from parsing `.gitlab-ci.yml`. The shared `GOV-EVIDFRESH-054` control evaluates evidence-file freshness only when evidence is supplied (silent pass when absent).

### Caveats

- **Mutable tag detection is v0.1.** It catches the canonical mutable tags (`:latest`, `:edge`, `:stable`, `:main`, `:master`, `:nightly`, `:lts`). Custom mutable-tag conventions (e.g. an internal `:dev` registry tag) are not detected.
- **Remote includes are tracked, not fetched.** If your pipeline depends on `include:remote:` for security-critical templates, the kit reports the dependency but cannot validate the remote content. Pin to a commit / ref where possible.
- **`extends:` inheritance is shallow.** A job that inherits an unpinned `image:` via `extends:` may not be detected on the parent declaration. Inspect the resolved pipeline in GitLab UI if a fail is unexpected.

### Lacunas conceituais futuras (NOT in v5.9.0)

`gitlab-level-2` / `gitlab-level-3` ladder, OIDC token check (`GL-PIPE-007`), self-hosted-runner tag restriction (`GL-PIPE-008`), audit-log streaming (`GL-PIPE-009`), `extends:` deep resolution, parent-child pipeline coverage. These are tracked in [docs/profiles/deferred-followups.md](deferred-followups.md).
