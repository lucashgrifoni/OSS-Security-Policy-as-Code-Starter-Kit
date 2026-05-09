# Terraform / OpenTofu IaC coverage (v5.5.0+)

This page is the operator playbook for the `IAC-TF-*` controls and the bundled `iac-terraform-baseline-1` profile introduced in v5.5.0.

## What it does

`oss-policy-kit scan-iac` runs a bundled rule pack against every `*.tf` file under `--target`, parses the HCL with `python-hcl2`, and writes a normalized JSON evidence file under `.oss-policy-kit/evidence/iac-terraform.json` (schema `oss-policy-kit/evidence/iac-terraform/v1`). Each `IAC-TF-*` control is a thin reader of that evidence file: zero findings → `pass`; one or more → `fail`; missing or `not_available` evidence → `manual-review-required`. Exact same contract as `scan-sast` / `SAST-SEMGREP-064`.

## What it is not

This is **not** a CSPM verdict and **not** a Trivy / Checkov / KICS replacement. The kit's value here is the **stable evidence shape** + **kit-managed waivers** + **profile composition** so you can fold IaC posture into your existing OSS policy gate. If you already run a deeper scanner, point its findings at the kit via a custom evaluator instead of duplicating its rule pack.

## Bundled rule pack

| Rule | Severity | What it catches |
| --- | --- | --- |
| `IAC-TF-001` | HIGH | `aws_s3_bucket.acl = "public-read"` (and variants), `aws_s3_bucket_public_access_block` flags set to false, `google_storage_bucket.public_access_prevention = "inherited"`. |
| `IAC-TF-002` | HIGH | `aws_security_group` ingress on management ports (22, 3389, 3306, 5432, 1433, 6379, 27017, 9200) from `0.0.0.0/0` or `::/0`. |
| `IAC-TF-003` | HIGH | IAM roles / policies attaching `AdministratorAccess`, or inline policies with `Action: "*"` paired with `Resource: "*"`. |
| `IAC-TF-004` | MEDIUM | Storage / RDS / EBS / DynamoDB / SNS / SQS / Kinesis / GCS / Azure Storage / Azure managed disks without encryption-at-rest configured. |
| `IAC-TF-005` | MEDIUM | `aws_cloudtrail.enable_logging = false`, `aws_s3_bucket` with no `logging` block and no companion `aws_s3_bucket_logging`, `aws_db_instance` without `enabled_cloudwatch_logs_exports`. |
| `IAC-TF-006` | MEDIUM | Use of `aws_default_vpc`, `aws_default_subnet`, `aws_default_security_group`, `aws_default_route_table`. |
| `IAC-TF-007` | MEDIUM | `aws_subnet.map_public_ip_on_launch = true`, `aws_instance.associate_public_ip_address = true`, `aws_launch_template` network_interfaces with public IP attached. |
| `IAC-TF-008` | LOW | `aws_*` resources without a `tags` block or without `owner` / `cost_center` / `Owner`. (Skips IAM role/policy attachments which do not accept tags.) |
| `IAC-TF-009` | LOW | `terraform { required_providers { ... } }` block missing or providers without a pinned `version`. |
| `IAC-TF-010` | LOW | `terraform { backend "local" {...} }` (state should be remote with encryption + locking). |
| `IAC-TF-011` | MEDIUM | Data stores whose name matches `prod\|production\|prd\|live` (in either resource name or `name`/`identifier`) without `lifecycle { prevent_destroy = true }`. |
| `IAC-TF-012` | LOW | `data.aws_iam_policy_document` statement with `principals.identifiers = ["*"]`. |

All 12 rules ship as `lifecycle: experimental` for v5.5. Promotion to `stable` is planned after one minor cycle of operator feedback (mirrors the v5.1 → v5.4 promotion cadence used for `SAST-SEMGREP-064`).

## Quickstart

```bash
pip install 'oss-policy-kit[iac]'                                  # one-time, brings python-hcl2
python -m oss_policy_kit scan-iac --target .                       # writes evidence
python -m oss_policy_kit evaluate \
  --target . \
  --profile iac-terraform-baseline-1 \
  --output-dir ./out/iac-baseline \
  --fail-on degraded
```

The bundled profile is **advisory** by design (`posture: advisory`, recommended `--fail-on degraded`). Use it as a scorecard alongside `*-release-hardening-3` profiles, not as a sole release gate.

## CLI flags

| Flag | Default | Purpose |
| --- | --- | --- |
| `--target / -t` | `.` | Repository root to scan. |
| `--include` | `**/*.tf` | Comma-separated glob patterns (e.g. `terraform/**/*.tf,modules/**/*.tf`). |
| `--exclude` | (none) | Comma-separated glob patterns matched against full paths. |
| `--timeout` | `120` | Wall-clock timeout in seconds (parser is in-process; included for symmetry). |
| `--format` | `human` | Stdout summary format: `human` (one-line) or `json` (full evidence echo). |

The scan **always skips** `.git`, `.terraform`, `node_modules`, `.venv`, `venv`, `__pycache__`, `dist`, `build`, and `.oss-policy-kit` — vendored modules and caches never pollute findings.

## Honesty contract

- **Parser missing → not_available.** The kit imports `hcl2` lazily; without the iac extra installed, `scan-iac` exits 0 and writes evidence with `status: not_available`. Every `IAC-TF-*` evaluator then reports `manual-review-required` (does not trip `--fail-on fail`). This is by design.
- **File parse failure → diagnostics, not crash.** A single malformed `.tf` file is recorded under `diagnostics.parse_errors` and the scan continues with the rest. The evidence still writes with `status: ok`.
- **Best-effort detection.** The rule pack uses string-and-attribute matching, not full data-flow analysis. False positives are possible on dev/sandbox layouts; combine with `--exclude` globs and the kit's existing waivers (`GOV-WAIV-014`).
- **No cloud APIs are called.** Everything runs on the clone. Cloud-side posture stays in `collect-evidence` territory.

## Integrating with existing profiles

`iac-terraform-baseline-1` is multi-platform (no platform prefix). Three composition patterns work well:

1. **Standalone IaC scorecard.** Run on its own at PR time; leave the platform ladders alone.
2. **Stacked with a level-3 hard-gate.** Run both: `--profile iac-terraform-baseline-1 --fail-on degraded` and separately `--profile aws-release-hardening-3 --fail-on fail`. Keep them in different jobs so an IaC advisory failure does not block release.
3. **Custom external profile.** Compose only the rules you need plus your own controls. Reuse the `IAC-TF-*` IDs from the bundled catalog.

## Waiving a finding

Findings are control-level (one finding per resource per rule). Waive at the control level via `waivers.yaml`:

```yaml
- id: WAIVER-IAC-TF-008-LEGACY
  control_id: IAC-TF-008
  reason: legacy modules pre-tagging policy; tracked in TICKET-1234
  owner: platform-team
  expires_on: 2026-09-30
```

The waiver flips the control to `waived` in the report; the underlying findings are still visible in the evidence JSON for audit. Waivers must have an `expires_on` to keep the kit honest.

## Roadmap

- v5.6+: Pulumi / CloudFormation / Bicep parsers; promotion of `IAC-TF-*` to `stable`; expansion of the encryption/audit rule sets.
- Plugin entry points for custom IaC rules will only be exposed after the core 12 stabilize, to avoid freezing an under-baked API.
