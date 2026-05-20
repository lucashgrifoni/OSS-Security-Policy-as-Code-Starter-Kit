# Sample Reports

These reports are generated from the bundled example repositories with `github-level-1`.
They are meant for quick inspection in GitHub without running the CLI first.

## Hardened Example

- [Markdown report](hardened/evaluation-report.md)
- [JSON report](hardened/evaluation-report.json)

Command:

```bash
python -m oss_policy_kit evaluate \
  --target ./examples/hardened-repo \
  --profile github-level-1 \
  --output-dir ./docs/sample-reports/hardened \
  --summary-only
```

Expected shape: 14 `pass`, 0 `fail`.

## Vulnerable Example

- [Markdown report](vulnerable/evaluation-report.md)
- [JSON report](vulnerable/evaluation-report.json)

Command:

```bash
python -m oss_policy_kit evaluate \
  --target ./examples/vulnerable-repo \
  --profile github-level-1 \
  --output-dir ./docs/sample-reports/vulnerable \
  --summary-only
```

Expected shape: multiple `fail` findings and remediation text per control. This run intentionally does not use `--fail-on fail` so the sample report files are still written.
