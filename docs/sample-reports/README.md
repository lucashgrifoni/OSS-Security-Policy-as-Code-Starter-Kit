# Sample Reports

These reports are generated from the bundled example repositories with `github-level-1`.
They are meant for quick inspection in GitHub without running the CLI first.

They are on the `reports/2.0` contract — the only contract the kit emits or reads since
v9.0.0 — and are regenerated whenever the report shape changes, so what is checked in here
is what the current CLI actually writes. Both runs are stamped with
`SOURCE_DATE_EPOCH=1785974400` (2026-08-06T00:00:00Z), which the kit honors for every
outcome-affecting clock read.

**Reproducing these bytes.** Export that variable and regenerate **on Linux** and the output
is byte-identical to what is checked in — these files are produced by the release workflow on
an Ubuntu runner. Regenerating on Windows gives you the same report with one difference, and
it is in the next paragraph.

Evidence references are redacted to their final component. A shareable report never carries
the directory chain of the machine it was produced on — that is the same redaction any adopter
gets by default. The marker is written against the root style of the path being redacted:

| Path being redacted | Rendered as |
| --- | --- |
| POSIX root (`/srv/build/repo/SECURITY.md`) | `<redacted-absolute>SECURITY.md` |
| Windows drive or UNC (`D:\build\repo\SECURITY.md`) | `<redacted-absolute>/SECURITY.md` |

Both forms mean the same thing and both are part of the `reports/2.0` surface. The separator
is not a path component; it is a historical difference in how the two roots have always been
rendered, kept so an existing consumer's parsing does not break.

## Hardened Example

- [Markdown report](hardened/evaluation-report.md)
- [JSON report](hardened/evaluation-report.json)

Command:

```bash
python -P -m oss_policy_kit evaluate \
  --target ./examples/hardened-repo \
  --profile github-level-1 \
  --output-dir ./docs/sample-reports/hardened \
  --summary-only
```

Expected shape: `{"PASS": 14}` — 14 of 14 controls satisfied.

## Vulnerable Example

- [Markdown report](vulnerable/evaluation-report.md)
- [JSON report](vulnerable/evaluation-report.json)

Command:

```bash
python -P -m oss_policy_kit evaluate \
  --target ./examples/vulnerable-repo \
  --profile github-level-1 \
  --output-dir ./docs/sample-reports/vulnerable \
  --summary-only
```

Expected shape: `{"FAIL": 11, "PASS": 2, "UNKNOWN": 1}`, with remediation text on each failing
control. This run intentionally does not pass `--fail-on fail`, so the sample report files are
still written instead of the gate stopping the run at exit 1.
