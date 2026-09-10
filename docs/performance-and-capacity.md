# Performance and capacity

What this CLI costs to run, how that cost grows with the repository it is pointed at, and where
the limits are. Every number here was measured on the environment recorded at the bottom; none
is extrapolated unless the row says so.

This is a command-line tool and a container image, not a service. There is no request rate, no
connection pool, and no queue. The workloads that matter are the ones CI actually runs: one
`evaluate` per repository, `evaluate-many` across a monorepo, and the `scan-*` parsers over a
working tree.

## Where the time goes

For a repository of any ordinary size, **most of the wall clock is interpreter start plus
import**, not the analysis:

| Command | Repository | Process wall | Of which, actual work |
|---|---|---:|---:|
| `evaluate --profile github-level-1` | 1 file | 1.10s | 0.084s |
| `evaluate --profile github-level-1` | 597 files | 1.08s | 0.101s |
| `evaluate --profile github-level-1` | 5,416 files | 1.13s | 0.136s |
| `evaluate --profile github-level-1` | 21,074 files | 1.23s | 0.241s |
| `evaluate --profile github-level-3` | 597 files | 1.20s | 0.195s |

A 21,000-file repository costs 0.16s more analysis than an empty one. Pointing the kit at a
bigger repository is close to free; **starting the process is what you pay for**, so a CI job
that calls the CLI once per repository is far cheaper than one that calls it per directory.

Startup itself depends on what else is installed in the environment:

| Environment | `--help` wall |
|---|---:|
| Clean `pip install oss-policy-kit` | 0.41s |
| A development virtualenv that also has `jsonschema[format-nongpl]` | 1.14s |

The 0.73s difference is one transitive import (`rfc3987_syntax`, pulled in by
`jsonschema`'s optional format checkers, which some dev tools install). The kit does not depend
on it, and an adopter installing the package normally does not get it. If your own environment
is slow to start, check whether something else put that extra there.

## Scanner cost by repository size

Measured on synthetic trees; `--timeout` left at its default. Times are the in-process scan,
excluding interpreter start.

| Scanner | 597 files | 5,416 files | 21,074 files | Peak RSS at 21,074 |
|---|---:|---:|---:|---:|
| `scan-iac` | 0.079s | 0.395s | 0.99s | 73 MiB |
| `scan-k8s` | 0.068s | 0.348s | 1.01s | 63 MiB |
| `scan-cfn` | 0.061s | 0.346s | 1.06s | 60 MiB |
| `scan-bicep` | 0.012s | 0.043s | 0.14s | 59 MiB |
| `scan-pulumi` | 0.17s | 1.69s | 5.4s | 99 MiB |

`scan-pulumi` is the expensive one and the reason is its include pattern: it matches
`**/*.py`, so on a Python repository it parses **every** source file to decide whether it
imports Pulumi. On a 20,000-module tree that is 20,000 AST parses. Narrow it with `--include`
when your Pulumi program lives in a known directory.

Memory is flat in repository size for every scanner. It is **not** flat in the size of any one
file, which is the next section.

## One process for many repositories

`evaluate-many` pays the interpreter and import cost once and then amortises it:

| Monorepo | Process wall | Of which, work | Per repository |
|---|---:|---:|---:|
| 5 repositories | 1.20s | 0.15s | 29ms |
| 25 repositories | 1.49s | 0.43s | 17ms |
| 100 repositories | 2.53s | 1.49s | 15ms |

Memory stays at 62 MiB across all three. The marginal cost of a repository settles around 15ms,
so **100 repositories in one `evaluate-many` cost 2.5s where 100 separate `evaluate` calls cost
about 109s** -- roughly 43x, and the whole difference is process startup. If you are looping the
CLI over directories in a shell script, this is the change worth making.

(These three rows were measured while the test suite was running on the same machine, so they
are upper bounds; the others were measured on an otherwise idle machine.)

## The limit that actually bites: one very large file

`evaluate` reads each CI configuration file whole. Cost is linear in the size of the largest
file, with a large constant:

| Largest workflow YAML | `evaluate` work | Peak RSS |
|---:|---:|---:|
| 3 KiB (normal) | 0.12s | 62 MiB |
| 0.92 MiB | 1.23s | 96 MiB |
| 9.42 MiB | 12.8s | 411 MiB |
| 47.85 MiB | 57.7s | 1,777 MiB |

Two constants fall out of those three points and hold across the whole range: roughly
**1.2 seconds and 36 MiB of resident memory per MiB of YAML**, on top of a 62 MiB floor. The
amplification is the parsed object graph, not the file buffer.

`evaluate` has no `--timeout` and applies no size cap to repository-controlled CI files. (The
size caps in `input_limits` cover the documents *you* pass on the command line -- evidence,
SARIF, scorecard, waivers, config -- not files discovered inside `--target`.)

**Derived, not measured:** on a runner with 7 GiB available, that ratio puts the
out-of-memory point near a **175 MiB single YAML file**. Nothing that large was executed; the
figure is a straight-line reading of the three measurements above and should be treated as an
order of magnitude, not a threshold.

## Capacity summary

| Workload | Sustained | Validated peak | Work time | Peak RSS | First limit |
|---|---|---|---:|---:|---|
| `evaluate`, one repository | any repo under ~20k files | 21,074 files | 0.24s | 62 MiB | process startup |
| `evaluate-many`, monorepo | 100 repositories | 100 repositories | 1.5s | 62 MiB | per-repository work, ~15ms each |
| `scan-iac` / `scan-k8s` / `scan-cfn` | ~20k files | 21,074 files | ~1.0s | 73 MiB | file count |
| `scan-pulumi` | ~5k Python files | 21,074 files | 5.4s | 99 MiB | one AST parse per `.py` |
| `evaluate` with one huge CI file | files under ~10 MiB | 47.85 MiB | 57.7s | 1.78 GiB | memory, ~36x file size |

Headroom, `PROPOSED` (no SLO exists for this project; these are candidates, not commitments):

- Keep the largest single CI YAML in a scanned repository **under 10 MiB**. That holds
  `evaluate` under ~13s and ~410 MiB, which leaves a 7 GiB runner roughly 94% of its memory.
- Budget **2 minutes** for a `scan-*` on a repository of 20,000 files, against ~2s measured --
  about 60x headroom for a slower runner and a cold page cache.
- Treat any repository over 50,000 files or any single CI file over 25 MiB as untested here.

## Running several invocations at once

The CLI is single-threaded; concurrency means running more than one process. Twelve concurrent
`evaluate` runs against the same target finished in 1.88s wall against 1.09s for a single run,
and all twelve reports were identical once the timestamp and target path were normalised.

Report writing is atomic (write to a temporary file, then `os.replace`), so two runs sharing an
`--output-dir` leave a complete report from one of them rather than a half-written file. Twelve
concurrent runs sharing one directory all exited 0 and left valid JSON.

**Scanner evidence writing is not atomic.** `write_evidence` writes
`.oss-policy-kit/evidence/*.json` in place. Twelve concurrent `scan-iac` runs against one target
produced no corrupt file in testing, but nothing in the code prevents an interleaving, so do not
point two concurrent scans at the same working tree.

## Environment these numbers came from

| Item | Value |
|---|---|
| CPU | Intel Core i9-14900KF, 24 cores / 32 threads |
| Memory | 128 GiB |
| Disk | NVMe SSD, local |
| OS | Windows 11 Pro (build 26200) |
| Runtime | CPython 3.12.10, 64-bit |
| Dataset | synthetic repositories, fixed seed, 1 to 21,074 files |
| Method | 2 warm-up runs discarded, then 3 to 9 timed runs; medians reported |
| Clock | `SOURCE_DATE_EPOCH` pinned so artifacts stay byte-identical between runs |

A CI runner has fewer, slower cores and a colder page cache, so treat these as a floor rather
than a forecast. What transfers between machines is the **shape** -- flat in repository size,
linear in the size of the largest file -- not the absolute seconds.
