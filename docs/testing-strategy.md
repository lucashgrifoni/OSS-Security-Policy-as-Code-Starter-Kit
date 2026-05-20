# Testing Strategy

## Layers

1. **Unit** (`tests/unit/`) - fast, deterministic checks for isolated behavior.
2. **Application** (`tests/application/`) - engine, evaluators, reporting, profile drift, and contracts.
3. **CLI** (`tests/cli/`) - subcommand behavior, flags, error handling, and compatibility surfaces.
4. **Infrastructure** (`tests/infrastructure/`) - workflow, packaging, and CI/CD structure checks.
5. **Integration** (`tests/integration/`) - end-to-end behavior against representative local fixtures.
6. **Property** (`tests/property/`) - Hypothesis-generated inputs for invariants and edge cases.

## Property-Based Testing

Property tests catch edge cases that example-based tests are unlikely to enumerate. Current coverage:

- Waiver expiry semantics across past, future, datetime-shaped, and invalid date strings.
- ProfileSpec loading for generated external profile YAML.
- ControlSpec catalog loading across assurance, lifecycle, and weight combinations.
- EvalOutcome JSON roundtrip for every status and evidence collection method.
- Evaluation report schema roundtrip for contracts `1.0`, `0.3`, `0.2`, and `2.0`.

Run locally:

```bash
python -m pytest tests/property/
```

Run with Hypothesis statistics:

```bash
python -m pytest tests/property/ --hypothesis-show-statistics
```

## Guardrails

- Property tests must stay deterministic enough for CI; use bounded `max_examples` and `deadline=None` for engine-level tests.
- Generated inputs should assert concrete invariants, not only non-null outputs.
- Network, cloud, registry, Docker daemon, and live GitHub API calls stay out of property tests.
- When Hypothesis finds a counterexample, add a focused regression test if the behavior is security-sensitive or user-visible.
