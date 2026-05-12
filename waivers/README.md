# waivers/

Two files live in this directory; do not confuse them.

## `waivers.example.yaml`

**Template** for consumers of the kit. Copy it into your own repository (typically at the repository root or any path you pass to `evaluate --waivers`) and edit to declare your real waivers. The file lists annotated, commented-out examples for common false-positive patterns so you can uncomment what applies and adjust the metadata.

## `waivers.yaml`

This project's **own** waiver file, exercised by the bundled `examples/hardened-repo` fixture and by the self-check workflows. It currently declares an empty list (`waivers: []`), which means the project itself does not waive any control. Treat it as the canonical "shape" that the kit's waiver loader accepts — but use `waivers.example.yaml` as your starting point, not this one.

## Schema

Both files follow the same shape:

```yaml
version: 1
waivers:
  - control_id: <ID>
    justification: <reason>
    owner: <email-or-team>
    status: approved | proposed | rejected
    expires_at: "YYYY-MM-DD"     # optional
    applies_to:                   # optional list of paths
      - "..."
```

See `docs/results-guide.md` and `docs/cli-reference.md` for how `--waivers` interacts with control status and the `--fail-on` policy.
