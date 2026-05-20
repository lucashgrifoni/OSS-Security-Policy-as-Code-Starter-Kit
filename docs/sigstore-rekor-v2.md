# Sigstore Rekor v2 (tile-based transparency log)

> Rekor v2 (GA, tile-based via Trillian-Tessera) changes the shape of inclusion
> proofs versus Rekor v1. The kit records the verification origin so adopters can
> distinguish a Rekor v2 tile-inclusion verification from earlier methods.
> See ADR-025 (PR-24).

## What changed

The three provenance evidence schemas
(`evidence-{github,aws,azure}-provenance-artifact.schema.json`) gained a new
`verification.source` enum value: **`rekor-v2-tile-inclusion`**.

The full enum is now:

```
npm-trusted-publishing | pypi-trusted-publishing | rubygems-trusted-publishing |
crates-trusted-publishing | github-attestation | sigstore-bundle |
rekor-v2-tile-inclusion | manual
```

`PROV-VERIFY-061` surfaces `verification.source` in its PASS reason text; it does
not gate on the specific value, so this addition is non-breaking.

## Migration note

If you previously recorded Rekor v1 inclusion as `sigstore-bundle` or `manual`,
you can set `verification.source: rekor-v2-tile-inclusion` once your verification
runs against a Rekor v2 instance (e.g. `log2025-…rekor.sigstore.dev`). The value
is optional; omitting it preserves prior behaviour.
