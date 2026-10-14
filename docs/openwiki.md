# Repository wiki with OpenWiki

The repository's [OpenWiki quickstart](../openwiki/quickstart.md) links architecture, evidence, policy and workflow pages. Use it to locate relevant source and tests; the guides under `docs/` remain the full user reference.

The wiki was initialized with OpenWiki 0.7.2 through its coding-agent lifecycle. Markdown, source-linked claims and completion metadata live in `openwiki/`. Review consequential claims against current code; verification metadata records the generation checks, not a security certification of the kit.

## Local setup

OpenWiki 0.7.2 requires Node.js 22.22.0 or newer. Install the pinned CLI, then its project-scoped Codex integration from this Git repository:

```sh
npm install --global openwiki@0.7.2
openwiki integrations install codex --project .
```

Restart Codex in this repository so it loads the integration. Ask it to initialize the wiki only for a fresh repository wiki; for this existing wiki, ask it to update from source changes. The integration uses the coding agent's authenticated session and repository tools. Refer to the [upstream guide](https://github.com/langchain-ai/openwiki#coding-agent-integrations) for other supported hosts.

Project-local `.agents/` and `.codex/` installation state and the generated root instruction files are ignored by this repository. Keep them local. The wiki itself and its claim sidecars are versioned as documentation.

## Scope and maintenance

The brief in `openwiki/INSTRUCTIONS.md` defines priorities and output language. `.openwikiignore` defines paths the generator may not read. It excludes local credentials, private evidence and runtime state; it does not make a finding or topic disappear from other permitted source evidence.

OpenWiki owns the claims, page manifest, indexes, provenance and run checkpoints. Maintain them through its lifecycle rather than editing those records directly. Update the relevant user guide or source first, request a wiki update, then review the changed pages and instruction-file diff.

## Scheduled workflow boundary

OpenWiki 0.7.2 initialization also scaffolds `.github/workflows/openwiki-update.yml`. This repository keeps that generated file local through `.gitignore`; it is outside the initial documentation change. No scheduled OpenWiki job or auto-merge is introduced here.

Adopting CI generation requires a separate review of triggers, least-privilege permissions, provider access, tracing, cost, pinned tools and the generated PR's paths. Keep private operating-context files out of a documentation PR. The local coding-agent integration works independently of that workflow.

## Validation

Review wiki links, source references, claim status and changes to the brief or ignore file. Search and read relevant sections through the OpenWiki integration to check retrieval. After a source change, check that an update addresses the affected claims; with unchanged source, verify that a clean update leaves page content intact.

Run the repository checks in [CONTRIBUTING.md](../CONTRIBUTING.md) before proposing the change for merge. A generated wiki does not replace the kit's tests or the adopter's own validation.
