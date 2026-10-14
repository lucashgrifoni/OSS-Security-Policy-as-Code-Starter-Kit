# Repository wiki brief

Document the OSS Security Policy as Code Starter Kit from the current source and focused tests.

- Write the wiki in English, matching the repository's public documentation.
- Explain the project as a local repository assessment and policy kit. Do not claim certification, legal compliance, vulnerability absence, or proof of live enforcement from static files.
- Treat the current source as authoritative. Separate implemented behavior, external inputs, optional live collectors, policy decisions, and documented limitations.
- Cover the evaluation flow, profiles and controls, evidence and assurance, waivers and gate outcomes, CLI and CI consumption, collectors and scanner adapters, findings and supply-chain exports, extensions, and testing.
- Prefer bounded repo:// source spans for independently falsifiable claims. Use focused tests to explain invariants; a test's existence is not proof that it was executed.
- Keep existing docs under docs/ as user-facing reference material; link to them rather than duplicating their exhaustive command and control lists.
- Do not include local paths, user-specific evidence, credentials, private operational notes, or agent configuration in public wiki content.
- Read boundaries are defined by .openwikiignore. Public synthetic examples and their documented limitations may be referenced from source and tests.
- Do not change application code, policy data, workflow execution, branch protections, release settings or version stamps while generating the wiki.
- No scheduled generation, auto-merge or external deployment is part of this initial pilot.
