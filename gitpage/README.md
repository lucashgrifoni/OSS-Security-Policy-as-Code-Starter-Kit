# gitpage - optional GitHub Pages site

This directory contains the optional front-end site for the project. It is a static
single-page React app served as plain files; **no build step is required**. It is **not**
part of the Python package published as `oss-policy-kit`.

## What it is for

- Project website and public landing page
- Product positioning and onboarding content
- GitHub Pages deployment from `gitpage/`

## What it is not

- Not part of the Python wheel or sdist
- Not required to use the CLI
- Not required for the Python test suite

## Toolchain (none required to deploy)

The page loads React + Babel + Tailwind via CDN at runtime. There is no `npm install`,
no compile step, no bundler. Files served as-is:

- `index.html` - entry point (loads CDN scripts and registers `<script type="text/babel">` parts)
- `app.jsx` - top-level React app
- `parts/*.jsx` - section components (background, header, hero, sections-a/b/c, footer-cta, primitives)
- `styles.css` - additional styles on top of Tailwind CDN

## Local usage

Serve `gitpage/` with any static HTTP server, then open the printed URL:

```bash
# Python 3 stdlib server
cd gitpage
python -m http.server 8080

# Node.js alternative (no install)
cd gitpage
npx --yes http-server -p 8080
```

Opening `gitpage/index.html` directly via `file://` may fail because some browsers refuse to
load `<script src="parts/...jsx">` from the local filesystem; an HTTP server is the simplest
fix.

## CI behavior

The site is deployed by `.github/workflows/deploy-github-pages.yml`. The workflow uploads
`gitpage/` directly as a Pages artifact on push to `master` (paths-filtered to `gitpage/**`).
No build job is needed; no Node toolchain is invoked.

Important boundaries:

- Python quality, typing, tests, packaging, and security checks run in the repository root workflows
- the Pages workflow runs only for `gitpage/**` and the Pages workflow file itself
- the Python package does not depend on Node tooling

## Residual risks

The gitpage site is a static marketing surface. It is intentionally decoupled from the
Python package and CI merge gates, and ships with two acknowledged supply-chain risks
that downstream consumers should be aware of:

- **Tailwind CDN is unpinned.** `index.html` loads `https://cdn.tailwindcss.com` without a
  fixed version and without Subresource Integrity. This is a CDN-trust risk on the marketing
  page only. It does not affect the Python wheel/sdist, the CLI, the SARIF/JSON reports, or
  any CI gate. Pinning Tailwind to a specific version with SRI is tracked as a `v5.x.y`
  follow-up and explicitly **not** a v5.0.0 hard requirement.
- **React, ReactDOM, and Babel standalone are pinned.** `index.html` loads them via `unpkg.com`
  at fixed versions (React 18.3.1, Babel standalone 7.29.0) and ships SRI `integrity`
  attributes on each script tag, so those CDN fetches fail closed if upstream content
  changes.

If you are evaluating this kit for adoption, the trust boundary that matters is the wheel
and sdist signed/checked under `dist/`, the CycloneDX SBOM under `artifacts/sbom.cyclonedx.json`,
and the workflow files pinned to immutable SHAs. The gitpage site is outside that boundary
by design.

## Source of truth

For release confidence, the authoritative answer to "is the site live?" is the GitHub Pages
deployment status on GitHub Actions plus the published URL at
`https://lucashgrifoni.github.io/OSS-Security-Policy-as-Code-Starter-Kit/`.
