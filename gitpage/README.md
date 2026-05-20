# gitpage - optional GitHub Pages site

This directory contains the optional front-end site for the project. It is a
static single-page React app served as plain files after the committed CSS and
JavaScript bundle are built. It is **not** part of the Python package published
as `oss-policy-kit`.

## What it is for

- Project website and public landing page
- Product positioning and onboarding content
- GitHub Pages deployment from `gitpage/`

## What it is not

- Not part of the Python wheel or sdist
- Not required to use the CLI
- Not required for the Python test suite

## Toolchain

The page serves committed static files. Tailwind is built locally into
`tailwind.css` and JSX is bundled into `bundle.js` instead of loading build
tools in the browser.

- `index.html` - entry point (loads committed CSS, pinned React/ReactDOM CDN scripts, and committed `bundle.js`)
- `tailwind.css` - generated Tailwind utilities, committed for traceability
- `site.css` - generated combined/minified CSS loaded by `index.html`
- `tailwind.config.js` / `tailwind.input.css` - Tailwind build inputs
- `build-js.mjs` - esbuild transform for the static JSX bundle
- `bundle.js` - generated site JavaScript, committed for GitHub Pages
- `app.jsx` - top-level React app
- `parts/*.jsx` - section components (background, header, hero, sections-a/b/c, footer-cta, primitives)
- `styles.css` - additional custom styles on top of generated Tailwind CSS
- `screenshots/*.png` - copied public report screenshots used by the Sample Output section

When changing Tailwind classes or JSX, rebuild the generated static assets:

```bash
cd gitpage
npm ci
npm run build
```

The npm scripts call Node entrypoints directly so they work from Windows paths
that contain `&`.

## Content sections

The site order is:

1. Hero with pass/fail policy-gate value proposition.
2. Problem statement.
3. Comparison matrix.
4. Scope and workflow.
5. Sample output screenshots.
6. Quickstart, capabilities, profiles, evaluation states, differentiators, signals.
7. Roadmap and final CTA.

Keep comparison wording factual and non-adversarial. Do not add SLSA L3 wording unless the release workflow produces verifier-backed SLSA provenance.

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

Opening `gitpage/index.html` directly via `file://` is not the recommended
preview path; an HTTP server mirrors the GitHub Pages deployment shape.

## CI behavior

The site is deployed by `.github/workflows/deploy-github-pages.yml`. The workflow uploads
`gitpage/` directly as a Pages artifact on push to `master` (paths-filtered to `gitpage/**`).
No Node toolchain is invoked during deploy; `site.css` and `bundle.js` must
already be committed.

Important boundaries:

- Python quality, typing, tests, packaging, and security checks run in the repository root workflows
- the Pages workflow runs only for `gitpage/**` and the Pages workflow file itself
- the Python package does not depend on Node tooling

## Residual risks

The gitpage site is a static marketing surface. It is intentionally decoupled
from the Python package and CI merge gates. Runtime CDN exposure is limited to
React and ReactDOM:

- **Tailwind is bundled.** `index.html` loads committed `site.css`; no Tailwind runtime CDN is used.
- **Runtime CSS is combined.** `index.html` loads committed `site.css`, which
  combines the generated Tailwind output and local custom CSS.
- **JSX is bundled.** `index.html` loads committed `bundle.js`; Babel standalone
  is not loaded at runtime.
- **React and ReactDOM are pinned.** `index.html` loads them via `unpkg.com` at
  fixed React 18.3.1 URLs and ships SRI `integrity` attributes on each script
  tag, so those CDN fetches fail closed if upstream content changes.

If you are evaluating this kit for adoption, the trust boundary that matters is the wheel
and sdist signed/checked under `dist/`, the CycloneDX SBOM under `artifacts/sbom.cyclonedx.json`,
and the workflow files pinned to immutable SHAs. The gitpage site is outside that boundary
by design.

## Source of truth

For release confidence, the authoritative answer to "is the site live?" is the GitHub Pages
deployment status on GitHub Actions plus the published URL at
`https://lucashgrifoni.github.io/OSS-Security-Policy-as-Code-Starter-Kit/`.
