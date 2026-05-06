// Final CTA + Footer

function CTASection() {
  return (
    <section id="cta" className="relative scroll-mt-24 py-24 md:py-32">
      <div className="mx-auto max-w-6xl px-4 sm:px-6">
        <Reveal>
          <div className="relative overflow-hidden rounded-[2rem] border border-signal/30 bg-gradient-to-br from-signal/15 via-ink-soft/70 to-ink-deep p-10 shadow-glow md:p-16">
            <div className="pointer-events-none absolute -right-24 -top-24 h-72 w-72 rounded-full bg-signal/30 blur-[100px]" />
            <div className="pointer-events-none absolute -bottom-28 -left-20 h-80 w-80 rounded-full bg-slate/30 blur-[110px]" />

            {/* Animated grid surface */}
            <div
              className="pointer-events-none absolute inset-0 opacity-30"
              style={{
                backgroundImage:
                  "linear-gradient(rgba(8,185,139,0.10) 1px, transparent 1px), linear-gradient(90deg, rgba(8,185,139,0.10) 1px, transparent 1px)",
                backgroundSize: "24px 24px",
                maskImage:
                  "radial-gradient(ellipse 90% 80% at 30% 30%, black 30%, transparent 80%)",
                WebkitMaskImage:
                  "radial-gradient(ellipse 90% 80% at 30% 30%, black 30%, transparent 80%)",
              }}
            />

            <div className="relative max-w-3xl">
              <p className="font-mono text-xs uppercase tracking-[0.3em] text-signal/90">
                Next step
              </p>
              <h2 className="mt-4 text-3xl font-semibold tracking-tight text-mist md:text-5xl">
                Run the self-check, compare the fixtures, and use the first
                report as your{" "}
                <span className="text-gradient">backlog</span>.
              </h2>
              <p className="mt-6 text-base leading-relaxed text-slate md:text-lg">
                Start with{" "}
                <code className="rounded bg-ink-deep/80 px-1.5 py-0.5 font-mono text-sm text-signal">
                  python -m oss_policy_kit profiles
                </code>
                , then evaluate your clone with{" "}
                <code className="rounded bg-ink-deep/80 px-1.5 py-0.5 font-mono text-sm text-signal">
                  github-level-1
                </code>{" "}
                or the recommended profile. If you need a fast demo, the
                repository already ships hardened and vulnerable examples.
              </p>
              <div className="mt-10 flex flex-wrap gap-4">
                <MagneticButton href={REPO_URL} variant="primary" external>
                  Open repository
                  <Icon name="arrow" className="h-4 w-4" />
                </MagneticButton>
                <MagneticButton href={DOCS_URL} variant="ghost" external>
                  <Icon name="book" className="h-4 w-4" />
                  Open docs
                </MagneticButton>
              </div>
            </div>
          </div>
        </Reveal>
      </div>
    </section>
  );
}

function SiteFooter() {
  return (
    <footer className="relative border-t border-white/10 py-12 text-sm text-slate">
      <div className="mx-auto flex max-w-6xl flex-col gap-6 px-4 sm:flex-row sm:items-center sm:justify-between sm:px-6">
        <div className="flex items-start gap-3">
          <span className="flex h-9 w-9 items-center justify-center rounded-lg border border-signal/40 bg-signal/15 font-mono text-[10px] font-bold text-signal shadow-glow-sm">
            OSS
          </span>
          <p className="max-w-xl leading-relaxed">
            Python package and GitHub Pages site for local OSS security
            evaluation. Apache-2.0. Evidence first, explicit limits, and no
            certification theater.
          </p>
        </div>
        <div className="flex flex-wrap gap-4 font-mono text-xs text-steel">
          <a className="transition hover:text-signal" href={REPO_URL} target="_blank" rel="noreferrer noopener">
            Repository
          </a>
          <span aria-hidden="true">·</span>
          <a className="transition hover:text-signal" href={DOCS_URL} target="_blank" rel="noreferrer noopener">
            Docs
          </a>
          <span aria-hidden="true">·</span>
          <a className="transition hover:text-signal" href="#quickstart">
            Quickstart
          </a>
          <span aria-hidden="true">·</span>
          <a className="transition hover:text-signal" href="#cta">
            Get started
          </a>
        </div>
      </div>
    </footer>
  );
}

window.CTASection = CTASection;
window.SiteFooter = SiteFooter;
