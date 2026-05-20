// Sections C: Differentiators, Signals (control examples), Roadmap, Repo anatomy

const SAMPLE_REPORTS = [
  {
    title: "Hardened repository",
    caption: "github-level-1 profile, 14/14 pass in the bundled hardened fixture.",
    src: "screenshots/05-example-hardened.png",
    width: 1551,
    height: 1571,
    alt: "Hardened repository report output",
    tone: "text-signal",
  },
  {
    title: "Vulnerable repository",
    caption: "Same profile against the vulnerable fixture, with multiple failing controls.",
    src: "screenshots/06-example-vulnerable.png",
    width: 2201,
    height: 1094,
    alt: "Vulnerable repository report output",
    tone: "text-red-200",
  },
];

function SampleOutputSection() {
  return (
    <SectionShell
      id="sample-output"
      eyebrow="Sample output"
      title="The report is meant to be read by humans and kept by CI."
      subtitle="The same evaluation produces Markdown for reviewers, JSON for automation, and optional SARIF for code-scanning workflows."
    >
      <div className="grid gap-6 lg:grid-cols-2">
        {SAMPLE_REPORTS.map((item, i) => (
          <Reveal key={item.title} delay={i * 80}>
            <div className="h-full overflow-hidden rounded-3xl border border-white/10 bg-white/4 shadow-floor">
              <div className="border-b border-white/10 px-5 py-4">
                <h3 className={`text-lg font-semibold ${item.tone}`}>{item.title}</h3>
                <p className="mt-1 text-sm text-slate">{item.caption}</p>
              </div>
              <img
                src={item.src}
                alt={item.alt}
                width={item.width}
                height={item.height}
                className="block w-full bg-ink-deep object-cover"
                loading="lazy"
              />
            </div>
          </Reveal>
        ))}
      </div>
      <Reveal className="mt-8">
        <a
          href="https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/tree/master/docs/sample-reports"
          target="_blank"
          rel="noreferrer noopener"
          className="inline-flex items-center gap-2 rounded-lg border border-signal/40 bg-signal/10 px-4 py-3 text-sm font-medium text-signal transition hover:bg-signal/20"
        >
          Browse full sample reports
          <Icon name="arrow" className="h-4 w-4" />
        </a>
      </Reveal>
    </SectionShell>
  );
}

const DIFFS = [
  { icon: "layers", title: "Honest trust model", body: "The kit distinguishes clone-visible truth, self-attested evidence, and platform-only reality instead of collapsing them into one confidence claim." },
  { icon: "cpu", title: "Useful command surface", body: "The CLI does more than one demo command: it supports profile discovery, recommendation, batch evaluation, evidence scaffolding, summaries, and CI thresholds." },
  { icon: "zap", title: "Small and inspectable", body: "Controls, profiles, schemas, and parsers live in the repository in plain files, which makes the project easier to audit and easier to fork responsibly." },
  { icon: "target", title: "Built for adoption", body: "Fixtures, docs, templates, screenshots, and the GitHub Pages site make the kit easier to demo, teach, and operationalize with maintainers." },
  { icon: "sparkles", title: "One output for people and automation", body: "The same evaluation produces narrative Markdown for review and structured JSON for pipelines, integrations, and regression checks." },
];

function DifferentiatorsSection() {
  return (
    <SectionShell
      id="differentiators"
      eyebrow="Differentiators"
      title="What makes this project useful is not polish alone, but operational honesty."
      subtitle="It is designed for real maintainers and AppSec engineers who need evidence they can explain, not just output that looks impressive in a screenshot."
    >
      <div className="space-y-4 perspective-1800">
        {DIFFS.map((it, i) => (
          <Reveal key={it.title} delay={i * 70}>
            <div className="group relative flex flex-col gap-4 overflow-hidden rounded-3xl border border-white/10 bg-linear-to-r from-white/4.5 via-white/2 to-transparent p-6 transition cell-hover md:flex-row md:items-center md:gap-8 md:p-8">
              <span
                aria-hidden="true"
                className="pointer-events-none absolute right-0 top-0 h-full w-2/3 bg-[radial-gradient(circle_at_right,rgba(8,185,139,0.10),transparent_60%)] opacity-0 transition group-hover:opacity-100"
              />
              <span className="relative z-1 flex h-14 w-14 shrink-0 items-center justify-center rounded-2xl border border-signal/30 bg-signal/10 text-signal shadow-glow-sm transition group-hover:scale-105 group-hover:rotate-6">
                <Icon name={it.icon} className="h-6 w-6" strokeWidth={1.7} />
              </span>
              <div className="relative z-1 flex-1">
                <div className="flex items-center gap-3">
                  <span className="font-mono text-[10px] uppercase tracking-[0.24em] text-steel">
                    0{i + 1}
                  </span>
                  <span className="h-px flex-1 max-w-[40px] bg-white/10" />
                </div>
                <h3 className="mt-1 text-lg font-semibold text-mist md:text-xl">
                  {it.title}
                </h3>
                <p className="mt-2 text-sm leading-relaxed text-slate md:text-base">
                  {it.body}
                </p>
              </div>
              <Icon
                name="arrow"
                className="hidden md:block h-5 w-5 text-steel transition group-hover:translate-x-1 group-hover:text-signal"
              />
            </div>
          </Reveal>
        ))}
      </div>
    </SectionShell>
  );
}

const EXAMPLES = [
  "Missing SECURITY.md, CONTRIBUTING.md, or LICENSE in a repository that should expose basic governance signals.",
  "Missing CODEOWNERS, which leaves ownership and review expectations ambiguous for core paths.",
  "GitHub Actions jobs without explicit permissions, creating overly broad default token scope.",
  "Third-party GitHub Actions pinned to mutable tags instead of immutable commit SHAs.",
  "Dangerous pull_request_target patterns combined with checkout of untrusted code.",
  "Release-hardening profiles that expect branch protection, rulesets, or environment evidence but only have a local clone to inspect.",
  "Azure branch-policy or pipeline-governance expectations that cannot be proven without supplied evidence files.",
  "AWS CodeBuild or committed CodePipeline posture expected by the selected profile but missing from the evaluated artifact set.",
];

function SignalsSection() {
  return (
    <SectionShell
      id="examples"
      eyebrow="Signal library"
      title="Representative signals span governance files, workflow hygiene, and release-hardening evidence."
      subtitle="These are examples of the kinds of findings and non-pass states the bundled catalog can emit today."
    >
      <div className="columns-1 gap-4 space-y-4 md:columns-2">
        {EXAMPLES.map((text, i) => (
          <Reveal key={i} delay={(i % 4) * 60}>
            <div className="group break-inside-avoid rounded-2xl border border-white/10 bg-white/3 p-5 transition cell-hover">
              <div className="flex items-start gap-3">
                <span className="mt-0.5 inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-md border border-signal/30 bg-signal/10 text-signal shadow-glow-sm">
                  <Icon name="octagon" className="h-4 w-4" />
                </span>
                <p className="text-sm leading-relaxed text-mist/95">{text}</p>
              </div>
            </div>
          </Reveal>
        ))}
      </div>
    </SectionShell>
  );
}

const MILESTONES = [
  {
    id: "current",
    title: "Now",
    icon: "rocket",
    era: "v6.0.0 GA",
    bullets: [
      "Finish local v6.0.0 branch review and push strategy",
      "Keep reports/1.0 as default while shipping opt-in reports/2.0",
      "Ship the landed v6 profile expansion: AI/LLM, EU AI Act, SLSA Source L1, GitLab L2, OSS publish readiness",
      "Publish release evidence: PyPI attestations, signed GHCR image, SBOM, changelog, migration guide, sample reports",
    ],
  },
  {
    id: "next",
    title: "Next",
    icon: "shield",
    era: "v6.x",
    bullets: [
      "Refactor the large evaluator module into smaller family modules",
      "Add property-based tests for control/profile YAML, waivers, and report schema edge cases",
      "Add a navigable control catalog on GitHub Pages",
      "Expand public comparison docs and first-adopter tutorial assets",
      "Publish threat model and supply-chain pipeline audit evidence",
    ],
  },
  {
    id: "later",
    title: "Later",
    icon: "satellite",
    era: "v7+",
    bullets: [
      "Explore CEL/Rego export as an integration layer for policy engines",
      "Add SPDX SBOM export alongside CycloneDX-focused flows",
      "Add diff-catalogs for control/profile deltas between kit versions",
      "Add optional structured JSON logging and richer CLI explain commands",
      "Publish maintainer/community signals when there is real adoption evidence",
    ],
  },
  {
    id: "guardrails",
    title: "Guardrails",
    icon: "network",
    era: "Stays true",
    bullets: [
      "No fake remote verification from clone-only data",
      "No universal scanner claims or certification theater",
      "No shift toward SaaS control planes at the expense of evidence quality and inspectability",
    ],
  },
];

function RoadmapSection() {
  return (
    <SectionShell
      id="roadmap"
      eyebrow="Roadmap"
      title="The roadmap is conservative: deepen evidence quality without losing scope discipline."
      subtitle="What matters here is not surface area. It is keeping the kit useful, explainable, and safe to trust for the things it claims to evaluate."
    >
      <div className="relative">
        <div
          className="absolute bottom-6 left-14 top-6 hidden w-px md:block flow-connector"
          aria-hidden="true"
        />
        <div className="space-y-10 md:space-y-14">
          {MILESTONES.map((m, i) => (
            <Reveal key={m.id} delay={i * 80}>
              <div className="relative md:pl-36">
                <div className="mb-4 flex items-center gap-4 md:absolute md:left-0 md:top-1/2 md:mb-0 md:w-28 md:-translate-y-1/2 md:flex-col md:items-center md:gap-3">
                  <span className="relative flex h-12 w-12 items-center justify-center rounded-2xl border border-signal/40 bg-signal/12 text-signal shadow-glow-sm">
                    <Icon name={m.icon} className="h-5 w-5" />
                    <span className="absolute -inset-1.5 rounded-2xl border border-signal/15" />
                  </span>
                  <span className="text-center font-mono text-[10px] uppercase tracking-[0.24em] text-steel">
                    {m.era}
                  </span>
                </div>
                <TiltCard className="" intensity={3}>
                  <div className="flex flex-wrap items-end gap-3">
                    <h3 className="text-2xl font-semibold text-mist">
                      {m.title}
                    </h3>
                    <span className="rounded-md border border-white/10 px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider text-slate">
                      directional
                    </span>
                  </div>
                  <ul className="mt-6 space-y-3">
                    {m.bullets.map((b) => (
                      <li
                        key={b}
                        className="flex gap-3 text-sm leading-relaxed text-slate md:text-base"
                      >
                        <span className="mt-2 h-1.5 w-1.5 shrink-0 rounded-full bg-signal" />
                        <span>{b}</span>
                      </li>
                    ))}
                  </ul>
                </TiltCard>
              </div>
            </Reveal>
          ))}
        </div>
      </div>
    </SectionShell>
  );
}

const BLOCKS = [
  { id: "package", label: "src/oss_policy_kit", hint: "CLI, engine, evaluators, parsers" },
  { id: "data", label: "src/.../data", hint: "Controls, profiles, schemas" },
  { id: "docs", label: "docs", hint: "Adoption, architecture, release notes" },
  { id: "examples", label: "examples", hint: "Hardened and vulnerable fixtures" },
  { id: "tests", label: "tests", hint: "Regression coverage for package behavior" },
  { id: "templates", label: "templates", hint: "Governance starter files and examples" },
  { id: "waivers", label: "waivers", hint: "Waiver examples and exception flows" },
  { id: "gitpage", label: "gitpage", hint: "Public project site for GitHub Pages" },
];

function RepoAnatomySection() {
  return (
    <SectionShell
      id="architecture"
      eyebrow="Repository anatomy"
      title="The repository already packages code, policy data, fixtures, docs, and the public site."
      subtitle="That makes the project easier to validate end to end: the kit can test itself, document itself, and demonstrate itself from one source tree."
    >
      <Reveal>
        <div className="relative overflow-hidden rounded-3xl border border-white/10 bg-ink-deep/80 p-6 md:p-10 shadow-floor">
          <div className="pointer-events-none absolute inset-0 opacity-50">
            <div
              className="absolute inset-0"
              style={{
                backgroundImage:
                  "linear-gradient(rgba(8,185,139,0.08) 1px, transparent 1px), linear-gradient(90deg, rgba(8,185,139,0.08) 1px, transparent 1px)",
                backgroundSize: "32px 32px",
                maskImage:
                  "radial-gradient(ellipse 80% 80% at 50% 50%, black 30%, transparent 80%)",
                WebkitMaskImage:
                  "radial-gradient(ellipse 80% 80% at 50% 50%, black 30%, transparent 80%)",
              }}
            />
          </div>

          <div className="relative grid gap-4 sm:grid-cols-2 lg:grid-cols-4 perspective-1800">
            {BLOCKS.map((b, i) => (
              <Reveal key={b.id} delay={i * 50}>
                <div className="group relative h-full rounded-2xl border border-white/10 bg-white/4 p-5 backdrop-blur transition cell-hover">
                  <div className="flex items-start justify-between gap-2">
                    <Icon name="folder" className="h-4 w-4 text-signal/80" />
                    <span className="font-mono text-[10px] text-steel">{String(i + 1).padStart(2, "0")}</span>
                  </div>
                  <p className="mt-3 font-mono text-sm font-semibold text-signal wrap-break-word">{b.label}/</p>
                  <p className="mt-2 text-xs leading-relaxed text-slate">{b.hint}</p>
                </div>
              </Reveal>
            ))}
          </div>

          <p className="relative mt-8 max-w-3xl text-sm text-slate">
            The repository is intentionally self-contained. Package logic,
            policy payloads, evidence schemas, fixtures, and documentation all
            live together so maintainers can see exactly what the kit ships
            today.
          </p>
        </div>
      </Reveal>
    </SectionShell>
  );
}

window.SampleOutputSection = SampleOutputSection;
window.DifferentiatorsSection = DifferentiatorsSection;
window.SignalsSection = SignalsSection;
window.RoadmapSection = RoadmapSection;
window.RepoAnatomySection = RepoAnatomySection;
