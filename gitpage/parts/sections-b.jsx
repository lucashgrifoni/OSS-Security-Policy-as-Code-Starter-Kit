// Sections B: Capabilities, Profiles (Frameworks), Evaluation states

const COMPARISON_ROWS = [
  ["Multi-platform CI/CD", "Partial", "Scanner-specific", "Generic", "Kubernetes", "Yes"],
  ["Built-in profiles", "Score model", "No", "No", "Policy-dependent", "47 dev / 38 public"],
  ["Assurance grading", "No", "No", "No", "Policy-dependent", "Yes"],
  ["Composes SARIF / JSON", "No", "n/a", "No", "No", "Yes"],
  ["Waiver registry", "No", "No", "Adopter writes", "Policy-dependent", "Yes"],
  ["CycloneDX VEX", "No", "No", "No", "No", "Yes"],
  ["Local-first default", "Mostly", "Yes", "Yes", "Yes", "Yes"],
];

function ComparisonSection() {
  const columns = ["Capability", "Scorecard", "zizmor / OSV / Gitleaks", "Conftest / OPA", "Kyverno", "OSS Policy Kit"];
  return (
    <SectionShell
      id="comparison"
      eyebrow="Comparison"
      title="The kit is a gate and composition layer, not a replacement for scanners or policy engines."
      subtitle="Scorecard, zizmor, OSV-Scanner, Gitleaks, OPA, and Kyverno remain useful. The kit sits above them when a maintainer needs one reviewable repository decision."
    >
      <Reveal>
        <div className="overflow-x-auto rounded-3xl border border-white/10 bg-white/[0.035]">
          <table className="min-w-[880px] w-full text-left text-sm">
            <thead className="border-b border-white/10 bg-ink-deep/70 text-mist">
              <tr>
                {columns.map((c, i) => (
                  <th
                    key={c}
                    scope="col"
                    className={`px-4 py-4 font-semibold ${i === columns.length - 1 ? "bg-signal/10 text-signal" : ""}`}
                  >
                    {c}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {COMPARISON_ROWS.map((row) => (
                <tr key={row[0]} className="border-b border-white/5 last:border-0">
                  <th scope="row" className="px-4 py-4 font-medium text-mist">
                    {row[0]}
                  </th>
                  {row.slice(1).map((cell, i) => (
                    <td
                      key={`${row[0]}-${i}`}
                      className={`px-4 py-4 text-slate ${i === row.length - 2 ? "bg-signal/10 font-medium text-signal" : ""}`}
                    >
                      {cell}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Reveal>
    </SectionShell>
  );
}

const CAPABILITIES = [
  { icon: "clipboard", title: "Bundled control catalog", body: "Versioned YAML control data and staged profiles define what the kit checks without hiding policy behind hard-coded heuristics." },
  { icon: "book", title: "Documented CLI surface", body: "The public contract includes evaluate, profiles, recommend-profile, evaluate-many, and scaffold-evidence." },
  { icon: "scan", title: "GitHub Actions hygiene", body: "Static workflow analysis covers governance signals, token permissions, action pinning, risky triggers, and other high-value repository checks." },
  { icon: "lock", title: "Explicit trust boundaries", body: "When branch protection, rulesets, or other platform controls cannot be proven from a clone, the kit degrades honestly instead of fabricating a pass." },
  { icon: "fileKey", title: "Structured evidence inputs", body: "Release-hardening profiles can consume schema-shaped evidence files under .oss-policy-kit/evidence/ when local files alone are not enough." },
  { icon: "package", title: "Release-hardening tracks", body: "GitHub, Azure, and AWS all ship release-oriented profile families that extend baseline checks with evidence-driven posture expectations." },
  { icon: "link", title: "OpenSSF Scorecard bridge", body: "Optional Scorecard JSON can be ingested as supplemental context without becoming a second source of truth." },
  { icon: "shield", title: "Cross-platform parsers", body: "The package includes static parsers for GitHub Actions, Azure Pipelines, and AWS CodeBuild or committed CodePipeline definitions." },
  { icon: "fileWarn", title: "Markdown + JSON reports", body: "Every run writes artifacts that work for both human review and machine consumption, with structured summaries available on stdout when needed." },
  { icon: "pull", title: "Traceable waivers", body: "Exceptions can be loaded from waivers YAML so non-pass decisions stay visible, reviewable, and time-bounded." },
  { icon: "gauge", title: "Batch evaluation", body: "Immediate child directories can be evaluated in one pass with consolidated batch reports for multi-repo or multi-app roots." },
  { icon: "fingerprint", title: "Examples, tests, and docs", body: "The repository ships fixtures, screenshots, documentation, and a regression suite so the kit can validate itself publicly." },
];

function CapabilitiesSection() {
  return (
    <SectionShell
      id="capabilities"
      eyebrow="Capability matrix"
      title="The project ships the actual pieces you need to evaluate, explain, and gate repository posture."
      subtitle="These are implementation capabilities in the repository today, not aspirational product bullets."
    >
      <div className="grid gap-5 sm:grid-cols-2 xl:grid-cols-3 perspective-1800">
        {CAPABILITIES.map((c, i) => (
          <Reveal key={c.title} delay={(i % 6) * 50}>
            <TiltCard className="h-full" intensity={6}>
              <span className="inline-flex h-10 w-10 items-center justify-center rounded-xl border border-signal/30 bg-signal/10 text-signal shadow-glow-sm">
                <Icon name={c.icon} className="h-5 w-5" />
              </span>
              <h3 className="mt-4 text-base font-semibold text-mist">{c.title}</h3>
              <p className="mt-2 text-sm leading-relaxed text-slate">{c.body}</p>
            </TiltCard>
          </Reveal>
        ))}
      </div>
    </SectionShell>
  );
}

const FRAMEWORKS = [
  {
    icon: "book2",
    name: "GitHub baseline ladder",
    code: "github-level-1..3",
    text: "The most mature path in the kit. It inspects governance files and GitHub Actions posture with increasing strictness.",
    chips: ["16-22 controls", "clone-visible", "most mature"],
    accent: "from-signal/30 to-signal/0",
  },
  {
    icon: "radar",
    name: "GitHub release hardening",
    code: "github-release-hardening-1..3",
    text: "Extends the baseline with branch protection, rulesets, environments, and secret scanning evidence flows.",
    chips: ["17-26 controls", "evidence files", "manual review if missing"],
    accent: "from-signal/25 to-signal/0",
  },
  {
    icon: "badge",
    name: "Azure tracks",
    code: "azure-level-1..3 · azure-release-hardening-1..3",
    text: "Cover clone-visible Azure Repos and Azure Pipelines signals plus optional evidence.",
    chips: ["12-17 controls", "clone + evidence", "static parsing"],
    accent: "from-slate/30 to-slate/0",
  },
  {
    icon: "github",
    name: "AWS tracks",
    code: "aws-level-1..3 · aws-release-hardening-1..3",
    text: "Cover CodeBuild, committed CodePipeline artifacts, and optional exported evidence files.",
    chips: ["11-17 controls", "clone + evidence", "static parsing"],
    accent: "from-slate/30 to-slate/0",
  },
];

function FrameworksSection() {
  return (
    <SectionShell
      id="profiles"
      eyebrow="Bundled profiles"
      title="Profile families let teams start small and harden posture without changing tools."
      subtitle="The public release line ships the v5 profile set; the v6 development branch has 47 profiles across platform, regulatory, supply-chain, AI, and release-hardening lanes."
    >
      <div className="grid gap-5 md:grid-cols-2 perspective-1800">
        {FRAMEWORKS.map((f, i) => (
          <Reveal key={f.name} delay={i * 80}>
            <TiltCard className="h-full overflow-hidden" intensity={6}>
              <div
                className={`pointer-events-none absolute -right-12 -top-12 h-44 w-44 rounded-full bg-linear-to-br ${f.accent} blur-3xl`}
              />
              <span className="relative z-1 inline-flex h-12 w-12 items-center justify-center rounded-2xl border border-signal/40 bg-signal/12 text-signal shadow-glow-sm">
                <Icon name={f.icon} className="h-6 w-6" />
              </span>
              <h3 className="relative z-1 mt-5 text-xl font-semibold text-mist">
                {f.name}
              </h3>
              <p className="relative z-1 mt-2 font-mono text-[11px] text-signal/85 wrap-break-word">
                {f.code}
              </p>
              <p className="relative z-1 mt-3 text-sm leading-relaxed text-slate">
                {f.text}
              </p>
              <div className="relative z-1 mt-5 flex flex-wrap gap-2">
                {f.chips.map((c) => (
                  <span
                    key={c}
                    className="rounded-md border border-white/10 bg-white/4 px-2.5 py-1 font-mono text-[10px] uppercase tracking-wider text-slate"
                  >
                    {c}
                  </span>
                ))}
              </div>
            </TiltCard>
          </Reveal>
        ))}
      </div>
    </SectionShell>
  );
}

const STATES = [
  { id: "pass", desc: "The evaluator observed a positive signal for the control in the clone or in accepted supporting evidence.", tone: "signal" },
  { id: "fail", desc: "A required signal was missing or a high-value problem was found in files, workflows, or supplied evidence.", tone: "rose" },
  { id: "manual-review-required", desc: "The control cannot be safely proven from a local clone alone, so platform confirmation or human review is still required.", tone: "amber" },
  { id: "self-attested", desc: "Maintainer-supplied local evidence exists, but trust still depends on honesty and review discipline rather than remote verification.", tone: "slate" },
  { id: "not-observable", desc: "The control exists conceptually, but the evaluated artifact set does not contain enough material to observe it safely.", tone: "muted" },
  { id: "not-applicable", desc: "The control does not apply to the evaluated repository shape, such as a repo that intentionally has no workflows.", tone: "muted" },
  { id: "waived", desc: "A documented exception overrode a non-pass outcome and remains visible in the report as an explicit decision.", tone: "violet" },
];

const TONE_CLASS = {
  signal: "border-signal/50 bg-signal/10 text-signal",
  rose: "border-red-400/40 bg-red-500/10 text-red-200",
  amber: "border-amber-400/40 bg-amber-500/10 text-amber-100",
  slate: "border-slate/50 bg-white/5 text-slate",
  muted: "border-white/10 bg-white/3 text-slate",
  violet: "border-violet-400/35 bg-violet-500/10 text-violet-100",
};

const FIELDS = [
  "control id",
  "status",
  "evidence sources",
  "confidence",
  "reason",
  "remediation",
  "waiver metadata",
];

function EvaluationStatesSection() {
  return (
    <SectionShell
      id="states"
      eyebrow="Evaluation model"
      title="Every control resolves to an explicit state, not to a hidden score."
      subtitle="That makes the output usable in triage, audit, and CI because teams can see what was proven, what was waived, and what still needs manual follow-up."
    >
      <div className="grid gap-4 lg:grid-cols-2">
        {STATES.map((s, i) => (
          <Reveal key={s.id} delay={i * 50}>
            <div
              className={`group relative rounded-2xl border p-5 transition cell-hover ${TONE_CLASS[s.tone]}`}
            >
              <div className="flex items-center gap-3">
                <span
                  className={`h-2 w-2 rounded-full ${
                    s.tone === "signal" ? "bg-signal shadow-[0_0_10px_rgba(8,185,139,0.8)]" :
                    s.tone === "rose" ? "bg-red-400" :
                    s.tone === "amber" ? "bg-amber-400" :
                    s.tone === "violet" ? "bg-violet-400" :
                    "bg-slate"
                  }`}
                />
                <code className="font-mono text-sm font-semibold tracking-tight">{s.id}</code>
              </div>
              <p className="mt-2 text-sm leading-relaxed text-mist/90">{s.desc}</p>
            </div>
          </Reveal>
        ))}
      </div>

      <Reveal className="mt-12">
        <div className="glass rounded-3xl p-8 md:p-10">
          <div className="flex items-center gap-3">
            <Icon name="file" className="h-5 w-5 text-signal" />
            <h3 className="text-lg font-semibold text-mist">
              Structured control records
            </h3>
          </div>
          <p className="mt-3 max-w-3xl text-sm text-slate">
            Each evaluated control carries fields meant to survive handoff from
            terminal output to a backlog item or review note:
          </p>
          <ul className="mt-6 flex flex-wrap gap-2">
            {FIELDS.map((f) => (
              <li
                key={f}
                className="rounded-lg border border-white/10 bg-ink-deep/60 px-3 py-2 font-mono text-xs text-mist transition hover:border-signal/40 hover:text-signal"
              >
                {f}
              </li>
            ))}
          </ul>
        </div>
      </Reveal>
    </SectionShell>
  );
}

window.CapabilitiesSection = CapabilitiesSection;
window.ComparisonSection = ComparisonSection;
window.FrameworksSection = FrameworksSection;
window.EvaluationStatesSection = EvaluationStatesSection;
