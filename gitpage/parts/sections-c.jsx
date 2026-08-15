// Sections C: Differentiators, Signals (control examples), Roadmap, Repo anatomy

const SAMPLE_REPORTS = [
  {
    id: "hardened",
    title: "Hardened repository",
    file: "hardened-report.md",
    profile: "github-level-1",
    caption: "github-level-1 profile, 14/14 pass in the bundled hardened fixture.",
    tone: "signal",
    stats: { pass: 14, fail: 0, review: 0, total: 14 },
    controls: [
      { id: "GOV-SEC-001", status: "pass", reason: "SECURITY.md present." },
      { id: "GOV-CON-002", status: "pass", reason: "Contributing guide present." },
      { id: "GOV-COWN-003", status: "pass", reason: "CODEOWNERS file present." },
      { id: "GOV-LIC-004", status: "pass", reason: "LICENSE (or COPYING) file detected." },
      { id: "CI-WF-005", status: "pass", reason: "Found 3 workflow file(s)." },
      { id: "CI-PERM-006", status: "pass", reason: "All workflows declare top-level permissions." },
      { id: "CI-DANGER-007", status: "pass", reason: "No pull_request_target detected in workflows." },
      { id: "CI-PIN-008", status: "pass", reason: "No obviously mutable third-party action pins." },
      { id: "CI-LEAST-009", status: "pass", reason: "No obviously over-broad workflow permissions." },
      { id: "SEC-CODEQL-010", status: "pass", reason: "github/codeql-action usage detected." },
      { id: "REL-CHANGE-012", status: "pass", reason: "Changelog or release notes file detected." },
      { id: "GOV-WAIV-014", status: "pass", reason: "Versioned waiver file detected in repository." },
    ],
  },
  {
    id: "vulnerable",
    title: "Vulnerable repository",
    file: "vulnerable-report.md",
    profile: "github-level-1",
    caption: "Same profile against the vulnerable fixture, with multiple failing controls.",
    tone: "red",
    stats: { pass: 2, fail: 11, review: 1, total: 14 },
    controls: [
      { id: "GOV-SEC-001", status: "fail", reason: "SECURITY.md missing." },
      { id: "GOV-CON-002", status: "fail", reason: "Contributing guide missing." },
      { id: "GOV-COWN-003", status: "fail", reason: "CODEOWNERS file missing." },
      { id: "GOV-LIC-004", status: "fail", reason: "No LICENSE file detected at repository root." },
      { id: "CI-WF-005", status: "pass", reason: "Found 1 workflow file." },
      { id: "CI-PERM-006", status: "fail", reason: "Workflow does not declare top-level permissions." },
      { id: "CI-DANGER-007", status: "fail", reason: "pull_request_target detected in unsafe.yml." },
      { id: "CI-PIN-008", status: "fail", reason: "Third-party actions pinned to mutable tags." },
      { id: "CI-LEAST-009", status: "pass", reason: "No obviously over-broad workflow permissions detected." },
      { id: "SEC-CODEQL-010", status: "fail", reason: "No CodeQL or equivalent signal in local workflows." },
      { id: "SEC-DEPREV-011", status: "fail", reason: "No dependency-review-action detected in workflows." },
      { id: "REL-CHANGE-012", status: "fail", reason: "No CHANGELOG-style file detected." },
      { id: "GOV-DISC-013", status: "fail", reason: "Disclosure reporting mechanism not implemented." },
      { id: "GOV-WAIV-014", status: "review", reason: "No versioned waiver policy file found in repository." },
    ],
  },
];

function SampleOutputStat({ label, value, accent }) {
  return (
    <div className="relative flex flex-col rounded-2xl border border-white/10 bg-ink-deep/60 p-4 backdrop-blur transition hover:border-signal/30">
      <span className="font-mono text-[10px] uppercase tracking-[0.22em] text-steel">{label}</span>
      <span className={`mt-1 text-3xl font-semibold leading-none ${accent}`}>
        <Counter to={value} duration={900} />
      </span>
    </div>
  );
}

const STATUS_META = {
  pass:   { glyph: "✓", text: "text-signal",  bg: "bg-signal/10",  border: "border-signal/30" },
  fail:   { glyph: "✗", text: "text-red-300", bg: "bg-red-500/10", border: "border-red-400/30" },
  review: { glyph: "?", text: "text-amber-200", bg: "bg-amber-500/10", border: "border-amber-400/30" },
};

function ReportRow({ row, i, activeId }) {
  const meta = STATUS_META[row.status] || STATUS_META.pass;
  return (
    <div
      key={`${activeId}-${row.id}`}
      className="report-row grid grid-cols-[110px_72px_1fr] items-start gap-3 border-b border-white/5 px-4 py-2.5 font-mono text-[11px] last:border-b-0 transition hover:bg-white/[0.03]"
      style={{ animationDelay: `${i * 28}ms` }}
    >
      <code className="text-signal/90">{row.id}</code>
      <span className={`inline-flex items-center gap-1.5 ${meta.text}`}>
        <span className="text-[13px] leading-none">{meta.glyph}</span>
        {row.status}
      </span>
      <span className="text-mist/85 leading-relaxed">{row.reason}</span>
    </div>
  );
}

function SampleOutputSection() {
  const [activeIdx, setActiveIdx] = useState(0);
  const item = SAMPLE_REPORTS[activeIdx];
  const ringTone =
    item.tone === "signal"
      ? "ring-signal/40 shadow-glow"
      : "ring-red-400/40 shadow-[0_0_60px_-10px_rgba(248,113,113,0.45)]";

  return (
    <SectionShell
      id="sample-output"
      eyebrow="Sample output"
      title="The report is meant to be read by humans and kept by CI."
      subtitle="The same evaluation produces Markdown for reviewers, JSON for automation, and optional SARIF for code-scanning workflows."
    >
      <Reveal>
        <div className={`relative overflow-hidden rounded-3xl border border-white/10 bg-ink-deep/70 ring-1 ${ringTone} transition-shadow duration-500 backdrop-blur-xl`}>
          {/* macOS-style chrome with tabs */}
          <div className="flex flex-wrap items-center gap-3 border-b border-white/10 bg-ink-deep/80 px-5 py-3">
            <div className="flex items-center gap-2">
              <span className="h-3 w-3 rounded-full bg-red-400/70" />
              <span className="h-3 w-3 rounded-full bg-amber-400/70" />
              <span className="h-3 w-3 rounded-full bg-signal/80" />
            </div>
            <div className="ml-2 flex flex-1 flex-wrap items-center gap-1">
              {SAMPLE_REPORTS.map((r, i) => {
                const isActive = i === activeIdx;
                const tab = r.tone === "signal" ? "text-signal" : "text-red-200";
                return (
                  <button
                    key={r.id}
                    type="button"
                    onClick={() => setActiveIdx(i)}
                    className={`group relative whitespace-nowrap rounded-md px-3 py-1.5 font-mono text-[11px] transition ${
                      isActive
                        ? `${tab} bg-white/[0.06] border border-white/10`
                        : "text-steel hover:text-mist border border-transparent"
                    }`}
                  >
                    <span className="inline-flex items-center gap-2">
                      <span
                        className={`h-1.5 w-1.5 rounded-full ${
                          r.tone === "signal"
                            ? "bg-signal shadow-[0_0_8px_rgba(8,185,139,0.8)]"
                            : "bg-red-400"
                        }`}
                      />
                      {r.file}
                    </span>
                    {isActive && (
                      <span className="absolute -bottom-px left-2 right-2 h-px bg-gradient-to-r from-transparent via-current to-transparent" />
                    )}
                  </button>
                );
              })}
            </div>
            <span className="hidden font-mono text-[11px] text-steel sm:inline">
              profile: <span className="text-signal">{item.profile}</span>
            </span>
          </div>

          {/* Body */}
          <div className="grid gap-6 p-6 md:p-8 lg:grid-cols-[280px_1fr] lg:gap-8">
            {/* Left: summary */}
            <div className="flex flex-col gap-4">
              <div className="rounded-2xl border border-white/10 bg-gradient-to-br from-white/[0.05] to-transparent p-5">
                <p className="font-mono text-[10px] uppercase tracking-[0.24em] text-steel">
                  Evaluation summary
                </p>
                <h3 className="mt-2 text-2xl font-semibold text-mist">{item.title}</h3>
                <p className="mt-2 text-sm leading-relaxed text-slate">{item.caption}</p>
              </div>

              <div key={`stats-${item.id}`} className="grid grid-cols-3 gap-3">
                <SampleOutputStat label="pass" value={item.stats.pass} accent="text-signal" />
                <SampleOutputStat label="fail" value={item.stats.fail} accent="text-red-300" />
                <SampleOutputStat label="review" value={item.stats.review} accent="text-amber-200" />
              </div>

              <div className="rounded-2xl border border-white/10 bg-ink-deep/60 p-4 font-mono text-[11px] leading-relaxed text-slate">
                <p className="text-steel">// outputs</p>
                <p>├─ evaluation-report.md</p>
                <p>├─ evaluation-report.json</p>
                <p>└─ evaluation-report.sarif</p>
              </div>

              <a
                href="https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/tree/master/docs/sample-reports"
                target="_blank"
                rel="noreferrer noopener"
                className="group inline-flex items-center justify-between gap-2 rounded-xl border border-signal/35 bg-signal/10 px-4 py-3 text-sm font-medium text-signal transition hover:bg-signal/20 hover:shadow-glow-sm"
              >
                <span>Browse full reports</span>
                <Icon name="arrow" className="h-4 w-4 transition group-hover:translate-x-0.5" />
              </a>
            </div>

            {/* Right: rendered report from structured text */}
            <div className="overflow-hidden rounded-2xl border border-white/10 bg-ink-deep/70 shadow-floor">
              {/* report header */}
              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/10 px-4 py-3 font-mono text-[11px] text-steel">
                <div className="flex items-center gap-2">
                  <Icon name="file" className="h-3.5 w-3.5 text-signal/80" />
                  <span>{item.file}</span>
                </div>
                <div className="flex items-center gap-3">
                  <span>
                    score:{" "}
                    <span className={item.tone === "signal" ? "text-signal" : "text-amber-200"}>
                      {Math.round((item.stats.pass / item.stats.total) * 100)}%
                    </span>
                  </span>
                  <span>·</span>
                  <span>
                    {item.stats.pass}/{item.stats.total} pass
                  </span>
                </div>
              </div>

              {/* health bar */}
              <div className="flex items-center gap-1 px-4 py-3">
                {Array.from({ length: item.stats.total }).map((_, i) => {
                  let cls = "bg-white/10";
                  if (i < item.stats.pass) cls = "bg-signal shadow-[0_0_6px_rgba(8,185,139,0.7)]";
                  else if (i < item.stats.pass + item.stats.fail) cls = "bg-red-400 shadow-[0_0_6px_rgba(248,113,113,0.6)]";
                  else if (i < item.stats.pass + item.stats.fail + item.stats.review) cls = "bg-amber-400 shadow-[0_0_6px_rgba(251,191,36,0.6)]";
                  return (
                    <span
                      key={i}
                      className={`h-2 flex-1 rounded-sm ${cls} transition-all duration-300`}
                      style={{ transitionDelay: `${i * 30}ms` }}
                    />
                  );
                })}
              </div>

              {/* rows */}
              <div key={item.id} className="max-h-[420px] overflow-y-auto">
                <div className="grid grid-cols-[110px_72px_1fr] gap-3 border-b border-white/10 px-4 py-2 font-mono text-[10px] uppercase tracking-[0.18em] text-steel">
                  <span>ID</span>
                  <span>Status</span>
                  <span>Reason</span>
                </div>
                {item.controls.map((row, i) => (
                  <ReportRow key={`${item.id}-${row.id}`} row={row} i={i} activeId={item.id} />
                ))}
              </div>
            </div>
          </div>
        </div>
      </Reveal>
    </SectionShell>
  );
}

const DIFFS = [
  { icon: "layers", title: "Honest trust model", body: "The kit distinguishes clone-visible truth, self-attested evidence, and platform-only reality instead of collapsing them into one confidence claim." },
  { icon: "cpu", title: "Useful command surface", body: "The CLI does more than one demo command: it supports profile discovery, recommendation, batch evaluation, evidence scaffolding, summaries, and CI thresholds." },
  { icon: "zap", title: "Small and inspectable", body: "Controls, profiles, schemas, and parsers live in the repository in plain files, which makes the project easier to audit and easier to fork responsibly." },
  { icon: "target", title: "Built for adoption", body: "Fixtures, docs, templates, sample reports, and the GitHub Pages site make the kit easier to demo, teach, and operationalize with maintainers." },
  { icon: "sparkles", title: "One output for people and automation", body: "The same evaluation produces narrative Markdown for review and structured JSON for pipelines, integrations, and regression checks." },
];

function DifferentiatorsSection() {
  return (
    <SectionShell
      id="differentiators"
      eyebrow="Differentiators"
      title="What makes this project useful is not polish alone, but operational honesty."
      subtitle="It is designed for real maintainers and AppSec engineers who need evidence they can explain, not just output that looks impressive out of context."
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
    title: "Now — v10.0",
    icon: "rocket",
    era: "v10.0",
    bullets: [
      "correlate-findings folds the scanner evidence already on disk into one deduplicated, KEV/EPSS-ranked findings/1.0 artifact — composing verdicts, never re-scanning.",
      "Control applicability is first-class, and verified build-provenance passes surface as ATTESTED by default.",
      "222 controls across 56 profiles on GitHub, GitLab, Azure, and AWS; reports/2.0 is the only report contract.",
      "Published to PyPI, GHCR, and GitHub Releases with signed assets, SBOM, and build provenance.",
    ],
  },
  {
    id: "shipped",
    title: "Shipped",
    icon: "shield",
    era: "v6.6 → v10",
    bullets: [
      "Ecosystem interop: reports/2.0 default flip, OpenVEX + CycloneDX VEX, SPDX + CycloneDX SBOM, CEL/Rego export, OSCAL + in-toto evidence.",
      "EU CRA conformance evidence: vulnerability-handling, support-period, and crypto-agility signals.",
      "OWASP Agentic ASI (ASI01–ASI10) source-side coverage and CISA Secure-by-Design readiness signals.",
      "NIST AI RMF / ISO 42001 / MITRE ATLAS crosswalks; GitHub immutable-release and org Actions-policy signals.",
    ],
  },
  {
    id: "directional",
    title: "Directional",
    icon: "satellite",
    era: "Unscheduled",
    bullets: [
      "A findings diff between two runs, and a findings section rendered into the Markdown report.",
      "A fifth SARIF source for the correlator, and a devcontainer for a one-command local setup.",
      "These horizons are direction only, not scheduled; they resume on a deliberate decision to reopen development.",
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
      subtitle="The kit is feature-complete for its core thesis and is now in a stable, maintenance-focused phase — security and dependency upkeep, not new surface area. The directional horizons below are retained as possible future work, not scheduled commitments."
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
