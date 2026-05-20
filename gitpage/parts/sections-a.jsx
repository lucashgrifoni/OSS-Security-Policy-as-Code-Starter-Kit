// Sections A: Problem, Scope, Workflow

const PROBLEMS = [
  {
    icon: "scale",
    title: "Clone truth is limited",
    body: "Repository files can prove some things well, suggest other things weakly, and say nothing about live platform settings. Most tools blur those lines.",
  },
  {
    icon: "workflow",
    title: "Baselines become hand-wavy",
    body: "Teams talk about OSS security maturity, but translating that into versioned controls, profiles, and repeatable checks is usually where momentum dies.",
  },
  {
    icon: "git",
    title: "Governance and pipelines drift apart",
    body: "SECURITY.md, CODEOWNERS, workflow permissions, release posture, and waiver decisions often live in different conversations instead of one evidence trail.",
  },
  {
    icon: "alert",
    title: "Dashboards hide the hard part",
    body: "A green score does not tell you what was observed, what was assumed, and what still needs manual review. Program reviews need that distinction.",
  },
];

function ProblemSection() {
  return (
    <SectionShell
      id="problem"
      eyebrow="Problem space"
      title="OSS security posture is easy to describe and surprisingly hard to verify honestly."
      subtitle="This kit turns that gap into a concrete workflow: pick a profile, inspect a local clone, add optional evidence, and keep every unresolved boundary visible."
    >
      <div className="grid gap-5 md:grid-cols-2 perspective-1800">
        {PROBLEMS.map((p, i) => (
          <Reveal key={p.title} delay={i * 80}>
            <TiltCard className="h-full">
              <span className="inline-flex h-11 w-11 items-center justify-center rounded-xl border border-signal/30 bg-signal/10 text-signal shadow-glow-sm">
                <Icon name={p.icon} className="h-5 w-5" />
              </span>
              <h3 className="mt-4 text-lg font-semibold text-mist">{p.title}</h3>
              <p className="mt-2 text-sm leading-relaxed text-slate">{p.body}</p>
            </TiltCard>
          </Reveal>
        ))}
      </div>
    </SectionShell>
  );
}

const IS_LIST = [
  "Python CLI that evaluates a local repository clone and writes Markdown + JSON reports",
  "Bundled profile families for GitHub, Azure, and AWS with staged level and release-hardening tracks",
  "Governance, workflow, and pipeline checks that stay inside clone-visible boundaries unless optional evidence is supplied",
  "Commands for profile discovery, profile recommendation, batch evaluation, and evidence scaffolding",
  "Optional waivers YAML and optional OpenSSF Scorecard JSON as additive local context",
  "Built-in hardened and vulnerable fixtures, templates, and docs for demos and onboarding",
  "Explicit remediation, confidence, and non-pass states instead of a single maturity score",
];

const NOT_LIST = [
  "Live verifier for GitHub settings, Azure policies, or AWS configuration outside the clone",
  "Universal SAST, DAST, dependency scanner, or application security platform",
  "Compliance certification engine, OSPS attestation service, or guarantee of secure posture",
  "Dashboard-first SaaS control plane that invents passes when evidence is missing",
];

function ScopeColumn({ title, items, tone }) {
  const isYes = tone === "yes";
  return (
    <div
      className={`glass-strong relative overflow-hidden rounded-3xl p-8 md:p-10 ${
        isYes ? "border-signal/30" : "border-white/10"
      }`}
    >
      <div
        className={`pointer-events-none absolute -top-24 -right-24 h-56 w-56 rounded-full blur-3xl ${
          isYes ? "bg-signal/20" : "bg-slate/15"
        }`}
      />
      <div
        className={`mb-6 inline-flex items-center gap-2 rounded-full px-3 py-1 font-mono text-xs uppercase tracking-[0.2em] ${
          isYes
            ? "bg-signal/15 text-signal border border-signal/40"
            : "bg-white/5 text-slate border border-white/10"
        }`}
      >
        <Icon name={isYes ? "check2" : "x"} className="h-3.5 w-3.5" />
        {title}
      </div>
      <ul className="relative space-y-4">
        {items.map((item) => (
          <li
            key={item}
            className="flex gap-3 text-sm leading-relaxed text-mist/95"
          >
            <span
              className={`mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-md border text-xs ${
                isYes
                  ? "border-signal/40 bg-signal/10 text-signal"
                  : "border-white/15 bg-white/5 text-slate"
              }`}
            >
              <Icon
                name={isYes ? "check2" : "x"}
                className="h-3.5 w-3.5"
              />
            </span>
            <span>{item}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function ScopeSection() {
  return (
    <SectionShell
      id="scope"
      eyebrow="Positioning"
      title="The scope is intentionally narrow because honest outputs are more useful than broad promises."
      subtitle="The kit is small, test-backed, and explicit about which results are automated, self-attested, or still blocked on manual review."
    >
      <div className="grid gap-6 lg:grid-cols-2">
        <Reveal>
          <ScopeColumn title="What it is" tone="yes" items={IS_LIST} />
        </Reveal>
        <Reveal delay={120}>
          <ScopeColumn title="What it is not" tone="no" items={NOT_LIST} />
        </Reveal>
      </div>
    </SectionShell>
  );
}

const FLOW_STEPS = [
  {
    icon: "sliders",
    title: "Discover the right profile",
    body: "Start with `profiles` or `recommend-profile` to choose the platform and strictness level that matches the repository you actually have.",
  },
  {
    icon: "merge",
    title: "Point the CLI at a clone",
    body: "Run `python -m oss_policy_kit evaluate --target <repo> --profile <profile>` against the working tree you want to inspect.",
  },
  {
    icon: "radar",
    title: "Layer in optional evidence",
    body: "Add waivers, Scorecard JSON, or `.oss-policy-kit/evidence/` files only when you need extra context for release-hardening or program review.",
  },
  {
    icon: "check",
    title: "Resolve explicit control states",
    body: "Each control ends as pass, fail, manual-review-required, self-attested, not-observable, not-applicable, or waived.",
  },
  {
    icon: "scroll",
    title: "Write reports for humans and CI",
    body: "The evaluator writes evaluation-report.md and evaluation-report.json, and can emit compact machine summaries with --summary-only --format json.",
  },
  {
    icon: "file",
    title: "Reuse it in pipelines or batches",
    body: "Use --fail-on for CI gates and evaluate-many when you want one pass over multiple child repositories or apps.",
  },
];

function WorkflowSection() {
  return (
    <SectionShell
      id="flow"
      eyebrow="Execution model"
      title="The workflow is practical: choose a profile, evaluate the clone, keep the evidence."
      subtitle="Nothing here depends on a remote service. The same flow works for local self-checks, demos, and CI gates."
    >
      <div className="relative">
        {/* vertical connector */}
        <div
          className="absolute left-[22px] top-2 hidden h-[calc(100%-1rem)] w-px md:block flow-connector"
          aria-hidden="true"
        />
        <ol className="space-y-8 md:space-y-10">
          {FLOW_STEPS.map((s, i) => (
            <Reveal
              key={s.title}
              delay={i * 70}
              as="li"
              className="relative flex flex-col gap-5 md:flex-row md:gap-8"
            >
              <div className="flex items-start gap-4 md:w-44 md:shrink-0 md:flex-col md:items-center">
                <span className="relative flex h-11 w-11 items-center justify-center rounded-2xl border border-signal/40 bg-signal/10 text-signal shadow-glow-sm">
                  <Icon name={s.icon} className="h-5 w-5" />
                  <span className="absolute -inset-1 rounded-2xl border border-signal/15" />
                </span>
                <span className="font-mono text-[11px] uppercase tracking-[0.22em] text-steel md:text-center">
                  Step {String(i + 1).padStart(2, "0")}
                </span>
              </div>
              <TiltCard className="flex-1" intensity={4}>
                <h3 className="text-lg font-semibold text-mist md:text-xl">
                  {s.title}
                </h3>
                <p className="mt-2 text-sm leading-relaxed text-slate md:text-base">
                  {s.body}
                </p>
              </TiltCard>
            </Reveal>
          ))}
        </ol>
      </div>
    </SectionShell>
  );
}

const QS_STEPS = [
  {
    icon: "terminal",
    title: "Install for local development",
    cmd: 'python -m pip install -e ".[dev]"',
    note: "Requires Python 3.12+. Release consumers can also install from GitHub Release wheel artifacts.",
  },
  {
    icon: "folder",
    title: "List bundled profiles",
    cmd: "python -m oss_policy_kit profiles",
    note: "This build ships 18 profiles across GitHub, Azure, and AWS, including baseline and release-hardening tracks.",
  },
  {
    icon: "check",
    title: "Run a self-check",
    cmd: "python -m oss_policy_kit evaluate --target . --profile github-level-1 --output-dir ./out/selfcheck",
    note: "The run writes evaluation-report.json and evaluation-report.md before you decide what to fix next.",
  },
  {
    icon: "check2",
    title: "Turn it into a CI gate",
    cmd: "python -m oss_policy_kit evaluate --target . --profile github-level-1 --fail-on fail",
    note: "Reports are still written first; the CI step fails only after evidence is available for review.",
  },
];

const QS_EXTRAS = [
  "python -m oss_policy_kit recommend-profile --target .",
  "python -m oss_policy_kit evaluate-many --target-root ./apps --profiles github-level-1",
  "python -m oss_policy_kit scaffold-evidence --target . --platform github",
  "python -m oss_policy_kit evaluate --target . --profile github-level-1 --summary-only --format json",
];

function CommandBlock({ cmd, copyable = true }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="group relative overflow-hidden rounded-xl border border-white/10 bg-ink-deep/80 p-4 font-mono text-xs leading-relaxed text-mist">
      <div className="flex items-start gap-3">
        <span className="text-signal/70 select-none">$</span>
        <code className="flex-1 break-all">{cmd}</code>
        {copyable && (
          <button
            type="button"
            onClick={() => {
              navigator.clipboard?.writeText(cmd);
              setCopied(true);
              setTimeout(() => setCopied(false), 1500);
            }}
            className="opacity-0 group-hover:opacity-100 transition shrink-0 rounded-md border border-white/10 px-2 py-1 text-[10px] uppercase tracking-wider text-slate hover:border-signal/40 hover:text-signal"
          >
            {copied ? "✓ copied" : "copy"}
          </button>
        )}
      </div>
      <div className="pointer-events-none absolute inset-x-0 -bottom-px h-px bg-gradient-to-r from-transparent via-signal/40 to-transparent opacity-0 group-hover:opacity-100 transition" />
    </div>
  );
}

function QuickstartSection() {
  return (
    <SectionShell
      id="quickstart"
      eyebrow="Quickstart"
      title="Four commands are enough to understand how the kit works in practice."
      subtitle="The explicit evaluate subcommand is the preferred contract. The rest of the CLI expands from that same local-first model."
    >
      <div className="grid gap-5 lg:grid-cols-2">
        {QS_STEPS.map((s, i) => (
          <Reveal key={s.title} delay={i * 60}>
            <TiltCard className="h-full" intensity={5}>
              <div className="flex items-center gap-3">
                <span className="flex h-11 w-11 items-center justify-center rounded-2xl border border-signal/35 bg-signal/10 text-signal shadow-glow-sm">
                  <Icon name={s.icon} className="h-5 w-5" />
                </span>
                <div>
                  <p className="font-mono text-[10px] uppercase tracking-[0.22em] text-steel">
                    Step {String(i + 1).padStart(2, "0")}
                  </p>
                  <h3 className="text-lg font-semibold text-mist">{s.title}</h3>
                </div>
              </div>
              <div className="mt-5">
                <CommandBlock cmd={s.cmd} />
              </div>
              <p className="mt-4 text-sm leading-relaxed text-slate">{s.note}</p>
            </TiltCard>
          </Reveal>
        ))}
      </div>

      <Reveal className="mt-10">
        <div className="rounded-3xl border border-white/10 bg-white/[0.03] p-6 md:p-8 backdrop-blur">
          <div className="flex items-center gap-3">
            <span className="font-mono text-xs uppercase tracking-[0.24em] text-steel">
              Also useful
            </span>
            <span className="h-px flex-1 bg-white/10" />
          </div>
          <div className="mt-5 grid gap-3 md:grid-cols-2">
            {QS_EXTRAS.map((e) => (
              <CommandBlock key={e} cmd={e} />
            ))}
          </div>
        </div>
      </Reveal>
    </SectionShell>
  );
}

window.ProblemSection = ProblemSection;
window.ScopeSection = ScopeSection;
window.WorkflowSection = WorkflowSection;
window.QuickstartSection = QuickstartSection;
