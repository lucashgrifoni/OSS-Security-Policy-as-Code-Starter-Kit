// Stats strip + marquee bands

const STATS = [
  { num: 56, suffix: "", label: "Bundled profiles", hint: "GitHub · GitLab · Azure · AWS" },
  { num: 9, suffix: "", label: "Explicit states", hint: "pass · fail · review · waived · …" },
  { num: 4, suffix: "", label: "Platforms supported", hint: "static parsers across forges" },
  { num: 23, suffix: "", label: "CLI commands", hint: "evaluate · profiles · …" },
];

function StatsStrip() {
  return (
    <section
      aria-label="At a glance"
      className="relative z-10 mx-auto -mt-4 max-w-6xl px-4 sm:px-6"
    >
      <Reveal>
        <div className="grid grid-cols-2 gap-4 rounded-3xl border border-white/10 bg-gradient-to-br from-white/[0.06] to-transparent p-6 backdrop-blur-md md:grid-cols-4 md:gap-0 md:p-2">
          {STATS.map((s, i) => (
            <div
              key={s.label}
              className={`group relative flex flex-col items-start gap-1 rounded-2xl p-4 md:p-6 transition ${
                i > 0 ? "md:border-l md:border-white/10" : ""
              }`}
            >
              <span className="pointer-events-none absolute -top-1 right-2 font-mono text-[10px] uppercase tracking-[0.24em] text-steel opacity-60">
                {String(i + 1).padStart(2, "0")}
              </span>
              <span className="stat-num text-5xl md:text-6xl font-semibold leading-none">
                <Counter to={s.num} duration={1400 + i * 150} />
              </span>
              <p className="mt-2 text-sm font-semibold text-mist">{s.label}</p>
              <p className="font-mono text-[11px] text-steel">{s.hint}</p>
            </div>
          ))}
        </div>
      </Reveal>
    </section>
  );
}

const PROFILE_NAMES = [
  "github-level-1",
  "github-level-2",
  "github-level-3",
  "github-release-hardening-1",
  "github-release-hardening-2",
  "github-release-hardening-3",
  "azure-level-1",
  "azure-level-2",
  "azure-level-3",
  "azure-release-hardening-1",
  "aws-level-1",
  "aws-level-2",
  "aws-level-3",
  "aws-release-hardening-1",
  "github-aws-level-2",
  "github-azure-level-2",
];

const CONTROL_TERMS = [
  "CODEOWNERS",
  "SECURITY.md",
  "branch-protection",
  "github-rulesets",
  "secret-scanning",
  "workflow-permissions",
  "action-pinning",
  "evidence-pack",
  "evaluation-report.json",
  "scorecard-bridge",
  "waivers.yaml",
  "scaffold-evidence",
  "fail-on-fail",
  "manual-review-required",
  "self-attested",
  "not-observable",
];

function ProfilesMarquee() {
  return (
    <div className="relative z-10 mt-24 space-y-3">
      <MarqueeBand items={PROFILE_NAMES} />
      <MarqueeBand items={CONTROL_TERMS} reverse />
    </div>
  );
}

window.StatsStrip = StatsStrip;
window.ProfilesMarquee = ProfilesMarquee;
