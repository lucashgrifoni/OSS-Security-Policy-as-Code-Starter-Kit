// Hero: 3D policy cube + animated JSON terminal + scroll parallax

const KEYWORDS = [
  "Local clone evaluation",
  "Versioned profiles",
  "Markdown + JSON reports",
  "Waivers",
  "Evidence scaffolding",
  "Scorecard JSON",
  "CI gates",
];

function CubeFace({ side, children }) {
  const T = {
    front: "translateZ(160px)",
    back: "rotateY(180deg) translateZ(160px)",
    right: "rotateY(90deg) translateZ(160px)",
    left: "rotateY(-90deg) translateZ(160px)",
    top: "rotateX(90deg) translateZ(160px)",
    bottom: "rotateX(-90deg) translateZ(160px)",
  };
  return (
    <div className="cube-face" style={{ transform: T[side] }}>
      <span className="face-bevel" aria-hidden="true" />
      <span className="corner tl" aria-hidden="true" />
      <span className="corner tr" aria-hidden="true" />
      <span className="corner bl" aria-hidden="true" />
      <span className="corner br" aria-hidden="true" />
      {children}
    </div>
  );
}

function PolicyCube() {
  const [paused, setPaused] = useState(false);
  const stageRef = useRef(null);
  const stateColors = {
    success: "text-signal",
    fail: "text-red-300",
    review: "text-amber-200",
    waived: "text-violet-300",
  };

  const handleMove = (e) => {
    const el = stageRef.current;
    if (!el) return;
    const r = el.getBoundingClientRect();
    const x = (e.clientX - r.left) / r.width - 0.5;
    const y = (e.clientY - r.top) / r.height - 0.5;
    el.style.setProperty("--tx", `${x * 25}deg`);
    el.style.setProperty("--ty", `${-y * 25 - 14}deg`);
  };
  const handleLeave = () => {
    const el = stageRef.current;
    if (!el) return;
    el.style.removeProperty("--tx");
    el.style.removeProperty("--ty");
    setPaused(false);
  };

  return (
    <div
      ref={stageRef}
      className={`cube-stage ${paused ? "cube-paused" : ""} relative aspect-square w-full max-w-[340px] mx-auto`}
      onMouseEnter={() => setPaused(true)}
      onMouseMove={handleMove}
      onMouseLeave={handleLeave}
    >
      <div className="cube-floor" aria-hidden="true" />

      {/* Floating particles around the cube */}
      <div className="cube-particles" aria-hidden="true">
        {Array.from({ length: 14 }).map((_, i) => {
          const left = (i * 37) % 100;
          const top = 50 + ((i * 53) % 50);
          const delay = (i * 0.43) % 6;
          const px = ((i * 17) % 80) - 40;
          return (
            <span
              key={i}
              className="particle"
              style={{
                left: `${left}%`,
                top: `${top}%`,
                animationDelay: `${delay}s`,
                "--px": `${px}px`,
              }}
            />
          );
        })}
      </div>

      {/* Orbital rings */}
      <div className="cube-orbits" aria-hidden="true">
        <div className="cube-orbit r1"><span className="cube-sat s1" /></div>
        <div className="cube-orbit r2"><span className="cube-sat s2" /></div>
        <div className="cube-orbit r3"><span className="cube-sat s3" /></div>
      </div>

      <div className="cube">
        <CubeFace side="front">
          <div className="flex items-center gap-2 border-b border-white/10 pb-2 text-signal">
            <Icon name="shield" className="h-4 w-4" />
            <span className="font-mono text-[11px] tracking-wide">github-level-1</span>
          </div>
          <div className="mt-3 space-y-1.5 font-mono text-[10px] leading-relaxed text-mist/85">
            <div className={`flex justify-between ${stateColors.success}`}>
              <span>GH-GOV-001</span><span>pass</span>
            </div>
            <div className={`flex justify-between ${stateColors.success}`}>
              <span>GH-GOV-002</span><span>pass</span>
            </div>
            <div className={`flex justify-between ${stateColors.fail}`}>
              <span>GH-CI-009</span><span>fail</span>
            </div>
            <div className={`flex justify-between ${stateColors.review}`}>
              <span>GH-REL-004</span><span>review</span>
            </div>
            <div className={`flex justify-between ${stateColors.waived}`}>
              <span>GH-CI-014</span><span>waived</span>
            </div>
          </div>
          <div className="mt-auto flex items-center justify-between font-mono text-[9px] text-steel border-t border-white/10 pt-2">
            <span>summary</span>
            <span className="text-signal">12 / 16</span>
          </div>
        </CubeFace>

        <CubeFace side="back">
          <div className="flex items-center gap-2 border-b border-white/10 pb-2 text-signal">
            <Icon name="layers" className="h-4 w-4" />
            <span className="font-mono text-[11px] tracking-wide">profile.yaml</span>
          </div>
          <div className="mt-3 space-y-1 font-mono text-[10px] leading-relaxed text-mist/85">
            <p><span className="text-steel">profile_id:</span> <span className="text-signal">github-level-1</span></p>
            <p><span className="text-steel">version:</span> 1.0.0</p>
            <p><span className="text-steel">controls:</span></p>
            <p className="pl-3">- GH-GOV-001</p>
            <p className="pl-3">- GH-GOV-002</p>
            <p className="pl-3">- GH-CI-009</p>
            <p className="pl-3">- GH-REL-004</p>
          </div>
        </CubeFace>

        <CubeFace side="right">
          <div className="flex items-center gap-2 border-b border-white/10 pb-2 text-signal">
            <Icon name="file" className="h-4 w-4" />
            <span className="font-mono text-[11px] tracking-wide">evidence/</span>
          </div>
          <div className="mt-3 space-y-1.5 font-mono text-[10px] text-mist/85">
            <p>branch-protection.json</p>
            <p>github-rulesets.json</p>
            <p>org-mfa-posture.json</p>
            <p>secret-scanning.json</p>
            <p>environment-protection.json</p>
          </div>
        </CubeFace>

        <CubeFace side="left">
          <div className="flex items-center gap-2 border-b border-white/10 pb-2 text-signal">
            <Icon name="terminal" className="h-4 w-4" />
            <span className="font-mono text-[11px] tracking-wide">cli</span>
          </div>
          <div className="mt-3 space-y-1.5 font-mono text-[9.5px] text-mist/85 leading-relaxed">
            <p><span className="text-steel">$</span> oss_policy_kit</p>
            <p className="pl-3 text-signal">profiles</p>
            <p className="pl-3">recommend-profile</p>
            <p className="pl-3">evaluate</p>
            <p className="pl-3">evaluate-many</p>
            <p className="pl-3">scaffold-evidence</p>
          </div>
        </CubeFace>

        <CubeFace side="top">
          <div className="flex items-center gap-2 border-b border-white/10 pb-2 text-signal">
            <Icon name="check" className="h-4 w-4" />
            <span className="font-mono text-[11px] tracking-wide">states</span>
          </div>
          <div className="mt-3 grid grid-cols-2 gap-1 font-mono text-[9px] text-mist/85">
            <span className="text-signal">pass</span>
            <span className="text-red-300">fail</span>
            <span className="text-amber-200">review</span>
            <span className="text-slate">attested</span>
            <span className="text-slate">n/observable</span>
            <span className="text-slate">n/applicable</span>
            <span className="text-violet-300">waived</span>
          </div>
        </CubeFace>

        <CubeFace side="bottom">
          <div className="flex items-center gap-2 border-b border-white/10 pb-2 text-signal">
            <Icon name="package" className="h-4 w-4" />
            <span className="font-mono text-[11px] tracking-wide">platforms</span>
          </div>
          <div className="mt-3 grid grid-cols-3 gap-1 text-center font-mono text-[10px] text-mist/85">
            <div className="rounded border border-signal/30 bg-signal/10 py-2 text-signal">GH</div>
            <div className="rounded border border-white/10 bg-white/5 py-2">AZ</div>
            <div className="rounded border border-white/10 bg-white/5 py-2">AWS</div>
          </div>
        </CubeFace>
      </div>
    </div>
  );
}

function TerminalReport() {
  const lines = [
    { d: "$ ", v: "python -m oss_policy_kit evaluate --target . --profile github-level-1", c: "text-mist" },
    { d: "→ ", v: "loading profile bundle... github-level-1@1.0.0", c: "text-slate" },
    { d: "→ ", v: "scanning .github/workflows ... 14 jobs", c: "text-slate" },
    { d: "→ ", v: "evaluating 16 controls", c: "text-slate" },
    { d: "✓ ", v: "GH-GOV-001 SECURITY.md present", c: "text-signal" },
    { d: "✓ ", v: "GH-GOV-002 CONTRIBUTING.md present", c: "text-signal" },
    { d: "✗ ", v: "GH-CI-009 implicit token permissions", c: "text-red-300" },
    { d: "? ", v: "GH-REL-004 manual-review-required", c: "text-amber-200" },
    { d: "→ ", v: "writing evaluation-report.json", c: "text-slate" },
    { d: "→ ", v: "writing evaluation-report.md", c: "text-slate" },
    { d: "▌ ", v: "summary  pass: 12  fail: 2  review: 2", c: "text-mist font-semibold" },
  ];

  const [shown, setShown] = useState(0);
  const [typed, setTyped] = useState("");

  useEffect(() => {
    if (prefersReducedMotion()) {
      setShown(lines.length);
      return;
    }
    let cancelled = false;
    const run = async () => {
      for (let i = 0; i < lines.length && !cancelled; i++) {
        const full = lines[i].v;
        for (let j = 0; j <= full.length && !cancelled; j++) {
          setShown(i);
          setTyped(full.slice(0, j));
          await new Promise((r) => setTimeout(r, j === full.length ? 220 : 12));
        }
        setShown(i + 1);
        setTyped("");
      }
    };
    const t = setTimeout(run, 600);
    return () => {
      cancelled = true;
      clearTimeout(t);
    };
  }, []);

  return (
    <div className="glass-strong relative overflow-hidden rounded-2xl border-white/10 shadow-floor">
      {/* terminal chrome */}
      <div className="flex items-center gap-2 border-b border-white/10 bg-black/30 px-4 py-2.5">
        <span className="h-2.5 w-2.5 rounded-full bg-red-400/60" />
        <span className="h-2.5 w-2.5 rounded-full bg-amber-400/60" />
        <span className="h-2.5 w-2.5 rounded-full bg-signal/70" />
        <span className="ml-3 font-mono text-[11px] text-steel">
          ~/projects/your-repo — oss_policy_kit
        </span>
      </div>

      <div className="relative h-[300px] overflow-hidden p-4 font-mono text-[11.5px] leading-relaxed">
        <div className="scanline" />
        <div className="space-y-1">
          {lines.slice(0, shown).map((l, i) => (
            <p key={i} className={l.c}>
              <span className="text-steel">{l.d}</span>
              <span>{l.v}</span>
            </p>
          ))}
          {shown < lines.length && (
            <p className={lines[shown].c}>
              <span className="text-steel">{lines[shown].d}</span>
              <span>{typed}</span>
              <span className="caret" />
            </p>
          )}
        </div>
      </div>
    </div>
  );
}

function Hero() {
  const ref = useRef(null);
  const [scroll, setScroll] = useState(0);

  useEffect(() => {
    if (prefersReducedMotion()) return;
    const onScroll = () => {
      const r = ref.current?.getBoundingClientRect();
      if (!r) return;
      const p = Math.min(1, Math.max(0, -r.top / r.height));
      setScroll(p);
    };
    window.addEventListener("scroll", onScroll, { passive: true });
    onScroll();
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  const op = 1 - scroll * 0.7;
  const ty = scroll * 60;

  return (
    <section
      ref={ref}
      id="hero"
      className="relative flex min-h-[100dvh] flex-col justify-center overflow-x-hidden pt-28 md:pt-32"
    >
      <div className="relative z-10 mx-auto grid w-full max-w-7xl flex-1 grid-cols-1 content-center gap-10 px-4 sm:px-6 xl:grid-cols-[minmax(0,1fr)_22rem] xl:items-center"
        style={{ opacity: op, transform: `translateY(${ty}px)` }}
      >
        <div className="min-w-0">
          <Reveal>
            <div className="pulse-ring inline-flex items-center gap-2.5 rounded-full border border-signal/35 bg-signal/[0.12] px-4 py-1.5 font-mono text-xs text-signal backdrop-blur-sm">
              <span className="relative flex h-2 w-2 shrink-0">
                <span className="absolute inline-flex h-full w-full rounded-full bg-signal/40 blur-[3px]" />
                <span className="relative inline-flex h-2 w-2 rounded-full bg-signal shadow-[0_0_14px_rgba(8,185,139,0.9)]" />
              </span>
              <span>Python CLI · GitHub / Azure / AWS / GitLab signals · evidence-first</span>
            </div>
          </Reveal>

          <Reveal delay={80}>
            <h1 className="headline-shadow mt-8 max-w-4xl text-4xl font-semibold leading-[1.04] tracking-tight text-mist md:text-6xl lg:text-7xl">
              Pass/fail policy gates
              <br />
              for your repository.
              <br className="hidden md:block" />
              With{" "}
              <span style={{ color: "#08b98b" }}>explicit trust grading</span>.
            </h1>
          </Reveal>

          <Reveal delay={150}>
            <p className="mt-6 max-w-2xl text-lg leading-relaxed text-slate md:text-xl">
              Composes zizmor, OSV-Scanner, Gitleaks, Scorecard, Semgrep, and
              your multi-platform CI/CD signals into one regulatory-aware
              decision without pretending clone-only data proves remote platform
              settings.
            </p>
          </Reveal>

          <Reveal delay={220}>
            <div className="mt-10 flex flex-wrap gap-3">
              <MagneticButton href={REPO_URL} variant="primary" external>
                View repository
                <Icon name="arrow" className="h-4 w-4" />
              </MagneticButton>
              <MagneticButton
                onClick={() => scrollToId("quickstart")}
                variant="ghost"
              >
                See quickstart
              </MagneticButton>
              <MagneticButton
                onClick={() => scrollToId("profiles")}
                variant="minimal"
              >
                Browse profiles
              </MagneticButton>
            </div>
          </Reveal>

          <Reveal delay={290}>
            <div className="mt-14">
              <p className="mb-4 font-mono text-xs uppercase tracking-[0.28em] text-steel">
                Core vocabulary
              </p>
              <div className="flex flex-wrap gap-2">
                {KEYWORDS.map((k, i) => (
                  <span
                    key={k}
                    className="rounded-lg border border-white/10 bg-white/[0.045] px-3 py-1.5 font-mono text-xs text-mist/95 shadow-sm backdrop-blur transition hover:-translate-y-0.5 hover:border-signal/30 hover:bg-white/[0.07] hover:shadow-glow-sm"
                    style={{ transitionDelay: `${i * 30}ms` }}
                  >
                    {k}
                  </span>
                ))}
              </div>
            </div>
          </Reveal>
        </div>

        {/* Right column: cube + terminal */}
        <div className="space-y-16">
          <Reveal delay={120}>
            <div className="float-y">
              <PolicyCube />
            </div>
          </Reveal>
          <Reveal delay={240}>
            <TerminalReport />
          </Reveal>
        </div>
      </div>

      <button
        type="button"
        aria-label="Scroll down"
        onClick={() => scrollToId("problem")}
        className="absolute bottom-8 left-1/2 z-20 flex -translate-x-1/2 flex-col items-center gap-1 text-slate transition hover:text-signal"
      >
        <span className="font-mono text-xs uppercase tracking-[0.28em]">
          Scroll
        </span>
        <span className="rounded-full p-1 ring-1 ring-transparent transition hover:ring-signal/35 hover:shadow-glow-sm">
          <Icon
            name="chevronDown"
            className="h-6 w-6 animate-bounce"
          />
        </span>
      </button>
    </section>
  );
}

window.Hero = Hero;
