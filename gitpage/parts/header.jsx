// Site header with active section tracking + scroll progress

const NAV = [
  { id: "hero", label: "Overview" },
  { id: "problem", label: "Problem" },
  { id: "comparison", label: "Compare" },
  { id: "scope", label: "Scope" },
  { id: "flow", label: "Workflow" },
  { id: "sample-output", label: "Output" },
  { id: "quickstart", label: "Quickstart" },
  { id: "capabilities", label: "Capabilities" },
  { id: "profiles", label: "Profiles" },
  { id: "states", label: "Evaluation" },
  { id: "differentiators", label: "Why" },
  { id: "examples", label: "Signals" },
  { id: "roadmap", label: "Roadmap" },
  { id: "architecture", label: "Repo" },
  { id: "cta", label: "Get started" },
];

function ScrollProgress() {
  const [w, setW] = useState(0);
  useEffect(() => {
    const onScroll = () => {
      const h = document.documentElement;
      const total = h.scrollHeight - h.clientHeight;
      setW(total > 0 ? (h.scrollTop / total) * 100 : 0);
    };
    window.addEventListener("scroll", onScroll, { passive: true });
    onScroll();
    return () => window.removeEventListener("scroll", onScroll);
  }, []);
  return (
    <div className="absolute inset-x-0 bottom-0 h-px bg-white/5">
      <div
        className="h-full bg-linear-to-r from-signal/0 via-signal to-signal/0 transition-[width]"
        style={{ width: `${w}%`, boxShadow: "0 0 12px rgba(8,185,139,0.6)" }}
      />
    </div>
  );
}

function SiteHeader() {
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState("hero");

  useEffect(() => {
    const ids = NAV.map((n) => n.id);
    const els = ids
      .map((id) => document.getElementById(id))
      .filter(Boolean);
    if (!els.length) return;
    const io = new IntersectionObserver(
      (entries) => {
        entries.forEach((e) => {
          if (e.isIntersecting) setActive(e.target.id);
        });
      },
      { rootMargin: "-40% 0px -50% 0px", threshold: 0 }
    );
    els.forEach((el) => io.observe(el));
    return () => io.disconnect();
  }, []);

  return (
    <header className="fixed inset-x-0 top-0 z-50 border-b border-white/5 bg-ink-deep/70 backdrop-blur-xl">
      <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-4 sm:px-6">
        <a
          href="#hero"
          onClick={(e) => {
            e.preventDefault();
            scrollToId("hero");
          }}
          className="group flex items-center gap-2.5 font-semibold tracking-tight text-mist"
        >
          <span className="relative flex h-9 w-9 items-center justify-center rounded-lg border border-signal/40 bg-signal/15 font-mono text-[10px] font-bold text-signal shadow-glow-sm overflow-hidden">
            <span className="absolute inset-0 bg-linear-to-br from-signal/20 to-transparent" />
            <span className="relative">OSS</span>
          </span>
          <span className="hidden sm:flex flex-col leading-tight">
            <span className="text-sm">Policy Kit</span>
            <span className="text-[10px] font-mono text-steel">starter</span>
          </span>
        </a>

        <nav
          className="hidden lg:flex items-center gap-0.5"
          aria-label="Primary"
        >
          {NAV.slice(1, -1).map((s) => (
            <button
              key={s.id}
              type="button"
              onClick={() => scrollToId(s.id)}
              className={`relative rounded-lg px-2.5 py-2 text-xs transition ${
                active === s.id
                  ? "text-signal"
                  : "text-slate hover:text-mist"
              }`}
            >
              {active === s.id && (
                <span className="absolute inset-0 rounded-lg bg-signal/10 border border-signal/30" />
              )}
              <span className="relative">{s.label}</span>
            </button>
          ))}
        </nav>

        <div className="flex items-center gap-2">
          <a
            href={REPO_URL}
            target="_blank"
            rel="noreferrer noopener"
            className="hidden sm:inline-flex items-center gap-2 rounded-lg border border-signal/40 bg-signal/15 px-3 py-2 text-xs font-medium text-signal shadow-glow-sm transition hover:bg-signal/25 hover:shadow-glow"
          >
            <Icon name="github" className="h-4 w-4" />
            Repository
          </a>
          <button
            type="button"
            className="inline-flex items-center justify-center rounded-lg border border-white/10 p-2 text-mist lg:hidden"
            aria-label={open ? "Close navigation" : "Open navigation"}
            aria-expanded={open}
            onClick={() => setOpen((v) => !v)}
          >
            <Icon name={open ? "x" : "menu"} className="h-5 w-5" />
          </button>
        </div>
      </div>
      <ScrollProgress />

      {open && (
        <div className="border-t border-white/5 bg-ink-deep/95 lg:hidden">
          <div className="flex max-h-[70vh] flex-col gap-1 overflow-y-auto px-4 py-4">
            {NAV.map((s) => (
              <button
                key={s.id}
                type="button"
                className={`rounded-lg px-3 py-3 text-left text-sm transition ${
                  active === s.id ? "text-signal bg-signal/10" : "text-slate hover:text-mist"
                }`}
                onClick={() => {
                  setOpen(false);
                  scrollToId(s.id);
                }}
              >
                {s.label}
              </button>
            ))}
            <a
              href={REPO_URL}
              target="_blank"
              rel="noreferrer noopener"
              className="mt-2 rounded-lg border border-signal/40 px-3 py-3 text-center text-sm font-medium text-signal"
            >
              View on GitHub
            </a>
          </div>
        </div>
      )}
    </header>
  );
}

window.SiteHeader = SiteHeader;
