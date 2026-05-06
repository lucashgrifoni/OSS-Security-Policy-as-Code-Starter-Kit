// Primitives: Reveal, TiltCard, MagneticButton, useReveal, etc.

const { useEffect, useRef, useState, useCallback, useMemo } = React;

const prefersReducedMotion = () =>
  typeof window !== "undefined" &&
  window.matchMedia &&
  window.matchMedia("(prefers-reduced-motion: reduce)").matches;

function useInView(opts = {}) {
  const ref = useRef(null);
  const [inView, setInView] = useState(false);
  useEffect(() => {
    if (!ref.current) return;
    const el = ref.current;
    const io = new IntersectionObserver(
      (entries) => {
        entries.forEach((e) => {
          if (e.isIntersecting) {
            setInView(true);
            io.unobserve(el);
          }
        });
      },
      { threshold: 0.15, rootMargin: "-8% 0px", ...opts }
    );
    io.observe(el);
    return () => io.disconnect();
  }, []);
  return [ref, inView];
}

function Reveal({ children, delay = 0, className = "", as: Tag = "div" }) {
  const [ref, inView] = useInView();
  const style = { transitionDelay: `${delay}ms` };
  return (
    <Tag
      ref={ref}
      className={`reveal ${inView ? "in" : ""} ${className}`}
      style={style}
    >
      {children}
    </Tag>
  );
}

function TiltCard({ children, className = "", intensity = 8 }) {
  const ref = useRef(null);
  const onMove = (e) => {
    if (prefersReducedMotion()) return;
    const el = ref.current;
    if (!el) return;
    const r = el.getBoundingClientRect();
    const x = (e.clientX - r.left) / r.width;
    const y = (e.clientY - r.top) / r.height;
    const rx = (0.5 - y) * intensity;
    const ry = (x - 0.5) * intensity;
    el.style.transform = `perspective(900px) rotateX(${rx}deg) rotateY(${ry}deg) translateZ(0)`;
    el.style.setProperty("--mx", `${x * 100}%`);
    el.style.setProperty("--my", `${y * 100}%`);
    el.style.setProperty("--stroke-angle", `${(x + y) * 180}deg`);
  };
  const onLeave = () => {
    const el = ref.current;
    if (!el) return;
    el.style.transform = "perspective(900px) rotateX(0deg) rotateY(0deg)";
  };
  return (
    <div
      ref={ref}
      className={`tilt-card glass rounded-2xl p-6 md:p-7 ${className}`}
      onMouseMove={onMove}
      onMouseLeave={onLeave}
    >
      <span className="tilt-stroke" />
      <span className="tilt-shine" />
      <div className="relative" style={{ transform: "translateZ(30px)" }}>
        {children}
      </div>
    </div>
  );
}

function MagneticButton({
  children,
  href,
  onClick,
  variant = "primary",
  className = "",
  external = false,
}) {
  const ref = useRef(null);
  const onMove = (e) => {
    if (prefersReducedMotion()) return;
    const el = ref.current;
    if (!el) return;
    const r = el.getBoundingClientRect();
    const x = e.clientX - (r.left + r.width / 2);
    const y = e.clientY - (r.top + r.height / 2);
    el.style.transform = `translate(${x * 0.18}px, ${y * 0.25}px)`;
  };
  const onLeave = () => {
    const el = ref.current;
    if (!el) return;
    el.style.transform = "translate(0,0)";
  };
  const base =
    "inline-flex items-center gap-2 rounded-xl px-5 py-3 text-sm font-semibold transition relative magnetic";
  const styles = {
    primary:
      "bg-signal text-ink shadow-glow hover:shadow-glow-lg hover:bg-[#2ed8a8]",
    ghost:
      "border border-white/15 bg-white/5 text-mist backdrop-blur hover:border-signal/45 hover:bg-white/10",
    minimal:
      "border border-white/10 text-slate hover:border-white/20 hover:text-mist",
  };
  const cls = `${base} ${styles[variant]} ${className}`;
  const props = {
    ref,
    className: cls,
    onMouseMove: onMove,
    onMouseLeave: onLeave,
    onClick,
  };
  if (href) {
    return (
      <a
        href={href}
        target={external ? "_blank" : undefined}
        rel={external ? "noreferrer noopener" : undefined}
        {...props}
      >
        {children}
      </a>
    );
  }
  return (
    <button type="button" {...props}>
      {children}
    </button>
  );
}

function SectionShell({
  id,
  eyebrow,
  title,
  subtitle,
  children,
  className = "",
}) {
  return (
    <section
      id={id}
      className={`relative scroll-mt-24 py-20 md:py-28 ${className}`}
    >
      <div className="relative z-10 mx-auto max-w-6xl px-4 sm:px-6">
        <Reveal>
          <p className="font-mono text-xs uppercase tracking-[0.28em] text-signal/85">
            {eyebrow}
          </p>
        </Reveal>
        <Reveal delay={80}>
          <h2 className="mt-3 max-w-4xl text-3xl font-semibold leading-tight tracking-tight text-mist md:text-5xl">
            {title}
          </h2>
        </Reveal>
        {subtitle && (
          <Reveal delay={140}>
            <p className="mt-5 max-w-3xl text-base leading-relaxed text-slate md:text-lg">
              {subtitle}
            </p>
          </Reveal>
        )}
        <div className="mt-12 md:mt-16">{children}</div>
      </div>
    </section>
  );
}

// Inline icon set (matches lucide style — no external deps)
function Icon({ name, className = "h-5 w-5", strokeWidth = 1.6 }) {
  const paths = {
    shield: <path d="M12 3l8 3v6c0 5-3.5 8.5-8 9-4.5-.5-8-4-8-9V6l8-3z" />,
    arrow: <path d="M5 12h14M13 5l7 7-7 7" />,
    chevronDown: <path d="M6 9l6 6 6-6" />,
    layers: (
      <g>
        <path d="M12 3l9 5-9 5-9-5 9-5z" />
        <path d="M3 13l9 5 9-5M3 18l9 5 9-5" />
      </g>
    ),
    scale: (
      <g>
        <path d="M3 6h18M12 3v3M6 6l-3 6a3 3 0 006 0L6 6zM18 6l-3 6a3 3 0 006 0L18 6z" />
        <path d="M9 21h6" />
      </g>
    ),
    workflow: (
      <g>
        <rect x="3" y="3" width="6" height="6" rx="1" />
        <rect x="15" y="15" width="6" height="6" rx="1" />
        <path d="M9 6h6a3 3 0 013 3v6" />
      </g>
    ),
    git: (
      <g>
        <circle cx="6" cy="6" r="2" />
        <circle cx="18" cy="18" r="2" />
        <circle cx="6" cy="18" r="2" />
        <path d="M6 8v8M8 6h6a4 4 0 014 4v6" />
      </g>
    ),
    alert: (
      <g>
        <path d="M12 3l10 18H2L12 3z" />
        <path d="M12 10v5M12 18v.01" />
      </g>
    ),
    sliders: (
      <g>
        <path d="M3 6h12M21 6h-2M3 12h6M21 12h-8M3 18h14M21 18h-2" />
        <circle cx="17" cy="6" r="2" />
        <circle cx="11" cy="12" r="2" />
        <circle cx="19" cy="18" r="2" />
      </g>
    ),
    merge: (
      <g>
        <circle cx="6" cy="6" r="2" />
        <circle cx="6" cy="18" r="2" />
        <circle cx="18" cy="18" r="2" />
        <path d="M6 8v8M6 8a6 6 0 006 6h4" />
      </g>
    ),
    radar: (
      <g>
        <circle cx="12" cy="12" r="9" />
        <circle cx="12" cy="12" r="5" />
        <path d="M12 12l5-5" />
      </g>
    ),
    check: (
      <g>
        <circle cx="12" cy="12" r="9" />
        <path d="M8 12l3 3 5-6" />
      </g>
    ),
    scroll: (
      <g>
        <path d="M5 4h11l3 3v13a1 1 0 01-1 1H6a1 1 0 01-1-1V4z" />
        <path d="M9 9h7M9 13h7M9 17h4" />
      </g>
    ),
    file: (
      <g>
        <path d="M14 3H6a1 1 0 00-1 1v16a1 1 0 001 1h12a1 1 0 001-1V8l-5-5z" />
        <path d="M14 3v5h5" />
      </g>
    ),
    book: (
      <g>
        <path d="M4 5a2 2 0 012-2h13v16H6a2 2 0 00-2 2V5z" />
        <path d="M4 19a2 2 0 002-2h13" />
      </g>
    ),
    badge: (
      <g>
        <path d="M12 3l2.5 2.5L18 6l.5 3.5L21 12l-2.5 2.5L18 18l-3.5.5L12 21l-2.5-2.5L6 18l-.5-3.5L3 12l2.5-2.5L6 6l3.5-.5L12 3z" />
        <path d="M9 12l2 2 4-4" />
      </g>
    ),
    github: (
      <g>
        <path d="M12 2a10 10 0 00-3.16 19.49c.5.09.68-.22.68-.48v-1.7c-2.78.6-3.37-1.34-3.37-1.34-.46-1.16-1.12-1.47-1.12-1.47-.92-.62.07-.61.07-.61 1.01.07 1.55 1.04 1.55 1.04.9 1.55 2.36 1.1 2.94.84.09-.66.35-1.1.64-1.36-2.22-.25-4.55-1.11-4.55-4.94 0-1.09.39-1.99 1.03-2.69-.1-.25-.45-1.27.1-2.65 0 0 .84-.27 2.75 1.02a9.5 9.5 0 015 0c1.91-1.29 2.75-1.02 2.75-1.02.55 1.38.2 2.4.1 2.65.64.7 1.03 1.6 1.03 2.69 0 3.84-2.34 4.69-4.57 4.93.36.31.68.92.68 1.85v2.74c0 .26.18.58.69.48A10 10 0 0012 2z" />
      </g>
    ),
    cpu: (
      <g>
        <rect x="6" y="6" width="12" height="12" rx="1.5" />
        <path d="M9 9h6v6H9z" />
        <path d="M9 2v3M15 2v3M9 19v3M15 19v3M2 9h3M2 15h3M19 9h3M19 15h3" />
      </g>
    ),
    zap: <path d="M13 2L4 14h7l-1 8 9-12h-7l1-8z" />,
    target: (
      <g>
        <circle cx="12" cy="12" r="9" />
        <circle cx="12" cy="12" r="5" />
        <circle cx="12" cy="12" r="1.5" />
      </g>
    ),
    sparkles: (
      <g>
        <path d="M12 3l1.5 4.5L18 9l-4.5 1.5L12 15l-1.5-4.5L6 9l4.5-1.5L12 3z" />
        <path d="M19 15l.7 2.3L22 18l-2.3.7L19 21l-.7-2.3L16 18l2.3-.7L19 15z" />
      </g>
    ),
    rocket: (
      <g>
        <path d="M14 4c4 0 6 2 6 6 0 4-4 8-9 12l-4-4c4-5 8-9 12-9-1-3-3-5-5-5z" />
        <circle cx="14" cy="10" r="1.5" />
        <path d="M7 17l-3 3M9 14c-2 1-4 3-4 6 3 0 5-2 6-4" />
      </g>
    ),
    satellite: (
      <g>
        <path d="M5 13l6-6 6 6-6 6-6-6z" />
        <path d="M9 9l-3-3M15 15l3 3" />
        <path d="M19 5a4 4 0 00-4 4M21 9a8 8 0 00-8-8" />
      </g>
    ),
    network: (
      <g>
        <circle cx="12" cy="5" r="2" />
        <circle cx="5" cy="19" r="2" />
        <circle cx="19" cy="19" r="2" />
        <path d="M12 7v3M12 14l-5 4M12 14l5 4" />
        <rect x="9" y="10" width="6" height="4" rx="1" />
      </g>
    ),
    folder: (
      <g>
        <path d="M3 5a1 1 0 011-1h5l2 2h9a1 1 0 011 1v11a1 1 0 01-1 1H4a1 1 0 01-1-1V5z" />
      </g>
    ),
    terminal: (
      <g>
        <rect x="3" y="4" width="18" height="16" rx="1" />
        <path d="M7 9l3 3-3 3M13 15h4" />
      </g>
    ),
    package: (
      <g>
        <path d="M3 7l9-4 9 4-9 4-9-4z" />
        <path d="M3 7v10l9 4 9-4V7" />
        <path d="M12 11v10" />
      </g>
    ),
    fingerprint: (
      <g>
        <path d="M12 4a8 8 0 00-8 8c0 1 .5 4 2 6" />
        <path d="M8 12a4 4 0 018 0c0 2-.5 4-2 6" />
        <path d="M12 12c0 4-1 6-2 8" />
      </g>
    ),
    fileKey: (
      <g>
        <path d="M14 3H6a1 1 0 00-1 1v16a1 1 0 001 1h12a1 1 0 001-1V8l-5-5z" />
        <circle cx="11" cy="14" r="2" />
        <path d="M13 14h3M16 14v3" />
      </g>
    ),
    fileWarn: (
      <g>
        <path d="M14 3H6a1 1 0 00-1 1v16a1 1 0 001 1h12a1 1 0 001-1V8l-5-5z" />
        <path d="M12 11v3M12 17v.01" />
      </g>
    ),
    pull: (
      <g>
        <circle cx="6" cy="6" r="2" />
        <circle cx="6" cy="18" r="2" />
        <circle cx="18" cy="18" r="2" />
        <path d="M6 8v8M14 6h2a2 2 0 012 2v8" />
      </g>
    ),
    gauge: (
      <g>
        <path d="M12 13l4-4" />
        <path d="M3 13a9 9 0 0118 0" />
      </g>
    ),
    scan: (
      <g>
        <path d="M3 7V4h3M21 7V4h-3M3 17v3h3M21 17v3h-3" />
        <path d="M7 12h10" />
      </g>
    ),
    lock: (
      <g>
        <rect x="5" y="11" width="14" height="10" rx="1.5" />
        <path d="M8 11V7a4 4 0 018 0v4" />
      </g>
    ),
    clipboard: (
      <g>
        <path d="M9 4h6v3H9z" />
        <path d="M5 6h2v14a1 1 0 001 1h8a1 1 0 001-1V6h2" />
        <path d="M9 12h6M9 16h6" />
      </g>
    ),
    link: (
      <g>
        <path d="M10 13l4-4M8 16l-2 2a3 3 0 01-4-4l3-3M16 8l2-2a3 3 0 014 4l-3 3" />
      </g>
    ),
    octagon: (
      <g>
        <path d="M8 3h8l5 5v8l-5 5H8l-5-5V8l5-5z" />
        <path d="M12 8v5M12 16v.01" />
      </g>
    ),
    x: <path d="M6 6l12 12M6 18L18 6" />,
    menu: <path d="M3 6h18M3 12h18M3 18h18" />,
    check2: <path d="M5 12l5 5 9-11" />,
    code: (
      <g>
        <path d="M8 6l-5 6 5 6M16 6l5 6-5 6M14 4l-4 16" />
      </g>
    ),
    book2: (
      <g>
        <path d="M4 5a2 2 0 012-2h13v16H6a2 2 0 00-2 2V5z" />
        <path d="M9 7h6M9 11h6" />
      </g>
    ),
  };
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={strokeWidth}
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      aria-hidden="true"
    >
      {paths[name] || null}
    </svg>
  );
}

function scrollToId(id) {
  const el = document.getElementById(id);
  if (el) el.scrollIntoView({ behavior: "smooth", block: "start" });
}

const REPO_URL =
  "https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit";
const DOCS_URL = `${REPO_URL}/tree/master/docs`;

Object.assign(window, {
  Reveal,
  TiltCard,
  MagneticButton,
  SectionShell,
  Icon,
  scrollToId,
  prefersReducedMotion,
  useInView,
  REPO_URL,
  DOCS_URL,
});
