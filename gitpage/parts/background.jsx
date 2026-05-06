// Ambient backgrounds: aurora, grid floor, cursor glow

function AmbientBackground() {
  useEffect(() => {
    if (prefersReducedMotion()) return;
    const glow = document.getElementById("cursor-glow");
    if (!glow) return;
    let raf = 0;
    let tx = window.innerWidth / 2;
    let ty = window.innerHeight / 2;
    let cx = tx;
    let cy = ty;
    const move = (e) => {
      tx = e.clientX;
      ty = e.clientY;
    };
    const tick = () => {
      cx += (tx - cx) * 0.15;
      cy += (ty - cy) * 0.15;
      glow.style.left = `${cx}px`;
      glow.style.top = `${cy}px`;
      raf = requestAnimationFrame(tick);
    };
    window.addEventListener("mousemove", move);
    raf = requestAnimationFrame(tick);
    return () => {
      window.removeEventListener("mousemove", move);
      cancelAnimationFrame(raf);
    };
  }, []);

  return (
    <>
      <div className="fixed inset-0 z-0 pointer-events-none">
        <div className="aurora">
          <div className="aurora-blob aurora-1" />
          <div className="aurora-blob aurora-2" />
          <div className="aurora-blob aurora-3" />
        </div>
      </div>
      <div className="fixed inset-x-0 bottom-0 z-0 pointer-events-none grid-floor">
        <div className="grid-floor-inner" />
      </div>
      <div id="cursor-glow" className="cursor-glow" aria-hidden="true" />
      <div className="noise" aria-hidden="true" />
    </>
  );
}

window.AmbientBackground = AmbientBackground;
