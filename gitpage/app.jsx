// App entry — composes all sections

function App() {
  return (
    <div className="relative">
      <AmbientBackground />
      <SiteHeader />
      <main className="relative z-10">
        <Hero />
        <ProblemSection />
        <ComparisonSection />
        <ScopeSection />
        <WorkflowSection />
        <SampleOutputSection />
        <QuickstartSection />
        <CapabilitiesSection />
        <FrameworksSection />
        <EvaluationStatesSection />
        <DifferentiatorsSection />
        <SignalsSection />
        <RoadmapSection />
        <RepoAnatomySection />
        <CTASection />
        <SiteFooter />
      </main>
    </div>
  );
}

const root = ReactDOM.createRoot(document.getElementById("root"));
root.render(<App />);
