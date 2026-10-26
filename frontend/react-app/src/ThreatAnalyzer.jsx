
export default function ThreatAnalyzer() {
  return (
    <section className="rounded-2xl border border-white/10 bg-zinc-900 p-6">
      <div className="mb-4 flex items-center gap-3">
        <div className="rounded-xl bg-cyan-400/10 p-3 text-cyan-300">
          <span className="text-xl">🛡️</span>
        </div>
        <div>
          <h2 className="text-xl font-semibold text-white">
            Trust Lens — Threat Analysis
          </h2>
          <p className="mt-1 text-sm text-zinc-400">
            Multi-vector security analysis workspace
          </p>
        </div>
      </div>

      <div className="rounded-xl border border-amber-400/20 bg-amber-400/5 p-4">
        <p className="font-medium text-amber-300">Demo mode</p>
        <p className="mt-1 text-sm text-zinc-400">
          The analyzer workspace is ready. AI analysis will be enabled after
          connecting the team's backend API.
        </p>
      </div>
    </section>
  )
}
