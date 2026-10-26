
import { useState } from 'react'
import {
  ShieldCheck,
  LayoutDashboard,
  ScanSearch,
  FileSearch,
  History,
  Bell,
  Search,
  ShieldAlert,
  Activity,
  Globe,
  ArrowUpRight,
  LockKeyhole,
  ChevronRight,
  CircleDot,
} from 'lucide-react'

import ThreatAnalyzer from './ThreatAnalyzer.jsx'

const navigation = [
  { label: 'Overview', icon: LayoutDashboard },
  { label: 'Threat Analysis', icon: ScanSearch },
  { label: 'File Integrity', icon: FileSearch },
  { label: 'Incident Timeline', icon: History },
]

function App() {
  const [activeNav, setActiveNav] = useState('Overview')
  const [url, setUrl] = useState('')
  const [result, setResult] = useState(null)

  function handleScan(event) {
    event.preventDefault()

    if (!url.trim()) {
      setResult({
        title: 'URL required',
        detail: 'Enter a website address to continue.',
        type: 'warning',
      })
      return
    }

    let parsed

    try {
      parsed = new URL(
        /^[a-zA-Z][a-zA-Z\d+.-]*:/.test(url.trim())
          ? url.trim()
          : `https://${url.trim()}`
      )
    } catch {
      setResult({
        title: 'Invalid URL format',
        detail: 'Check the address and try again.',
        type: 'warning',
      })
      return
    }

    if (!['http:', 'https:'].includes(parsed.protocol)) {
      setResult({
        title: 'Unsupported URL protocol',
        detail: 'Enter an HTTP or HTTPS address.',
        type: 'warning',
      })
      return
    }

    setResult({
      title: 'Demo analysis completed',
      detail: `${parsed.hostname} was accepted as input. No real threat analysis has been performed.`,
      type: 'info',
    })
  }

  function renderWorkspacePage() {
    if (activeNav === 'Threat Analysis') {
      return <ThreatAnalyzer />
    }

    if (activeNav === 'File Integrity') {
      return (
        <section className="space-y-6">
          <div>
            <div className="flex items-center gap-3">
              <div className="rounded-xl bg-cyan-400/10 p-3 text-cyan-300">
                <FileSearch size={23} />
              </div>
              <div>
                <h3 className="text-xl font-semibold">
                  File Integrity Monitor
                </h3>
                <p className="mt-1 text-sm text-zinc-400">
                  Monitor file fingerprints and identify unexpected changes.
                </p>
              </div>
            </div>
          </div>

          <div className="rounded-2xl border border-white/10 bg-zinc-900/60 p-6 sm:p-8">
            <div className="rounded-xl border border-dashed border-white/15 p-8 text-center">
              <LockKeyhole
                size={34}
                className="mx-auto text-cyan-300"
              />
              <h4 className="mt-4 font-semibold">
                File integrity workspace
              </h4>
              <p className="mx-auto mt-2 max-w-md text-sm leading-6 text-zinc-400">
                This workspace will help detect file modifications using
                cryptographic hashes. File monitoring is not connected yet.
              </p>
              <span className="mt-5 inline-flex rounded-full border border-amber-400/20 bg-amber-400/5 px-3 py-1.5 text-xs text-amber-300">
                Monitoring not connected
              </span>
            </div>
          </div>
        </section>
      )
    }

    if (activeNav === 'Incident Timeline') {
      return (
        <section className="space-y-6">
          <div className="flex items-center gap-3">
            <div className="rounded-xl bg-cyan-400/10 p-3 text-cyan-300">
              <History size={23} />
            </div>
            <div>
              <h3 className="text-xl font-semibold">Incident Timeline</h3>
              <p className="mt-1 text-sm text-zinc-400">
                Review security scans and incident response activity.
              </p>
            </div>
          </div>

          <div className="rounded-2xl border border-white/10 bg-zinc-900/60 p-6 sm:p-8">
            <div className="rounded-xl border border-dashed border-white/15 p-8 text-center">
              <Activity size={34} className="mx-auto text-cyan-300" />
              <h4 className="mt-4 font-semibold">No incidents recorded</h4>
              <p className="mx-auto mt-2 max-w-md text-sm leading-6 text-zinc-400">
                Security events and remediation activity will appear here
                when incident history is implemented.
              </p>
              <span className="mt-5 inline-flex rounded-full border border-amber-400/20 bg-amber-400/5 px-3 py-1.5 text-xs text-amber-300">
                Waiting for scan history
              </span>
            </div>
          </div>
        </section>
      )
    }

    return null
  }

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100">
      {/* Sidebar */}
      <aside className="fixed inset-y-0 left-0 z-20 hidden w-64 border-r border-white/10 bg-zinc-950 p-5 lg:flex lg:flex-col">
        <div className="flex items-center gap-3">
          <div className="rounded-xl bg-cyan-400/10 p-2.5 text-cyan-300">
            <ShieldCheck size={25} />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-[0.2em]">
              Trust Lens
            </h1>
            <p className="text-[10px] tracking-[0.22em] text-zinc-500">
              THREAT INTELLIGENCE
            </p>
          </div>
        </div>

        <div className="mt-12">
          <p className="mb-3 px-3 text-[10px] font-semibold tracking-[0.2em] text-zinc-600">
            WORKSPACE
          </p>

          <nav className="space-y-1">
            {navigation.map(({ label, icon: Icon }) => (
              <button
                key={label}
                type="button"
                onClick={() => setActiveNav(label)}
                aria-current={activeNav === label ? 'page' : undefined}
                className={`flex w-full items-center gap-3 rounded-xl border px-3 py-3 text-left text-sm transition ${
                  activeNav === label
                    ? 'border-cyan-400/20 bg-cyan-400/10 text-cyan-300'
                    : 'border-transparent text-zinc-400 hover:bg-white/5 hover:text-white'
                }`}
              >
                <Icon size={18} />
                <span>{label}</span>
                {activeNav === label && (
                  <ChevronRight className="ml-auto" size={16} />
                )}
              </button>
            ))}
          </nav>
        </div>

        <div className="mt-auto rounded-2xl border border-white/10 bg-zinc-900/70 p-4">
          <div className="flex items-center gap-2 text-xs font-medium text-emerald-400">
            <CircleDot size={14} />
            Frontend demo mode
          </div>
          <p className="mt-2 text-xs leading-5 text-zinc-500">
            AI analysis and backend connectivity have not been enabled yet.
          </p>
        </div>
      </aside>

      {/* Main workspace */}
      <main className="min-h-screen lg:ml-64">
        <header className="flex items-center justify-between border-b border-white/10 px-5 py-5 sm:px-8">
          <div>
            <p className="text-xs text-zinc-500">
              Security Operations / Workspace
            </p>
            <h2 className="mt-1 text-lg font-semibold">{activeNav}</h2>
          </div>

          <div className="flex items-center gap-3">
            <span className="hidden rounded-full border border-amber-400/20 bg-amber-400/10 px-3 py-1.5 text-xs text-amber-300 sm:inline-flex">
              DEMO ENVIRONMENT
            </span>
            <button
              type="button"
              aria-label="Notifications"
              className="rounded-xl border border-white/10 p-2.5 text-zinc-400 hover:text-white"
            >
              <Bell size={18} />
            </button>
            <div className="flex h-9 w-9 items-center justify-center rounded-full bg-cyan-400/15 text-sm font-semibold text-cyan-300">
              T
            </div>
          </div>
        </header>

        <div className="mx-auto max-w-7xl space-y-7 p-5 sm:p-8">
          {activeNav === 'Overview' ? (
            <>
              {/* Welcome banner */}
              <section className="relative overflow-hidden rounded-3xl border border-cyan-400/15 bg-gradient-to-br from-cyan-950/70 via-zinc-900 to-zinc-950 p-6 sm:p-9">
                <div className="pointer-events-none absolute -right-12 -top-20 h-64 w-64 rounded-full bg-cyan-400/10 blur-3xl" />

                <div className="relative max-w-2xl">
                  <div className="mb-4 inline-flex items-center gap-2 rounded-full border border-cyan-400/20 bg-cyan-400/10 px-3 py-1.5 text-xs text-cyan-300">
                    <Activity size={14} />
                    SECURITY INTELLIGENCE CONSOLE
                  </div>

                  <h3 className="text-3xl font-semibold leading-tight tracking-tight sm:text-4xl">
                    See beyond the
                    <span className="text-cyan-300"> threat.</span>
                  </h3>

                  <p className="mt-3 max-w-xl text-sm leading-6 text-zinc-400 sm:text-base">
                    A unified workspace for phishing analysis, domain
                    inspection, and incident response.
                  </p>

                  <button
                    type="button"
                    onClick={() => setActiveNav('Threat Analysis')}
                    className="mt-6 inline-flex items-center gap-2 rounded-xl bg-cyan-300 px-5 py-3 text-sm font-semibold text-zinc-950 transition hover:bg-cyan-200"
                  >
                    Open threat console <ArrowUpRight size={17} />
                  </button>
                </div>
              </section>

              {/* Dashboard metrics */}
              <section className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
                {[
                  {
                    label: 'Total Scanned',
                    value: '0',
                    note: 'No scan history recorded',
                    icon: Search,
                    color: 'text-cyan-300',
                  },
                  {
                    label: 'Threats Neutralized',
                    value: '0',
                    note: 'No remediation actions recorded',
                    icon: ShieldCheck,
                    color: 'text-emerald-400',
                  },
                  {
                    label: 'Active Incidents',
                    value: '0',
                    note: 'No real incident feed connected',
                    icon: ShieldAlert,
                    color: 'text-amber-300',
                  },
                ].map((stat) => (
                  <article
                    key={stat.label}
                    className="rounded-2xl border border-white/10 bg-zinc-900/60 p-5"
                  >
                    <div className="flex items-start justify-between">
                      <p className="text-sm text-zinc-400">{stat.label}</p>
                      <stat.icon className={stat.color} size={19} />
                    </div>
                    <p className="mt-5 text-3xl font-semibold">
                      {stat.value}
                    </p>
                    <p className="mt-2 text-xs text-zinc-500">
                      {stat.note}
                    </p>
                  </article>
                ))}
              </section>

              {/* Quick URL check and intelligence status */}
              <section className="grid items-start gap-5 xl:grid-cols-[1.4fr_0.8fr]">
                <article className="rounded-2xl border border-white/10 bg-zinc-900/60 p-5 sm:p-7">
                  <div className="flex items-center gap-3">
                    <div className="rounded-xl bg-cyan-400/10 p-2.5 text-cyan-300">
                      <Globe size={20} />
                    </div>
                    <div>
                      <h3 className="font-semibold">Quick URL Check</h3>
                      <p className="mt-1 text-xs text-zinc-500">
                        Enter a URL to try the interface
                      </p>
                    </div>
                  </div>

                  <form onSubmit={handleScan} className="mt-6 space-y-3">
                    <label
                      htmlFor="url-input"
                      className="text-xs text-zinc-400"
                    >
                      Website address
                    </label>
                    <div className="flex flex-col gap-3 sm:flex-row">
                      <input
                        id="url-input"
                        type="text"
                        value={url}
                        onChange={(event) => setUrl(event.target.value)}
                        placeholder="https://example.com"
                        className="min-w-0 flex-1 rounded-xl border border-white/10 bg-zinc-950 px-4 py-3 text-sm outline-none placeholder:text-zinc-600 focus:border-cyan-400/60"
                      />
                      <button
                        type="submit"
                        className="inline-flex items-center justify-center gap-2 rounded-xl bg-cyan-300 px-5 py-3 text-sm font-semibold text-zinc-950 hover:bg-cyan-200"
                      >
                        <ScanSearch size={17} /> Test URL
                      </button>
                    </div>
                  </form>

                  {result && (
                    <div
                      role="status"
                      className={`mt-5 rounded-xl border p-4 ${
                        result.type === 'warning'
                          ? 'border-amber-400/20 bg-amber-400/5'
                          : 'border-cyan-400/20 bg-cyan-400/5'
                      }`}
                    >
                      <p className="text-sm font-semibold">{result.title}</p>
                      <p className="mt-1 break-words text-sm leading-6 text-zinc-400">
                        {result.detail}
                      </p>
                    </div>
                  )}

                  <p className="mt-4 text-xs leading-5 text-zinc-500">
                    Demo only: this form does not contact an AI model or
                    verify whether a website is safe.
                  </p>
                </article>

                <article className="rounded-2xl border border-white/10 bg-zinc-900/60 p-5 sm:p-7">
                  <div className="flex items-center gap-3">
                    <div className="rounded-xl bg-emerald-400/10 p-2.5 text-emerald-400">
                      <LockKeyhole size={20} />
                    </div>
                    <div>
                      <h3 className="font-semibold">Threat Intelligence</h3>
                      <p className="mt-1 text-xs text-zinc-500">
                        Analysis status
                      </p>
                    </div>
                  </div>

                  <div className="mt-6 rounded-xl border border-white/10 bg-zinc-950/70 p-5 text-center">
                    <div className="mx-auto flex h-24 w-24 items-center justify-center rounded-full border-4 border-zinc-800">
                      <span className="text-2xl font-semibold text-zinc-500">
                        —
                      </span>
                    </div>
                    <p className="mt-4 font-medium">
                      Awaiting analysis engine
                    </p>
                    <p className="mt-2 text-xs leading-5 text-zinc-500">
                      Verdict and threat score will appear here after backend
                      integration.
                    </p>
                  </div>

                  <div className="mt-4 flex items-center gap-2 text-xs text-amber-300">
                    <CircleDot size={13} />
                    AI engine not connected
                  </div>
                </article>
              </section>

              <footer className="border-t border-white/10 py-5 text-center text-xs text-zinc-600">
                Trust Lens · Threat Intelligence Workspace · Development
                Preview
              </footer>
            </>
          ) : (
            renderWorkspacePage()
          )}
        </div>
      </main>
    </div>
  )
}

export default App
