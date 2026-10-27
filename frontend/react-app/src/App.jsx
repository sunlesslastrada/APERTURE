import { useCallback, useEffect, useState } from "react";
import {
  ShieldCheck,
  LayoutDashboard,
  ScanSearch,
  History,
  ShieldAlert,
  Activity,
  AlertTriangle,
  CheckCircle2,
  Clock3,
  ArrowUpRight,
  Menu,
  X,
  TrendingUp,
  Radar,
  ClipboardList,
  Copy,
  Mail,
  Link2,
  Tag,
  Radio,
} from "lucide-react";
import MessageDeepScan from "./MessageDeepScan.jsx";
import DomainSentinel from "./DomainSentinel.jsx";

const HISTORY_KEY = "aperture-threat-history";
const LEGACY_HISTORY_KEY = "trust-lens-history";

const NAV_ITEMS = [
  { name: "Overview", icon: LayoutDashboard },
  { name: "Message DeepScan", icon: Mail },
  { name: "Domain Sentinel", icon: Link2 },
  { name: "Incident Responder", icon: History },
];

function readHistory() {
  try {
    const saved = localStorage.getItem(HISTORY_KEY);
    if (saved) {
      const parsed = JSON.parse(saved);
      if (Array.isArray(parsed)) return parsed;
    }
    // Backward compatibility fallback & migration
    const legacy = localStorage.getItem(LEGACY_HISTORY_KEY);
    if (legacy) {
      const parsed = JSON.parse(legacy);
      if (Array.isArray(parsed) && parsed.length) {
        try {
          localStorage.setItem(HISTORY_KEY, JSON.stringify(parsed));
        } catch {}
        return parsed;
      }
    }
    return [];
  } catch {
    return [];
  }
}

function getVerdict(item) {
  return String(item?.verdict || "UNKNOWN").toUpperCase();
}

function getScore(item) {
  const score = Number(item?.threat_score ?? item?.score ?? 0);
  return Number.isFinite(score) ? score : 0;
}

function getSender(item) {
  return (
    item?.sender_analysis?.sender_email ||
    item?.sender ||
    item?.input?.sender ||
    item?.input?.url ||
    item?.url ||
    "Vector Inspection"
  );
}

function getTimestamp(item) {
  return item?.timestamp ? String(item.timestamp) : "Saved scan";
}

function getIncidentKey(item, index) {
  return String(item?.id || item?.timestamp || `incident-${index}`);
}

function verdictStyle(verdict) {
  switch (verdict) {
    case "PHISHING":
      return "border-red-500/20 bg-red-500/10 text-red-400";
    case "SUSPICIOUS":
      return "border-amber-500/20 bg-amber-500/10 text-amber-400";
    case "SAFE":
      return "border-emerald-500/20 bg-emerald-500/10 text-emerald-400";
    default:
      return "border-slate-700 bg-slate-800 text-slate-300";
  }
}

function VerdictBadge({ verdict }) {
  return (
    <span
      className={`inline-flex items-center rounded-full border px-3 py-1 text-xs font-semibold ${verdictStyle(
        verdict
      )}`}
    >
      {verdict}
    </span>
  );
}

function StatCard({
  title,
  value,
  description,
  icon: Icon,
  color,
  tint,
}) {
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5 transition hover:border-slate-700">
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-sm text-slate-400">{title}</p>
          <p className="mt-3 text-3xl font-bold tracking-tight text-white">
            {value}
          </p>
        </div>

        <div className={`rounded-xl p-3 ${tint}`}>
          <Icon size={22} className={color} />
        </div>
      </div>

      <p className="mt-4 text-xs text-slate-500">{description}</p>
    </div>
  );
}

function IncidentRow({ item }) {
  const verdict = getVerdict(item);
  const archetype = item?.threat_archetype || item?.playbook?.threat_archetype;

  return (
    <div className="flex flex-col gap-3 rounded-xl border border-slate-800 bg-slate-950/60 p-4 sm:flex-row sm:items-center sm:justify-between">
      <div className="flex min-w-0 items-center gap-3">
        <div className="rounded-xl bg-slate-800 p-2.5">
          <ShieldAlert size={19} className="text-slate-300" />
        </div>

        <div className="min-w-0">
          <p className="break-all text-sm font-medium text-slate-200">
            {getSender(item)}
          </p>
          <p className="mt-1 text-xs text-slate-500">
            {getTimestamp(item)}
          </p>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-2 pl-1 sm:pl-0">
        {archetype && archetype !== "BENIGN_LEGITIMATE" && (
          <span className="hidden sm:inline-flex rounded-md border border-cyan-500/20 bg-cyan-500/5 px-2 py-0.5 text-[11px] font-medium text-cyan-300">
            {archetype.replace(/_/g, " ")}
          </span>
        )}
        <VerdictBadge verdict={verdict} />
        <span className="whitespace-nowrap text-sm text-slate-400 font-mono">
          {getScore(item)}/100
        </span>
      </div>
    </div>
  );
}

function Overview({ history, onNavigate }) {
  const total = history.length;

  const phishing = history.filter(
    (item) => getVerdict(item) === "PHISHING"
  ).length;

  const suspicious = history.filter(
    (item) => getVerdict(item) === "SUSPICIOUS"
  ).length;

  const safe = history.filter(
    (item) => getVerdict(item) === "SAFE"
  ).length;

  const stats = [
    {
      title: "Total Vectors Scanned",
      value: total,
      description: "Inspections recorded in SecOps database",
      icon: Activity,
      color: "text-cyan-400",
      tint: "bg-cyan-500/10",
    },
    {
      title: "Phishing Neutralized",
      value: phishing,
      description: "Adversarial payloads classified as malicious",
      icon: ShieldAlert,
      color: "text-red-400",
      tint: "bg-red-500/10",
    },
    {
      title: "Active Incidents",
      value: phishing + suspicious,
      description: "Escalated to NIST containment playbooks",
      icon: AlertTriangle,
      color: "text-amber-400",
      tint: "bg-amber-500/10",
    },
    {
      title: "Verified Legitimate",
      value: safe,
      description: "Clean transactional communications",
      icon: CheckCircle2,
      color: "text-emerald-400",
      tint: "bg-emerald-500/10",
    },
  ];

  return (
    <div className="space-y-8">
      <section>
        <div className="mb-3 inline-flex items-center gap-2 rounded-full border border-cyan-500/20 bg-cyan-500/5 px-3 py-1.5 text-xs font-medium text-cyan-400">
          <Radar size={14} />
          APERTURE THREAT INTELLIGENCE & REMEDIATION PLATFORM
        </div>

        <h1 className="text-3xl font-bold tracking-tight text-white sm:text-4xl">
          Security Operations Center
        </h1>

        <p className="mt-3 max-w-2xl text-sm leading-6 text-slate-400 sm:text-base">
          Zero-shot LLM reasoning and multimodal OCR vision detecting zero-day phishing,
          adversarial homoglyphs, and psychological extortion with automated Tier-3 containment playbooks.
        </p>
      </section>

      <section className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {stats.map((stat) => (
          <StatCard key={stat.title} {...stat} />
        ))}
      </section>

      {/* Investigation Modules Grid */}
      <section className="grid grid-cols-1 gap-5 xl:grid-cols-2">
        {/* Module 1 Card */}
        <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6 flex flex-col justify-between">
          <div>
            <div className="flex items-start gap-4">
              <div className="rounded-xl bg-cyan-500/10 p-3 text-cyan-400">
                <Mail size={24} />
              </div>

              <div>
                <h2 className="text-lg font-semibold text-white">
                  Message & Email DeepScan
                </h2>
                <p className="mt-2 text-sm leading-6 text-slate-400">
                  Full communication triage inspecting sender identity headers, cognitive urgency extortion,
                  and embedded hyperlinks. Supports raw header ingestion and screenshot OCR.
                </p>
              </div>
            </div>

            <div className="mt-5 flex flex-wrap gap-2">
              {[
                "Sender Spoofing Guard",
                "Psychological Triggers",
                "Multimodal Screenshot OCR",
              ].map((label) => (
                <span
                  key={label}
                  className="rounded-lg border border-slate-800 bg-slate-950 px-3 py-1.5 text-xs text-slate-300"
                >
                  {label}
                </span>
              ))}
            </div>
          </div>

          <button
            onClick={() => onNavigate("Message DeepScan")}
            className="mt-6 inline-flex items-center justify-between rounded-xl bg-cyan-400 px-5 py-3 text-sm font-semibold text-slate-950 transition hover:bg-cyan-300 w-full"
          >
            <span>Initiate Vector Inspection</span>
            <ArrowUpRight size={17} />
          </button>
        </div>

        {/* Module 2 Card */}
        <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6 flex flex-col justify-between">
          <div>
            <div className="flex items-start gap-4">
              <div className="rounded-xl bg-cyan-500/10 p-3 text-cyan-400">
                <Link2 size={24} />
              </div>

              <div>
                <h2 className="text-lg font-semibold text-white">
                  Direct URL & Domain Sentinel
                </h2>
                <p className="mt-2 text-sm leading-6 text-slate-400">
                  Perimeter destination analysis evaluating character homoglyphs, brand typosquatting,
                  deceptive subdomain stacking, and generating one-click DNS sinkhole blocklists.
                </p>
              </div>
            </div>

            <div className="mt-5 flex flex-wrap gap-2">
              {[
                "Homoglyph Detection",
                "Subdomain Stacking",
                "DNS Sinkhole Playbooks",
              ].map((label) => (
                <span
                  key={label}
                  className="rounded-lg border border-slate-800 bg-slate-950 px-3 py-1.5 text-xs text-slate-300"
                >
                  {label}
                </span>
              ))}
            </div>
          </div>

          <button
            onClick={() => onNavigate("Domain Sentinel")}
            className="mt-6 inline-flex items-center justify-between rounded-xl border border-slate-700 bg-slate-800 px-5 py-3 text-sm font-semibold text-slate-200 transition hover:bg-slate-700 w-full"
          >
            <span>Launch Domain Sentinel</span>
            <ArrowUpRight size={17} />
          </button>
        </div>
      </section>

      {/* Recent Analyses Activity */}
      <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5 sm:p-6">
        <div className="mb-5 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-lg font-semibold text-white">
              Recent Vector Triage Activity
            </h2>
            <p className="mt-1 text-sm text-slate-400">
              Live audit timeline recorded in SecOps browser store
            </p>
          </div>

          <button
            onClick={() => onNavigate("Incident Responder")}
            className="text-sm font-medium text-cyan-400 hover:text-cyan-300"
          >
            View Incident Playbooks & Escalations
          </button>
        </div>

        {history.length === 0 ? (
          <div className="rounded-xl border border-dashed border-slate-700 px-5 py-10 text-center">
            <Clock3
              size={30}
              className="mx-auto mb-3 text-slate-500"
            />
            <p className="font-medium text-slate-300">
              No vector analyses recorded yet
            </p>
            <p className="mt-2 text-sm text-slate-500">
              Run your first DeepScan or Sentinel check to populate telemetry.
            </p>
          </div>
        ) : (
          <div className="space-y-3">
            {history.slice(0, 5).map((item, index) => (
              <IncidentRow
                key={getIncidentKey(item, index)}
                item={item}
              />
            ))}
          </div>
        )}
      </section>

      <p className="flex items-center gap-2 text-xs text-slate-500">
        <TrendingUp size={14} />
        Dashboard telemetry synchronized with APERTURE NIST SP 800-61 incident metrics.
      </p>
    </div>
  );
}

function IncidentTimeline({ history }) {
  const [expandedResponses, setExpandedResponses] = useState({});

  const threats = history.filter((item) =>
    ["PHISHING", "SUSPICIOUS"].includes(getVerdict(item))
  );

  function toggleResponse(key, checked) {
    setExpandedResponses((previous) => ({
      ...previous,
      [key]: checked,
    }));
  }

  return (
    <div className="space-y-6">
      <section>
        <p className="mb-2 text-xs font-semibold tracking-widest text-cyan-400">
          INCIDENT PLAYBOOKS · NIST SP 800-61 & MITRE ATT&CK
        </p>
        <h1 className="text-3xl font-bold tracking-tight text-white sm:text-4xl">
          Incident Responder Deck
        </h1>
        <p className="mt-3 text-sm leading-6 text-slate-400">
          Review escalated adversarial payloads, inspect vector-specific IoCs, and dispatch
          pre-composed Tier-3 SOC briefing drafts.
        </p>
      </section>

      <section className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <StatCard
          title="Recorded Scans"
          value={history.length}
          description="All evaluated payloads"
          icon={History}
          color="text-cyan-400"
          tint="bg-cyan-500/10"
        />

        <StatCard
          title="Threat Incidents"
          value={threats.length}
          description="High-severity phishing & suspicious payloads"
          icon={AlertTriangle}
          color="text-amber-400"
          tint="bg-amber-500/10"
        />

        <StatCard
          title="Verified Safe"
          value={
            history.filter((item) => getVerdict(item) === "SAFE").length
          }
          description="Payloads cleared of threat indicators"
          icon={CheckCircle2}
          color="text-emerald-400"
          tint="bg-emerald-500/10"
        />
      </section>

      <section>
        <p className="mb-3 text-base font-bold tracking-[0.2em] text-cyan-400 sm:text-lg">
          CHRONOLOGICAL AUDIT TRAIL
        </p>

        <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5 sm:p-6">
          <h2 className="mb-5 text-lg font-semibold text-white">
            Incident History & Containment Plans
          </h2>

          {history.length === 0 ? (
            <div className="rounded-xl border border-dashed border-slate-700 px-5 py-12 text-center">
              <History
                size={30}
                className="mx-auto mb-3 text-slate-500"
              />
              <p className="font-medium text-slate-300">
                Audit timeline is empty
              </p>
              <p className="mt-2 text-sm text-slate-500">
                Saved vector inspection results will populate automatically.
              </p>
            </div>
          ) : (
            <div className="space-y-4">
              {history.map((item, index) => {
                const key = getIncidentKey(item, index);
                const isExpanded = Boolean(expandedResponses[key]);
                const verdict = getVerdict(item);
                const isThreat = ["PHISHING", "SUSPICIOUS"].includes(verdict);

                const content = item.content_analysis || {};
                const senderAnalysis = item.sender_analysis || {};
                const urlAnalysis = item.url_analysis || {};
                const playbook = item.playbook || {};

                const actions = Array.isArray(playbook.immediate_actions)
                  ? playbook.immediate_actions
                  : [];

                const urls = Array.isArray(urlAnalysis.extracted_urls)
                  ? urlAnalysis.extracted_urls
                  : [];

                const triggers = Array.isArray(content.psychological_triggers)
                  ? content.psychological_triggers
                  : [];

                return (
                  <div
                    key={key}
                    className="rounded-xl border border-slate-800 bg-slate-950/40 p-3 sm:p-4"
                  >
                    <IncidentRow item={item} />

                    {isThreat ? (
                      <label className="mt-3 flex cursor-pointer items-start gap-3 rounded-lg border border-cyan-500/20 bg-cyan-500/5 p-3 text-sm text-slate-200 transition hover:bg-cyan-500/10">
                        <input
                          type="checkbox"
                          checked={isExpanded}
                          onChange={(event) =>
                            toggleResponse(key, event.target.checked)
                          }
                          className="mt-0.5 h-4 w-4 accent-cyan-400"
                        />

                        <span>
                          <span className="block font-semibold text-cyan-300">
                            Expand Incident Playbook & Remediation Command
                          </span>
                          <span className="mt-1 block text-xs leading-5 text-slate-400">
                            View forensic indicators, MITRE techniques, and NIST containment steps.
                          </span>
                        </span>
                      </label>
                    ) : (
                      <p className="mt-3 text-xs text-slate-500">
                        No active containment required for verified legitimate communication.
                      </p>
                    )}

                    {isThreat && isExpanded && (
                      <div className="mt-4 space-y-4 rounded-xl border border-slate-700 bg-slate-900/70 p-4 sm:p-5">
                        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-3">
                          <div>
                            <h3 className="text-base font-bold text-white">
                              Incident Forensic Analysis
                            </h3>
                            <p className="mt-0.5 text-xs text-slate-400">
                              NIST SP 800-61 Detection & Analysis Data
                            </p>
                          </div>
                          {playbook.threat_archetype && (
                            <span className="rounded-md border border-cyan-500/30 bg-cyan-500/10 px-2.5 py-1 text-xs font-semibold text-cyan-300">
                              {playbook.threat_archetype.replace(/_/g, " ")}
                            </span>
                          )}
                        </div>

                        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                          <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-3">
                            <p className="text-xs text-slate-500">
                              Sender & Infrastructure
                            </p>

                            <p className="mt-1 break-words text-sm text-slate-200">
                              {senderAnalysis.sender_email || getSender(item)}
                            </p>

                            <p className="mt-2 text-xs leading-5 text-slate-400">
                              {senderAnalysis.domain_reputation_notes ||
                                "No sender reputation notes logged."}
                            </p>

                            {typeof senderAnalysis.is_spoofed === "boolean" && (
                              <p className="mt-2 text-xs text-amber-300">
                                Spoofing Detected:{" "}
                                {senderAnalysis.is_spoofed ? "YES" : "NO"}
                              </p>
                            )}
                          </div>

                          <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-3">
                            <p className="text-xs text-slate-500">
                              Behavioral Drivers
                            </p>

                            <p className="mt-1 text-sm text-slate-200">
                              Urgency Vectors:{" "}
                              {content.urgency_tactics_detected
                                ? "Detected"
                                : "Not detected"}
                            </p>

                            <p className="mt-2 text-xs leading-5 text-slate-400">
                              {content.sentiment_analysis ||
                                "No behavioral sentiment summary logged."}
                            </p>
                          </div>
                        </div>

                        {playbook.admin_alert_draft && (
                          <div className="rounded-lg border border-slate-800 bg-slate-950 p-4">
                            <p className="mb-2 text-xs font-semibold uppercase tracking-wider text-cyan-400">
                              SOC Escalation Briefing
                            </p>
                            <pre className="whitespace-pre-wrap font-mono text-xs leading-5 text-slate-300 overflow-x-auto">
                              {playbook.admin_alert_draft}
                            </pre>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </section>
    </div>
  );
}

export default function App() {
  const [activeNav, setActiveNav] = useState("Overview");
  const [history, setHistory] = useState(readHistory);
  const [menuOpen, setMenuOpen] = useState(false);

  const refreshHistory = useCallback(() => {
    setHistory(readHistory());
  }, []);

  useEffect(() => {
    window.addEventListener("storage", refreshHistory);
    window.addEventListener("focus", refreshHistory);
    window.addEventListener("aperture-history-updated", refreshHistory);
    window.addEventListener("trust-lens-history-updated", refreshHistory);

    return () => {
      window.removeEventListener("storage", refreshHistory);
      window.removeEventListener("focus", refreshHistory);
      window.removeEventListener("aperture-history-updated", refreshHistory);
      window.removeEventListener("trust-lens-history-updated", refreshHistory);
    };
  }, [refreshHistory]);

  function navigate(page) {
    setActiveNav(page);
    setMenuOpen(false);
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      {/* Sidebar Navigation */}
      <aside className="fixed inset-y-0 left-0 z-40 hidden w-64 flex-col border-r border-slate-800 bg-slate-950 lg:flex">
        <div className="flex h-20 items-center gap-3 border-b border-slate-800 px-6">
          <div className="rounded-xl bg-cyan-500/10 p-2">
            <ShieldCheck size={28} className="text-cyan-400" />
          </div>

          <div>
            <p className="text-lg font-bold tracking-wide text-white">
              APERTURE
            </p>
            <p className="mt-0.5 text-xs text-slate-500">
              Threat Intelligence
            </p>
          </div>
        </div>

        <nav className="flex-1 space-y-2 p-4">
          <p className="mb-4 px-3 text-xs font-semibold uppercase tracking-widest text-slate-600">
            Operations
          </p>

          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            const selected = activeNav === item.name;

            return (
              <button
                key={item.name}
                onClick={() => navigate(item.name)}
                className={`flex w-full items-center gap-3 rounded-xl px-4 py-3 text-left text-sm font-medium transition ${
                  selected
                    ? "border border-cyan-500/20 bg-cyan-500/10 text-cyan-300"
                    : "border border-transparent text-slate-400 hover:bg-slate-900 hover:text-white"
                }`}
              >
                <Icon size={19} />
                {item.name}
              </button>
            );
          })}
        </nav>

        {/* System Status Footer */}
        <div className="border-t border-slate-800 p-5">
          <div className="flex items-center gap-2 text-xs text-slate-400 font-medium">
            <span className="h-2 w-2 rounded-full bg-cyan-400 animate-pulse" />
            APERTURE Engine v2.0
          </div>
          <p className="mt-1 text-[11px] leading-4 text-slate-500">
            NIST SP 800-61 & MITRE ATT&CK Calibrated SecOps Platform
          </p>
        </div>
      </aside>

      {/* Mobile Navigation Drawer */}
      {menuOpen && (
        <div className="fixed inset-0 z-50 bg-slate-950 lg:hidden">
          <div className="flex h-20 items-center justify-between border-b border-slate-800 px-5">
            <div className="flex items-center gap-3">
              <ShieldCheck size={27} className="text-cyan-400" />
              <span className="font-bold text-white">APERTURE</span>
            </div>

            <button
              onClick={() => setMenuOpen(false)}
              aria-label="Close navigation"
              className="rounded-lg p-2 text-slate-300 hover:bg-slate-800"
            >
              <X size={22} />
            </button>
          </div>

          <nav className="space-y-2 p-4">
            {NAV_ITEMS.map((item) => {
              const Icon = item.icon;

              return (
                <button
                  key={item.name}
                  onClick={() => navigate(item.name)}
                  className={`flex w-full items-center gap-3 rounded-xl px-4 py-3 text-sm ${
                    activeNav === item.name
                      ? "bg-cyan-500/10 text-cyan-300"
                      : "text-slate-300 hover:bg-slate-900"
                  }`}
                >
                  <Icon size={19} />
                  {item.name}
                </button>
              );
            })}
          </nav>
        </div>
      )}

      {/* Main Content Pane */}
      <div className="lg:pl-64">
        <header className="sticky top-0 z-30 flex h-20 items-center justify-between border-b border-slate-800 bg-slate-950/90 px-5 backdrop-blur sm:px-8">
          <div className="flex items-center gap-3">
            <button
              onClick={() => setMenuOpen(true)}
              aria-label="Open navigation"
              className="rounded-lg p-2 text-slate-300 hover:bg-slate-800 lg:hidden"
            >
              <Menu size={22} />
            </button>

            <div>
              <p className="text-sm font-semibold text-white">{activeNav}</p>
              <p className="mt-0.5 text-xs text-slate-500">
                APERTURE / {activeNav}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 rounded-full border border-slate-800 bg-slate-900 px-3.5 py-1.5">
            <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
            <span className="text-xs font-medium text-slate-300">
              SOC Live Inspection
            </span>
          </div>
        </header>

        <main className="mx-auto max-w-[1600px] p-5 sm:p-8">
          {activeNav === "Overview" && (
            <Overview history={history} onNavigate={navigate} />
          )}

          {(activeNav === "Message DeepScan" || activeNav === "Threat Analysis" || activeNav === "Vector DeepScan") && (
            <MessageDeepScan />
          )}

          {activeNav === "Domain Sentinel" && (
            <DomainSentinel />
          )}

          {activeNav === "Incident Responder" && (
            <IncidentTimeline history={history} />
          )}
        </main>

        <footer className="border-t border-slate-800 px-5 py-5 text-center text-xs text-slate-600 sm:px-8">
          APERTURE · AI-Driven Threat Intelligence & Incident Remediation
        </footer>
      </div>
    </div>
  );
}
