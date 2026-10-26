
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
} from "lucide-react";
import ThreatAnalyzer from "./ThreatAnalyzer.jsx";

const HISTORY_KEY = "trust-lens-history";

const NAV_ITEMS = [
  { name: "Overview", icon: LayoutDashboard },
  { name: "Threat Analysis", icon: ScanSearch },
  { name: "Incident Responder", icon: History },
];

function readHistory() {
  try {
    const saved = localStorage.getItem(HISTORY_KEY);
    const parsed = saved ? JSON.parse(saved) : [];
    return Array.isArray(parsed) ? parsed : [];
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
    "Security analysis"
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

      <div className="flex items-center gap-3 pl-1 sm:pl-0">
        <VerdictBadge verdict={verdict} />
        <span className="whitespace-nowrap text-sm text-slate-400">
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
      title: "Total Scanned",
      value: total,
      description: "Analyses saved in this browser",
      icon: Activity,
      color: "text-cyan-400",
      tint: "bg-cyan-500/10",
    },
    {
      title: "Phishing Detected",
      value: phishing,
      description: "Scans classified as phishing",
      icon: ShieldAlert,
      color: "text-red-400",
      tint: "bg-red-500/10",
    },
    {
      title: "Active Incidents",
      value: phishing + suspicious,
      description: "Suspicious or phishing results",
      icon: AlertTriangle,
      color: "text-amber-400",
      tint: "bg-amber-500/10",
    },
    {
      title: "Safe Results",
      value: safe,
      description: "Scans classified as safe",
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
          THREAT INTELLIGENCE CONSOLE
        </div>

        <h1 className="text-3xl font-bold tracking-tight text-white sm:text-4xl">
          Security Overview
        </h1>

        <p className="mt-3 max-w-2xl text-sm leading-6 text-slate-400 sm:text-base">
          Detect phishing attempts, investigate suspicious links, and review
          incident response recommendations from one security dashboard.
        </p>
      </section>

      <section className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {stats.map((stat) => (
          <StatCard key={stat.title} {...stat} />
        ))}
      </section>

      <section className="grid grid-cols-1 gap-5 xl:grid-cols-3">
        <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6 xl:col-span-2">
          <div className="flex items-start gap-4">
            <div className="rounded-xl bg-cyan-500/10 p-3">
              <ScanSearch size={25} className="text-cyan-400" />
            </div>

            <div>
              <h2 className="text-lg font-semibold text-white">
                Multi-Vector Threat Analysis
              </h2>
              <p className="mt-2 text-sm leading-6 text-slate-400">
                Inspect sender identity, psychological manipulation, and
                suspicious URLs in a single analysis workflow.
              </p>
            </div>
          </div>

          <div className="mt-6 flex flex-wrap gap-2">
            {[
              "Sender Identity",
              "Content Analysis",
              "URL Inspection",
            ].map((label) => (
              <span
                key={label}
                className="rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-xs text-slate-300"
              >
                {label}
              </span>
            ))}
          </div>

          <button
            onClick={() => onNavigate("Threat Analysis")}
            className="mt-6 inline-flex items-center gap-2 rounded-xl bg-cyan-400 px-5 py-3 text-sm font-semibold text-slate-950 transition hover:bg-cyan-300"
          >
            Run Security Check
            <ArrowUpRight size={17} />
          </button>
        </div>

        <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6">
          <div className="flex items-center gap-3">
            <div className="rounded-xl bg-emerald-500/10 p-3">
              <ShieldCheck size={24} className="text-emerald-400" />
            </div>

            <div>
              <h2 className="font-semibold text-white">Incident Response</h2>
              <p className="mt-1 text-xs text-slate-500">
                Detection and remediation
              </p>
            </div>
          </div>

          <p className="mt-5 text-sm leading-6 text-slate-400">
            Review suggested containment steps and prepare an escalation report
            when a scan identifies a potential threat.
          </p>

          <button
            onClick={() => onNavigate("Incident Responder")}
            className="mt-5 inline-flex items-center gap-2 text-sm font-medium text-cyan-400 transition hover:text-cyan-300"
          >
            Review incidents
            <ArrowUpRight size={16} />
          </button>
        </div>
      </section>

      <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5 sm:p-6">
        <div className="mb-5 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-lg font-semibold text-white">
              Recent Analyses
            </h2>
            <p className="mt-1 text-sm text-slate-400">
              Latest saved results from this browser
            </p>
          </div>

          <button
            onClick={() => onNavigate("Incident Responder")}
            className="text-sm font-medium text-cyan-400 hover:text-cyan-300"
          >
            View incident responder
          </button>
        </div>

        {history.length === 0 ? (
          <div className="rounded-xl border border-dashed border-slate-700 px-5 py-10 text-center">
            <Clock3
              size={30}
              className="mx-auto mb-3 text-slate-500"
            />
            <p className="font-medium text-slate-300">
              No analyses recorded yet
            </p>
            <p className="mt-2 text-sm text-slate-500">
              Run your first scan to populate dashboard metrics and history.
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
        Dashboard metrics are calculated from saved analysis results.
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
        <h1 className="text-3xl font-bold tracking-tight text-white sm:text-4xl">
          Incident Responder
        </h1>
        <p className="mt-3 text-sm leading-6 text-slate-400">
          Review incidents, understand why messages were flagged, and inspect
          recommended system response actions.
        </p>
      </section>

      <section className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <StatCard
          title="Recorded Scans"
          value={history.length}
          description="All saved analyses"
          icon={History}
          color="text-cyan-400"
          tint="bg-cyan-500/10"
        />

        <StatCard
          title="Potential Incidents"
          value={threats.length}
          description="Suspicious and phishing results"
          icon={AlertTriangle}
          color="text-amber-400"
          tint="bg-amber-500/10"
        />

        <StatCard
          title="Safe Results"
          value={
            history.filter((item) => getVerdict(item) === "SAFE").length
          }
          description="Results marked safe"
          icon={CheckCircle2}
          color="text-emerald-400"
          tint="bg-emerald-500/10"
        />
      </section>

      <section>
        <p className="mb-3 text-base font-bold tracking-[0.2em] text-cyan-400 sm:text-lg">
          AUDIT TRAIL
        </p>

        <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5 sm:p-6">
          <h2 className="mb-5 text-lg font-semibold text-white">
            Chronological Activity
          </h2>

          {history.length === 0 ? (
            <div className="rounded-xl border border-dashed border-slate-700 px-5 py-12 text-center">
              <History
                size={30}
                className="mx-auto mb-3 text-slate-500"
              />
              <p className="font-medium text-slate-300">
                Your timeline is empty
              </p>
              <p className="mt-2 text-sm text-slate-500">
                Saved analysis results will appear here.
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
                            Show incident response plan
                          </span>
                          <span className="mt-1 block text-xs leading-5 text-slate-400">
                            View the indicators found in this scan and the
                            actions recommended for this specific incident.
                          </span>
                        </span>
                      </label>
                    ) : (
                      <p className="mt-3 text-xs text-slate-500">
                        No response plan is needed for a result marked safe.
                      </p>
                    )}

                    {isThreat && isExpanded && (
                      <div className="mt-4 space-y-4 rounded-xl border border-slate-700 bg-slate-900/70 p-4 sm:p-5">
                        <div>
                          <h3 className="text-base font-bold text-white">
                            Why This Message Was Flagged
                          </h3>
                          <p className="mt-1 text-xs text-slate-400">
                            These details are taken from the saved analysis
                            associated with this incident.
                          </p>
                        </div>

                        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                          <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-3">
                            <p className="text-xs text-slate-500">
                              Sender Identity
                            </p>

                            <p className="mt-1 break-words text-sm text-slate-200">
                              {senderAnalysis.sender_email || getSender(item)}
                            </p>

                            <p className="mt-2 text-xs leading-5 text-slate-400">
                              {senderAnalysis.domain_reputation_notes ||
                                "No saved sender reputation notes for this scan."}
                            </p>

                            {typeof senderAnalysis.is_spoofed === "boolean" && (
                              <p className="mt-2 text-xs text-amber-300">
                                Possible sender spoofing:{" "}
                                {senderAnalysis.is_spoofed
                                  ? "Flagged"
                                  : "Not flagged"}
                              </p>
                            )}

                            {typeof senderAnalysis.display_name_match ===
                              "boolean" && (
                              <p className="mt-2 text-xs text-slate-400">
                                Display name match:{" "}
                                {senderAnalysis.display_name_match
                                  ? "Match reported"
                                  : "Mismatch reported"}
                              </p>
                            )}
                          </div>

                          <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-3">
                            <p className="text-xs text-slate-500">
                              Message Content
                            </p>

                            <p className="mt-1 text-sm text-slate-200">
                              Urgency tactics:{" "}
                              {content.urgency_tactics_detected
                                ? "Detected"
                                : "Not detected / not recorded"}
                            </p>

                            <p className="mt-2 text-xs leading-5 text-slate-400">
                              {content.sentiment_analysis ||
                                "No saved content summary for this scan."}
                            </p>

                            {triggers.length > 0 && (
                              <ul className="mt-2 list-disc space-y-1 pl-5 text-xs text-slate-300">
                                {triggers.map((trigger, triggerIndex) => (
                                  <li key={`${triggerIndex}-${trigger}`}>
                                    {trigger}
                                  </li>
                                ))}
                              </ul>
                            )}
                          </div>
                        </div>

                        <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-3">
                          <p className="text-xs text-slate-500">
                            URL and Domain Indicators
                          </p>

                          <p className="mt-1 text-sm leading-5 text-slate-300">
                            {urlAnalysis.domain_risk_summary ||
                              "No saved URL risk summary for this scan."}
                          </p>

                          {urls.length > 0 && (
                            <ul className="mt-2 space-y-1">
                              {urls.map((url, urlIndex) => (
                                <li
                                  key={`${urlIndex}-${url}`}
                                  className="break-all text-xs text-cyan-300"
                                >
                                  {url}
                                </li>
                              ))}
                            </ul>
                          )}

                          <p className="mt-2 text-xs text-slate-400">
                            Typosquatting:{" "}
                            {urlAnalysis.has_typosquatting
                              ? "Flagged"
                              : "Not flagged / not recorded"}
                            {" · "}
                            Suspicious redirects:{" "}
                            {urlAnalysis.suspicious_redirects
                              ? "Flagged"
                              : "Not flagged / not recorded"}
                          </p>
                        </div>

                        <div>
                          <h3 className="flex items-center gap-2 text-base font-bold text-white">
                            <ClipboardList
                              size={18}
                              className="text-cyan-400"
                            />
                            Recommended System Actions
                          </h3>

                          <p className="mt-1 text-xs leading-5 text-slate-400">
                            The following actions are recommendations from the
                            saved playbook. APERTURE has not executed them
                            automatically.
                          </p>

                          {actions.length > 0 ? (
                            <ol className="mt-3 space-y-2">
                              {actions.map((action, actionIndex) => (
                                <li
                                  key={`${actionIndex}-${action}`}
                                  className="flex items-start gap-3 rounded-lg border border-slate-800 bg-slate-950/60 p-3"
                                >
                                  <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-lg bg-cyan-500/10 text-xs font-bold text-cyan-400">
                                    {actionIndex + 1}
                                  </span>

                                  <span className="text-sm leading-5 text-slate-300">
                                    {action}
                                  </span>
                                </li>
                              ))}
                            </ol>
                          ) : (
                            <p className="mt-3 rounded-lg border border-slate-800 bg-slate-950/60 p-3 text-sm text-slate-400">
                              No specific response actions were saved for this
                              incident. Verify the message manually using
                              approved security tools.
                            </p>
                          )}
                        </div>

                        <div>
                          <h3 className="text-base font-bold text-white">
                            Admin Escalation Report
                          </h3>

                          <div className="mt-3 whitespace-pre-wrap break-words rounded-lg border border-slate-800 bg-slate-950/60 p-4 text-sm leading-6 text-slate-300">
                            {playbook.admin_alert_draft ||
                              `Incident review requested.
Sender or URL: ${getSender(item)}
Verdict: ${verdict}
Threat score: ${getScore(item)}/100
Severity: ${playbook.severity_level || "Not specified"}

Please investigate this incident using approved security tools.`}
                          </div>

                          {item.demo && (
                            <p className="mt-2 text-xs text-amber-400">
                              Demo analysis: verify these indicators before
                              using the report for a real incident.
                            </p>
                          )}

                          <button
                            type="button"
                            onClick={() => {
                              const report = [
                                "APERTURE INCIDENT RESPONSE REPORT",
                                `Sender or URL: ${getSender(item)}`,
                                `Verdict: ${verdict}`,
                                `Threat score: ${getScore(item)}/100`,
                                `Severity: ${
                                  playbook.severity_level || "Not specified"
                                }`,
                                "",
                                "Indicators:",
                                senderAnalysis.domain_reputation_notes ||
                                  "No sender notes recorded.",
                                content.sentiment_analysis ||
                                  "No content summary recorded.",
                                urlAnalysis.domain_risk_summary ||
                                  "No URL risk summary recorded.",
                                "",
                                "Recommended actions:",
                                ...(actions.length
                                  ? actions.map(
                                      (action, actionIndex) =>
                                        `${actionIndex + 1}. ${action}`
                                    )
                                  : ["No saved response actions."]),
                                "",
                                "Admin escalation:",
                                playbook.admin_alert_draft ||
                                  "No saved admin alert draft.",
                                "",
                                "This report contains analysis and recommendations. No automatic containment is confirmed.",
                              ].join("\n");

                              if (navigator.clipboard?.writeText) {
                                navigator.clipboard
                                  .writeText(report)
                                  .catch(() => {
                                    window.prompt(
                                      "Copy incident report:",
                                      report
                                    );
                                  });
                              } else {
                                window.prompt("Copy incident report:", report);
                              }
                            }}
                            className="mt-3 inline-flex items-center gap-2 rounded-lg border border-slate-700 px-4 py-2.5 text-sm font-medium text-slate-200 transition hover:bg-slate-800"
                          >
                            <Copy size={15} />
                            Copy Incident Report
                          </button>
                        </div>

                        <div className="rounded-lg border border-amber-500/20 bg-amber-500/5 p-3">
                          <p className="text-sm font-semibold text-amber-300">
                            System execution status
                          </p>
                          <p className="mt-1 text-xs leading-5 text-slate-300">
                            This interface displays recommended response
                            actions only. Blocking senders, quarantining
                            messages, disabling accounts, and notifying an
                            administrator require connected backend or
                            security-service integrations.
                          </p>
                        </div>
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
    window.addEventListener("trust-lens-history-updated", refreshHistory);

    return () => {
      window.removeEventListener("storage", refreshHistory);
      window.removeEventListener("focus", refreshHistory);
      window.removeEventListener(
        "trust-lens-history-updated",
        refreshHistory
      );
    };
  }, [refreshHistory]);

  function navigate(page) {
    setActiveNav(page);
    setMenuOpen(false);
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
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
            Workspace
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

        <div className="border-t border-slate-800 p-5">
          <div className="flex items-center gap-2 text-xs text-slate-400">
            <span className="h-2 w-2 rounded-full bg-amber-400" />
            Frontend integration
          </div>
          <p className="mt-2 text-xs leading-5 text-slate-600">
            Results depend on the configured mock or backend analysis source.
          </p>
        </div>
      </aside>

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
              <p className="mt-1 text-xs text-slate-500">
                APERTURE / {activeNav}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 rounded-full border border-slate-800 bg-slate-900 px-3 py-2">
            <span className="h-2 w-2 rounded-full bg-cyan-400" />
            <span className="text-xs font-medium text-slate-300">
              Demo Mode
            </span>
          </div>
        </header>

        <main className="mx-auto max-w-[1600px] p-5 sm:p-8">
          {activeNav === "Overview" && (
            <Overview history={history} onNavigate={navigate} />
          )}

          {activeNav === "Threat Analysis" && <ThreatAnalyzer />}

          {activeNav === "Incident Responder" && (
            <IncidentTimeline history={history} />
          )}
        </main>

        <footer className="border-t border-slate-800 px-5 py-5 text-center text-xs text-slate-600 sm:px-8">
          APERTURE · Threat Intelligence & Incident Response
        </footer>
      </div>
    </div>
  );
}
