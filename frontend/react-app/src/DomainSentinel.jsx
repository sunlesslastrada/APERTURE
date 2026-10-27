import { useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  ShieldAlert,
  ShieldCheck,
  ScanSearch,
  Link2,
  Copy,
  ClipboardCheck,
  LoaderCircle,
  ExternalLink,
  RefreshCw,
  Globe,
  Radio,
  Tag,
  Server,
  Layers,
} from "lucide-react";

const HISTORY_KEY = "aperture-threat-history";
const LEGACY_HISTORY_KEY = "trust-lens-history";

const SAMPLE_LOOKALIKE_URL = "http://micros0ft-account-security.example.com/verify";
const SAMPLE_BEC_URL = "https://paypa1-security-verification.top/confirm-billing";

function readHistory() {
  try {
    const saved = localStorage.getItem(HISTORY_KEY);
    if (saved) {
      const parsed = JSON.parse(saved);
      if (Array.isArray(parsed)) return parsed;
    }
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

function saveHistory(record) {
  const history = readHistory();
  const updated = [record, ...history].slice(0, 100);

  try {
    localStorage.setItem(HISTORY_KEY, JSON.stringify(updated));
    window.dispatchEvent(new Event("aperture-history-updated"));
    window.dispatchEvent(new Event("trust-lens-history-updated"));
  } catch (error) {
    console.error("Unable to save scan history:", error);
  }
}

function getVerdictColors(verdict) {
  if (verdict === "PHISHING") {
    return {
      text: "text-red-400",
      border: "border-red-500/30",
      background: "bg-red-500/10",
      bar: "bg-red-500",
    };
  }

  if (verdict === "SUSPICIOUS") {
    return {
      text: "text-amber-400",
      border: "border-amber-500/30",
      background: "bg-amber-500/10",
      bar: "bg-amber-400",
    };
  }

  return {
    text: "text-emerald-400",
    border: "border-emerald-500/30",
    background: "bg-emerald-500/10",
    bar: "bg-emerald-500",
  };
}

function formatArchetype(archetype) {
  switch (archetype) {
    case "BRAND_TYPOSQUATTING":
      return "Brand Typosquatting";
    case "CREDENTIAL_HARVESTING":
      return "Credential Harvesting";
    case "FINANCIAL_FRAUD_BEC":
      return "Financial Fraud / BEC";
    case "MALWARE_DROPPER":
      return "Malware Dropper";
    case "BENIGN_LEGITIMATE":
      return "Benign / Verified";
    default:
      return archetype ? archetype.replace(/_/g, " ") : "Domain Risk";
  }
}

function Flag({ active, yesText = "Detected", noText = "Not detected" }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium ${
        active
          ? "bg-amber-500/10 text-amber-300"
          : "bg-emerald-500/10 text-emerald-300"
      }`}
    >
      {active ? <AlertTriangle size={13} /> : <CheckCircle2 size={13} />}
      {active ? yesText : noText}
    </span>
  );
}

function DiagnosticCard({ title, icon: Icon, children }) {
  return (
    <section className="min-w-0 rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
      <div className="mb-5 flex items-center gap-3">
        <div className="rounded-lg bg-slate-800 p-2">
          <Icon size={19} className="text-cyan-400" />
        </div>
        <h3 className="font-semibold text-white">{title}</h3>
      </div>
      <div className="space-y-4">{children}</div>
    </section>
  );
}

export default function DomainSentinel() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [checkedActions, setCheckedActions] = useState({});
  const [copied, setCopied] = useState(false);

  function resetForm() {
    setUrl("");
    setResult(null);
    setError("");
    setCheckedActions({});
    setCopied(false);
  }

  async function runInspection(event) {
    event.preventDefault();
    setError("");
    setCopied(false);

    if (!url.trim()) {
      setError("Please enter a destination URL or hostname to inspect.");
      return;
    }

    if (!/^https?:\/\//i.test(url.trim())) {
      setError("Include http:// or https:// protocol at the start of the URL.");
      return;
    }

    setLoading(true);
    setCheckedActions({});

    const payload = {
      mode: "url",
      sender: "",
      message: "",
      url: url.trim(),
    };

    try {
      const response = await fetch("http://localhost:8000/api/analyze", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.detail || `Server responded with status ${response.status}`);
      }

      const data = await response.json();

      const record = {
        id: `${Date.now()}-${Math.random().toString(36).substring(2, 9)}`,
        timestamp: new Date().toLocaleString(),
        verdict: data.verdict,
        threat_score: data.threat_score,
        threat_archetype: data.threat_archetype || data.playbook?.threat_archetype || "BRAND_TYPOSQUATTING",
        input: {
          mode: "url",
          sender: "",
          message: "",
          url: url.trim(),
        },
        sender_analysis: data.sender_analysis,
        content_analysis: data.content_analysis,
        url_analysis: data.url_analysis,
        playbook: data.playbook,
      };

      setResult(record);
      saveHistory(record);
    } catch (err) {
      console.error("Domain Sentinel inspection failed:", err);
      setError(
        `Inspection failed: ${
          err.message ||
          "Could not connect to the APERTURE intelligence backend at http://localhost:8000. Ensure the API server is active."
        }`
      );
    } finally {
      setLoading(false);
    }
  }

  function toggleAction(index) {
    setCheckedActions((current) => ({
      ...current,
      [index]: !current[index],
    }));
  }

  async function copyEscalation() {
    if (!result) return;
    const reportText = result.playbook?.admin_alert_draft || "";

    try {
      await navigator.clipboard.writeText(reportText);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch {
      setError("Clipboard access failed. Check browser permissions and try again.");
    }
  }

  const verdict = result?.verdict || "";
  const colors = result ? getVerdictColors(verdict) : null;
  const actions = result?.playbook?.immediate_actions || [];
  const completedActions = actions.filter((_, index) => checkedActions[index]).length;
  const archetype = result?.threat_archetype || result?.playbook?.threat_archetype || "";

  // Parse destination URL for detailed dissection
  let parsedHost = "";
  let parsedProtocol = "";
  let parsedPath = "";
  try {
    if (url.trim()) {
      const u = new URL(url.trim().startsWith("http") ? url.trim() : `http://${url.trim()}`);
      parsedHost = u.hostname;
      parsedProtocol = u.protocol.replace(":", "").toUpperCase();
      parsedPath = u.pathname || "/";
    }
  } catch {}

  return (
    <div className="space-y-7">
      <section>
        <p className="mb-2 text-xs font-semibold tracking-widest text-cyan-400">
          DOMAIN SENTINEL · INFRASTRUCTURE & REPUTATION ENGINE
        </p>
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h1 className="text-3xl font-bold tracking-tight text-white sm:text-4xl">
              Direct URL & Domain Sentinel
            </h1>
            <p className="mt-3 max-w-2xl text-sm leading-6 text-slate-400">
              Autonomous domain dissection tool specialized in identifying character homoglyphs,
              brand typosquatting hostnames, deceptive subdomain stacking, and generating DNS sinkhole rules.
            </p>
          </div>
          <span className="inline-flex items-center gap-2 rounded-full border border-cyan-500/20 bg-cyan-500/5 px-3 py-2 text-xs font-medium text-cyan-300">
            <Radio size={14} className="animate-pulse text-cyan-400" />
            Perimeter Sentinel Live
          </span>
        </div>
      </section>

      {/* Target URL Input Console */}
      <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5 sm:p-6">
        <form onSubmit={runInspection} className="space-y-5">
          <div>
            <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
              <label htmlFor="target-url" className="text-sm font-medium text-slate-200">
                Target URL or Fully Qualified Domain Name (FQDN)
              </label>
              <div className="flex flex-wrap gap-2">
                <button
                  type="button"
                  onClick={() => setUrl(SAMPLE_LOOKALIKE_URL)}
                  className="inline-flex items-center gap-1.5 text-xs font-medium text-cyan-400 hover:text-cyan-300"
                >
                  <Globe size={13} />
                  Load Microsoft Homoglyph
                </button>
                <button
                  type="button"
                  onClick={() => setUrl(SAMPLE_BEC_URL)}
                  className="inline-flex items-center gap-1.5 text-xs font-medium text-cyan-400 hover:text-cyan-300"
                >
                  <Server size={13} />
                  Load PayPal .TOP Typosquat
                </button>
              </div>
            </div>

            <div className="relative">
              <Link2 size={18} className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500" />
              <input
                id="target-url"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://micros0ft-login.example.com/oauth/authorize"
                className="w-full rounded-xl border border-slate-700 bg-slate-950 py-3.5 pl-11 pr-4 text-sm text-white outline-none transition placeholder:text-slate-600 focus:border-cyan-400 focus:ring-2 focus:ring-cyan-400/10 font-mono"
              />
            </div>
            <p className="mt-2 text-xs text-slate-500">
              Evaluates homoglyphs (e.g. `micros0ft`), deceptive subdomains (e.g. `login.paypal.com.attacker.biz`), and bare IP destinations.
            </p>
          </div>

          {/* Quick Dissection Preview */}
          {parsedHost && (
            <div className="rounded-xl border border-slate-800 bg-slate-950/80 p-3.5">
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
                <div>
                  <span className="text-slate-500 block">Protocol</span>
                  <span className="font-mono text-cyan-400">{parsedProtocol}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Identified Hostname</span>
                  <span className="font-mono text-slate-200">{parsedHost}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Destination Path</span>
                  <span className="font-mono text-slate-400 truncate block">{parsedPath}</span>
                </div>
              </div>
            </div>
          )}

          {error && (
            <div role="alert" className="rounded-xl border border-red-500/20 bg-red-500/10 px-4 py-3 text-sm text-red-300">
              {error}
            </div>
          )}

          {loading && (
            <div className="flex items-center gap-3 rounded-xl border border-cyan-500/30 bg-cyan-500/10 px-4 py-3 text-sm text-cyan-300 animate-pulse">
              <LoaderCircle size={18} className="animate-spin text-cyan-400 shrink-0" />
              <span>Analyzing destination hostname for homoglyphs, typosquats, and deceptive redirects...</span>
            </div>
          )}

          <div className="flex flex-wrap gap-3 border-t border-slate-800 pt-5">
            <button
              type="submit"
              disabled={loading}
              className="inline-flex items-center justify-center gap-2 rounded-xl bg-cyan-400 px-5 py-3 text-sm font-semibold text-slate-950 transition hover:bg-cyan-300 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {loading ? (
                <>
                  <LoaderCircle size={17} className="animate-spin" />
                  Inspecting Domain...
                </>
              ) : (
                <>
                  <ScanSearch size={17} />
                  Initiate Vector Inspection
                </>
              )}
            </button>

            <button
              type="button"
              onClick={resetForm}
              className="inline-flex items-center gap-2 rounded-xl border border-slate-700 px-4 py-3 text-sm font-medium text-slate-300 transition hover:bg-slate-800"
            >
              <RefreshCw size={16} />
              Reset Console
            </button>
          </div>
        </form>
      </section>

      {/* Results Deck */}
      {result && (
        <>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <p className="text-xs font-semibold tracking-widest text-cyan-400">
                DOMAIN SENTINEL INTELLIGENCE
              </p>
              <h2 className="mt-2 text-2xl font-bold text-white">
                Destination Infrastructure Verdict
              </h2>
              <p className="mt-1 text-xs text-slate-500">
                APERTURE Sentinel · {result.timestamp}
              </p>
            </div>
            <button
              type="button"
              onClick={resetForm}
              className="inline-flex items-center gap-2 rounded-lg border border-slate-700 px-3 py-2 text-sm text-slate-300 hover:bg-slate-800"
            >
              <RefreshCw size={15} />
              New Scan
            </button>
          </div>

          <section className={`rounded-2xl border ${colors.border} ${colors.background} p-5 sm:p-7`}>
            <div className="grid grid-cols-1 items-center gap-6 md:grid-cols-[1fr_auto]">
              <div>
                <div className="flex flex-wrap items-center gap-3">
                  {verdict === "SAFE" ? (
                    <ShieldCheck size={26} className={colors.text} />
                  ) : (
                    <ShieldAlert size={26} className={colors.text} />
                  )}
                  <span className={`text-2xl font-bold ${colors.text}`}>
                    {verdict}
                  </span>
                  <span className="rounded-full border border-slate-700 bg-slate-950/40 px-3 py-1 text-xs text-slate-300">
                    Severity: {result.playbook.severity_level}
                  </span>
                  {archetype && (
                    <span className="inline-flex items-center gap-1.5 rounded-full border border-cyan-500/30 bg-cyan-500/10 px-3 py-1 text-xs font-semibold text-cyan-300">
                      <Tag size={12} />
                      {formatArchetype(archetype)}
                    </span>
                  )}
                </div>

                <p className="mt-3 max-w-2xl text-sm leading-6 text-slate-300">
                  {verdict === "PHISHING"
                    ? "Destination domain flagged as malicious typosquatting infrastructure. Immediate DNS sinkhole and proxy blocking enforced."
                    : verdict === "SUSPICIOUS"
                    ? "Destination displays deceptive subdomain structure or suspicious registrar routing. Block recommended pending manual review."
                    : "Domain verified as clean. No character homoglyphs, punycode lookalikes, or deceptive subdomains identified."}
                </p>
              </div>

              <div className="flex items-center gap-5 md:gap-6">
                <div
                  className="relative grid h-28 w-28 shrink-0 place-items-center rounded-full"
                  style={{
                    background: `conic-gradient(${
                      verdict === "PHISHING"
                        ? "#ef4444"
                        : verdict === "SUSPICIOUS"
                        ? "#f59e0b"
                        : "#10b981"
                    } ${Math.max(0, Math.min(100, result.threat_score))}%, #1e293b 0)`,
                  }}
                >
                  <div className="grid h-20 w-20 place-items-center rounded-full bg-slate-950">
                    <div className="text-center">
                      <p className="text-2xl font-bold text-white">
                        {result.threat_score}
                      </p>
                      <p className="text-[10px] uppercase tracking-widest text-slate-500">
                        out of 100
                      </p>
                    </div>
                  </div>
                </div>
                <div>
                  <p className="text-sm font-medium text-slate-200">
                    Infrastructure Threat Score
                  </p>
                  <p className="mt-1 max-w-32 text-xs leading-5 text-slate-400">
                    Calibrated DNS & Typosquat Metric
                  </p>
                </div>
              </div>
            </div>
          </section>

          {/* Diagnostic Breakdown */}
          <section className="grid grid-cols-1 gap-4 xl:grid-cols-2">
            <DiagnosticCard title="URL & Homoglyph Inspection" icon={Link2}>
              <div className="flex flex-wrap gap-2">
                <Flag
                  active={result.url_analysis.has_typosquatting}
                  yesText="Homoglyph / Lookalike Pattern"
                  noText="No Homoglyphs Found"
                />
                <Flag
                  active={result.url_analysis.suspicious_redirects}
                  yesText="Deceptive Redirection Concern"
                  noText="Direct Destination"
                />
              </div>

              <div>
                <p className="mb-2 text-xs font-medium text-slate-500">
                  Inspected Target URLs
                </p>
                {result.url_analysis.extracted_urls.length ? (
                  <div className="space-y-2">
                    {result.url_analysis.extracted_urls.map((item) => (
                      <div
                        key={item}
                        className="flex items-start gap-2 rounded-lg border border-slate-800 bg-slate-950 p-3"
                      >
                        <ExternalLink size={15} className="mt-0.5 shrink-0 text-amber-400" />
                        <span className="break-all text-xs leading-5 text-slate-300 font-mono">
                          {item}
                        </span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-sm text-slate-500">No destination URLs analyzed.</p>
                )}
              </div>

              <p className="text-sm leading-6 text-slate-400">
                {result.url_analysis.domain_risk_summary}
              </p>
            </DiagnosticCard>

            <DiagnosticCard title="Threat Classification & Indicators" icon={Layers}>
              <div>
                <p className="mb-1 text-xs text-slate-500">Assigned Threat Vector</p>
                <p className="text-sm font-semibold text-white">
                  {formatArchetype(archetype)}
                </p>
              </div>

              <div>
                <p className="mb-1 text-xs text-slate-500">Behavioral Sentiment Assessment</p>
                <p className="text-sm leading-6 text-slate-400">
                  {result.content_analysis.sentiment_analysis}
                </p>
              </div>

              <div>
                <p className="mb-1 text-xs text-slate-500">Destination Host Disposition</p>
                <p className="text-xs leading-5 text-slate-400">
                  {result.sender_analysis.domain_reputation_notes || "Direct URL scan executed against perimeter intelligence database."}
                </p>
              </div>
            </DiagnosticCard>
          </section>

          {/* DNS Sinkhole & Containment Checklist */}
          {verdict !== "SAFE" && (
            <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5 sm:p-6">
              <div className="flex flex-wrap items-start justify-between gap-4">
                <div className="flex items-start gap-3">
                  <div className="rounded-xl bg-slate-800 p-2.5">
                    <ClipboardCheck size={20} className="text-amber-400" />
                  </div>
                  <div>
                    <h3 className="font-semibold text-white">DNS Sinkhole & Mitigation Checklist</h3>
                    <p className="mt-1 text-sm leading-5 text-slate-400">
                      NIST SP 800-61 containment commands for perimeter firewalls and DNS resolvers.
                    </p>
                  </div>
                </div>
                <span className="rounded-full border border-amber-500/20 bg-amber-500/10 px-3 py-1.5 text-xs font-semibold text-amber-300">
                  {result.playbook.severity_level} SEVERITY
                </span>
              </div>

              <div className="mt-6">
                <div className="mb-3 flex items-center justify-between gap-3 text-xs text-slate-400">
                  <span>Perimeter Action Progress</span>
                  <span>
                    {completedActions} of {actions.length} completed
                  </span>
                </div>
                <div className="mb-5 h-1.5 overflow-hidden rounded-full bg-slate-800">
                  <div
                    className="h-full rounded-full bg-cyan-400 transition-all"
                    style={{
                      width: `${actions.length ? (completedActions / actions.length) * 100 : 0}%`,
                    }}
                  />
                </div>

                <div className="space-y-3">
                  {actions.map((action, index) => (
                    <label
                      key={`${index}-${action}`}
                      className="flex cursor-pointer items-start gap-3 rounded-xl border border-slate-800 bg-slate-950/60 p-4 transition hover:border-slate-700"
                    >
                      <input
                        type="checkbox"
                        checked={Boolean(checkedActions[index])}
                        onChange={() => toggleAction(index)}
                        className="mt-1 h-4 w-4 accent-cyan-400"
                      />
                      <span
                        className={`text-sm leading-6 ${
                          checkedActions[index]
                            ? "text-slate-500 line-through"
                            : "text-slate-300"
                        }`}
                      >
                        {action}
                      </span>
                    </label>
                  ))}
                </div>
              </div>

              <div className="mt-6 border-t border-slate-800 pt-6">
                <div className="mb-3">
                  <h3 className="font-semibold text-white">
                    Perimeter Escalation Report & Abuse Notice
                  </h3>
                  <p className="mt-1 text-sm text-slate-400">
                    NIST containment memo ready for network engineering and registrar abuse takedown.
                  </p>
                </div>

                <div className="whitespace-pre-wrap rounded-xl border border-slate-800 bg-slate-950 p-4 text-sm leading-6 text-slate-300 font-mono overflow-x-auto">
                  {result.playbook.admin_alert_draft}
                </div>

                <button
                  type="button"
                  onClick={copyEscalation}
                  className="mt-4 inline-flex items-center gap-2 rounded-xl bg-cyan-400 px-4 py-3 text-sm font-semibold text-slate-950 transition hover:bg-cyan-300"
                >
                  {copied ? <CheckCircle2 size={17} /> : <Copy size={17} />}
                  {copied ? "Copied to Clipboard!" : "Copy Admin Notice"}
                </button>
              </div>
            </section>
          )}

          <p className="text-xs leading-5 text-slate-500">
            <ShieldCheck size={14} className="mr-1 inline-block text-cyan-400" />
            Infrastructure telemetry validated by APERTURE Domain Sentinel.
          </p>
        </>
      )}
    </div>
  );
}
