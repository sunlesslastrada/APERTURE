import { useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  ShieldAlert,
  ShieldCheck,
  ScanSearch,
  Link2,
  Mail,
  Copy,
  ClipboardCheck,
  LoaderCircle,
  ExternalLink,
  RefreshCw,
  FileSearch,
  Eye,
  Radio,
} from "lucide-react";

const HISTORY_KEY = "trust-lens-history";

const SAMPLE_SENDER = "Microsoft Account Team <security-alerts@gmail.com>";

const SAMPLE_MESSAGE = `URGENT: Your Microsoft account will be suspended today.

We detected unusual activity on your account. You must verify your identity immediately to avoid permanent account suspension.

Verify your account now:
http://micros0ft-account-security.example.com/verify

Failure to act within 30 minutes may result in loss of access.`;

function readHistory() {
  try {
    const saved = JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
    return Array.isArray(saved) ? saved : [];
  } catch {
    return [];
  }
}

function saveHistory(record) {
  const history = readHistory();
  const updated = [record, ...history].slice(0, 100);

  try {
    localStorage.setItem(HISTORY_KEY, JSON.stringify(updated));
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

function SectionHeading({ icon: Icon, title, description, color = "text-cyan-400" }) {
  return (
    <div className="flex items-start gap-3">
      <div className="rounded-xl bg-slate-800 p-2.5">
        <Icon size={20} className={color} />
      </div>
      <div>
        <h3 className="font-semibold text-white">{title}</h3>
        {description && (
          <p className="mt-1 text-sm leading-5 text-slate-400">
            {description}
          </p>
        )}
      </div>
    </div>
  );
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

export default function ThreatAnalyzer() {
  const [mode, setMode] = useState("message");
  const [sender, setSender] = useState("");
  const [message, setMessage] = useState("");
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [checkedActions, setCheckedActions] = useState({});
  const [copied, setCopied] = useState(false);

  function loadSample() {
    setSender(SAMPLE_SENDER);
    setMessage(SAMPLE_MESSAGE);
    setMode("message");
    setError("");
    setResult(null);
    setCheckedActions({});
  }

  function resetForm() {
    setSender("");
    setMessage("");
    setUrl("");
    setResult(null);
    setError("");
    setCheckedActions({});
    setCopied(false);
  }

  async function runAnalysis(event) {
    event.preventDefault();
    setError("");
    setCopied(false);

    if (mode === "message" && !sender.trim() && !message.trim()) {
      setError("Enter a sender email or message body before running analysis.");
      return;
    }

    if (mode === "url" && !url.trim()) {
      setError("Enter a URL to run a quick check.");
      return;
    }

    if (mode === "url" && !/^https?:\/\//i.test(url.trim())) {
      setError("Include http:// or https:// at the start of the URL.");
      return;
    }

    setLoading(true);
    setCheckedActions({});

    const payload = {
      mode,
      sender: mode === "message" ? sender.trim() : "",
      message: mode === "message" ? message.trim() : "",
      url: mode === "url" ? url.trim() : "",
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
        input: {
          mode,
          sender: mode === "message" ? sender.trim() : "",
          message: mode === "message" ? message.trim() : "",
          url: mode === "url" ? url.trim() : "",
        },
        sender_analysis: data.sender_analysis,
        content_analysis: data.content_analysis,
        url_analysis: data.url_analysis,
        playbook: data.playbook,
      };

      setResult(record);
      saveHistory(record);
    } catch (err) {
      console.error("Threat analysis request failed:", err);
      setError(
        `Analysis failed: ${
          err.message ||
          "Could not connect to the APERTURE intelligence backend at http://localhost:8000. Ensure the API server is running."
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

    const draft = [
      "APERTURE — SECURITY INCIDENT ESCALATION",
      `Timestamp: ${result.timestamp}`,
      `Verdict: ${result.verdict}`,
      `Threat score: ${result.threat_score}/100`,
      `Severity: ${result.playbook.severity_level}`,
      `Sender: ${result.sender_analysis.sender_email}`,
      `Extracted URLs: ${
        result.url_analysis.extracted_urls.join(", ") || "None found"
      }`,
      "",
      "Sender findings:",
      result.sender_analysis.domain_reputation_notes,
      "",
      "Content findings:",
      result.content_analysis.sentiment_analysis,
      "",
      "URL findings:",
      result.url_analysis.domain_risk_summary,
      "",
      "Recommended actions:",
      ...result.playbook.immediate_actions.map(
        (action, index) => `${index + 1}. ${action}`
      ),
      "",
      "Incident summary:",
      result.playbook.admin_alert_draft,
    ].join("\n");

    try {
      await navigator.clipboard.writeText(draft);
      setCopied(true);
    } catch {
      setError("Clipboard access failed. Check browser permissions and try again.");
    }
  }

  const verdict = result?.verdict || "";
  const colors = result ? getVerdictColors(verdict) : null;
  const actions = result?.playbook?.immediate_actions || [];
  const completedActions = actions.filter((_, index) => checkedActions[index]).length;

  return (
    <div className="space-y-7">
      <section>
        <p className="mb-2 text-xs font-semibold tracking-widest text-cyan-400">
          THREAT INTELLIGENCE ENGINE
        </p>
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h1 className="text-3xl font-bold tracking-tight text-white sm:text-4xl">
              Threat Analysis
            </h1>
            <p className="mt-3 max-w-2xl text-sm leading-6 text-slate-400">
              Examine suspicious emails and URLs across sender identity,
              social-engineering language, and domain risk indicators.
            </p>
          </div>
          <span className="inline-flex items-center gap-2 rounded-full border border-cyan-500/20 bg-cyan-500/5 px-3 py-2 text-xs font-medium text-cyan-300">
            <Radio size={14} className="animate-pulse text-cyan-400" />
            Live Triage Active
          </span>
        </div>
      </section>

      <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5 sm:p-6">
        <div className="mb-6 flex flex-wrap gap-2 border-b border-slate-800 pb-4">
          <button
            type="button"
            onClick={() => {
              setMode("message");
              setError("");
            }}
            className={`inline-flex items-center gap-2 rounded-xl px-4 py-3 text-sm font-medium transition ${
              mode === "message"
                ? "bg-cyan-400 text-slate-950"
                : "bg-slate-800 text-slate-300 hover:bg-slate-700"
            }`}
          >
            <Mail size={17} />
            Full Message Analyzer
          </button>

          <button
            type="button"
            onClick={() => {
              setMode("url");
              setError("");
            }}
            className={`inline-flex items-center gap-2 rounded-xl px-4 py-3 text-sm font-medium transition ${
              mode === "url"
                ? "bg-cyan-400 text-slate-950"
                : "bg-slate-800 text-slate-300 hover:bg-slate-700"
            }`}
          >
            <Link2 size={17} />
            Quick URL Check
          </button>
        </div>

        <form onSubmit={runAnalysis} className="space-y-5">
          {mode === "message" ? (
            <>
              <div>
                <label
                  htmlFor="sender-email"
                  className="mb-2 block text-sm font-medium text-slate-200"
                >
                  Sender email or display name
                </label>
                <input
                  id="sender-email"
                  value={sender}
                  onChange={(event) => setSender(event.target.value)}
                  placeholder="e.g. Microsoft Support <security-alerts@gmail.com>"
                  className="w-full rounded-xl border border-slate-700 bg-slate-950 px-4 py-3 text-sm text-white outline-none transition placeholder:text-slate-600 focus:border-cyan-400 focus:ring-2 focus:ring-cyan-400/10"
                />
              </div>

              <div>
                <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
                  <label
                    htmlFor="message-body"
                    className="text-sm font-medium text-slate-200"
                  >
                    Email or message body
                  </label>
                  <button
                    type="button"
                    onClick={loadSample}
                    className="inline-flex items-center gap-1.5 text-xs font-medium text-cyan-400 hover:text-cyan-300"
                  >
                    <FileSearch size={14} />
                    Load Sample Phishing Email
                  </button>
                </div>
                <textarea
                  id="message-body"
                  value={message}
                  onChange={(event) => setMessage(event.target.value)}
                  rows={8}
                  placeholder="Paste the suspicious message here..."
                  className="w-full resize-y rounded-xl border border-slate-700 bg-slate-950 px-4 py-3 text-sm leading-6 text-white outline-none transition placeholder:text-slate-600 focus:border-cyan-400 focus:ring-2 focus:ring-cyan-400/10"
                />
                <p className="mt-2 text-xs text-slate-500">
                  Avoid pasting real passwords, authentication codes, or other sensitive information.
                </p>
              </div>
            </>
          ) : (
            <div>
              <label
                htmlFor="quick-url"
                className="mb-2 block text-sm font-medium text-slate-200"
              >
                URL to inspect
              </label>
              <div className="flex flex-col gap-3 sm:flex-row">
                <div className="relative flex-1">
                  <Link2
                    size={18}
                    className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500"
                  />
                  <input
                    id="quick-url"
                    value={url}
                    onChange={(event) => setUrl(event.target.value)}
                    placeholder="https://example.com/login"
                    className="w-full rounded-xl border border-slate-700 bg-slate-950 py-3 pl-11 pr-4 text-sm text-white outline-none transition placeholder:text-slate-600 focus:border-cyan-400 focus:ring-2 focus:ring-cyan-400/10"
                  />
                </div>
                <button
                  type="button"
                  onClick={() => setUrl("http://micros0ft-account-security.example.com/verify")}
                  className="rounded-xl border border-slate-700 px-4 py-3 text-sm text-slate-300 transition hover:bg-slate-800"
                >
                  Use sample URL
                </button>
              </div>
              <p className="mt-3 text-xs text-slate-500">
                Bare URL mode evaluates domain reputation, typosquats, character homoglyphs, and deceptive subdomains.
              </p>
            </div>
          )}

          {error && (
            <div role="alert" className="rounded-xl border border-red-500/20 bg-red-500/10 px-4 py-3 text-sm text-red-300">
              {error}
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
                  Running Security Triage...
                </>
              ) : (
                <>
                  <ScanSearch size={17} />
                  Run Security Triage
                </>
              )}
            </button>

            <button
              type="button"
              onClick={resetForm}
              className="inline-flex items-center gap-2 rounded-xl border border-slate-700 px-4 py-3 text-sm font-medium text-slate-300 transition hover:bg-slate-800"
            >
              <RefreshCw size={16} />
              Reset
            </button>
          </div>
        </form>
      </section>

      {result && (
        <>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <p className="text-xs font-semibold tracking-widest text-cyan-400">
                ANALYSIS REPORT
              </p>
              <h2 className="mt-2 text-2xl font-bold text-white">
                Live Threat Intelligence Results
              </h2>
              <p className="mt-1 text-xs text-slate-500">
                APERTURE Triage · {result.timestamp}
              </p>
            </div>
            <button
              type="button"
              onClick={resetForm}
              className="inline-flex items-center gap-2 rounded-lg border border-slate-700 px-3 py-2 text-sm text-slate-300 hover:bg-slate-800"
            >
              <RefreshCw size={15} />
              New analysis
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
                </div>

                <p className="mt-3 max-w-2xl text-sm leading-6 text-slate-300">
                  {verdict === "PHISHING"
                    ? "Multiple malicious indicators identified across identity, context, or destination vectors. Immediate containment is advised."
                    : verdict === "SUSPICIOUS"
                    ? "Suspicious signals detected that warrant scrutiny and secondary channel verification before interacting."
                    : "Payload evaluated as safe. No malicious identity spoofing, psychological manipulation, or suspicious URLs detected."}
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
                    Threat score
                  </p>
                  <p className="mt-1 max-w-32 text-xs leading-5 text-slate-400">
                    Quantified by APERTURE Intelligence Engine
                  </p>
                </div>
              </div>
            </div>
          </section>

          <section className="grid grid-cols-1 gap-4 xl:grid-cols-3">
            <DiagnosticCard title="Sender & Identity Guard" icon={Mail}>
              <div>
                <p className="mb-1 text-xs text-slate-500">Sender</p>
                <p className="break-all text-sm font-medium text-slate-200">
                  {result.sender_analysis.sender_email}
                </p>
              </div>

              <div className="flex flex-wrap gap-2">
                <Flag
                  active={result.sender_analysis.is_spoofed}
                  yesText="Possible spoofing"
                  noText="No spoofing flagged"
                />
                <Flag
                  active={!result.sender_analysis.display_name_match}
                  yesText="Name mismatch"
                  noText="Name match"
                />
              </div>

              <p className="text-sm leading-6 text-slate-400">
                {result.sender_analysis.domain_reputation_notes}
              </p>
            </DiagnosticCard>

            <DiagnosticCard title="Behavioral & Context" icon={Eye}>
              <div className="flex flex-wrap gap-2">
                <Flag
                  active={result.content_analysis.urgency_tactics_detected}
                  yesText="Urgency detected"
                  noText="No urgency flagged"
                />
              </div>

              <div>
                <p className="mb-2 text-xs font-medium text-slate-500">
                  Psychological triggers
                </p>
                {result.content_analysis.psychological_triggers.length ? (
                  <div className="flex flex-wrap gap-2">
                    {result.content_analysis.psychological_triggers.map(
                      (trigger) => (
                        <span
                          key={trigger}
                          className="rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-xs text-slate-300"
                        >
                          {trigger}
                        </span>
                      )
                    )}
                  </div>
                ) : (
                  <p className="text-sm text-slate-500">No triggers listed.</p>
                )}
              </div>

              <div>
                <p className="mb-1 text-xs font-medium text-slate-500">
                  Sentiment analysis
                </p>
                <p className="text-sm leading-6 text-slate-400">
                  {result.content_analysis.sentiment_analysis}
                </p>
              </div>
            </DiagnosticCard>

            <DiagnosticCard title="URL & Domain Inspection" icon={Link2}>
              <div className="flex flex-wrap gap-2">
                <Flag
                  active={result.url_analysis.has_typosquatting}
                  yesText="Lookalike pattern"
                  noText="No lookalike flagged"
                />
                <Flag
                  active={result.url_analysis.suspicious_redirects}
                  yesText="Redirect concern"
                  noText="No redirect flagged"
                />
              </div>

              <div>
                <p className="mb-2 text-xs font-medium text-slate-500">
                  Extracted URLs
                </p>
                {result.url_analysis.extracted_urls.length ? (
                  <div className="space-y-2">
                    {result.url_analysis.extracted_urls.map((item) => (
                      <div
                        key={item}
                        className="flex items-start gap-2 rounded-lg border border-slate-800 bg-slate-950 p-3"
                      >
                        <ExternalLink
                          size={15}
                          className="mt-0.5 shrink-0 text-amber-400"
                        />
                        <span className="break-all text-xs leading-5 text-slate-300">
                          {item}
                        </span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-sm text-slate-500">No URLs listed.</p>
                )}
              </div>

              <p className="text-sm leading-6 text-slate-400">
                {result.url_analysis.domain_risk_summary}
              </p>
            </DiagnosticCard>
          </section>

          {verdict !== "SAFE" && (
            <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5 sm:p-6">
              <div className="flex flex-wrap items-start justify-between gap-4">
                <SectionHeading
                  icon={ClipboardCheck}
                  title="Incident Responder"
                  description="Review prioritized containment actions and monitor remediation checklist."
                  color="text-amber-400"
                />
                <span className="rounded-full border border-amber-500/20 bg-amber-500/10 px-3 py-1.5 text-xs font-semibold text-amber-300">
                  {result.playbook.severity_level} SEVERITY
                </span>
              </div>

              <div className="mt-6">
                <div className="mb-3 flex items-center justify-between gap-3 text-xs text-slate-400">
                  <span>Response checklist</span>
                  <span>
                    {completedActions} of {actions.length} completed
                  </span>
                </div>
                <div className="mb-5 h-1.5 overflow-hidden rounded-full bg-slate-800">
                  <div
                    className="h-full rounded-full bg-cyan-400 transition-all"
                    style={{
                      width: `${
                        actions.length
                          ? (completedActions / actions.length) * 100
                          : 0
                      }%`,
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
                    SOC / IT Escalation Draft
                  </h3>
                  <p className="mt-1 text-sm text-slate-400">
                    Pre-composed Tier-3 incident escalation report ready for one-click copy.
                  </p>
                </div>

                <div className="whitespace-pre-wrap rounded-xl border border-slate-800 bg-slate-950 p-4 text-sm leading-6 text-slate-300 font-mono">
                  {result.playbook.admin_alert_draft}
                </div>

                <button
                  type="button"
                  onClick={copyEscalation}
                  className="mt-4 inline-flex items-center gap-2 rounded-xl bg-cyan-400 px-4 py-3 text-sm font-semibold text-slate-950 transition hover:bg-cyan-300"
                >
                  {copied ? <CheckCircle2 size={17} /> : <Copy size={17} />}
                  {copied ? "Copied to clipboard" : "Copy escalation report"}
                </button>
              </div>
            </section>
          )}

          <p className="text-xs leading-5 text-slate-500">
            <ShieldCheck size={14} className="mr-1 inline-block text-cyan-400" />
            Triage results generated by APERTURE automated threat intelligence engine.
          </p>
        </>
      )}
    </div>
  );
}
