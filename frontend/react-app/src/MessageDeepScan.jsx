import { useState, useRef } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  ShieldAlert,
  ShieldCheck,
  ScanSearch,
  Mail,
  Copy,
  ClipboardCheck,
  LoaderCircle,
  ExternalLink,
  RefreshCw,
  FileSearch,
  Eye,
  Radio,
  Tag,
  UploadCloud,
  FileText,
  Image as ImageIcon,
  X,
  Link2,
} from "lucide-react";

const HISTORY_KEY = "aperture-threat-history";
const LEGACY_HISTORY_KEY = "trust-lens-history";

const SAMPLE_SENDER = "Microsoft Security Response <security-alerts@gmail.com>";

const SAMPLE_MESSAGE = `URGENT SECURITY ALERT: Your Microsoft 365 enterprise account will be permanently suspended within 24 hours.

We detected unusual login attempts from an untrusted IP address. You must verify your credentials immediately to prevent account termination and loss of email access.

Verify your account credentials now:
http://micros0ft-account-security.example.com/verify

Failure to verify immediately will result in complete Active Directory deprovisioning.`;

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
    case "CREDENTIAL_HARVESTING":
      return "Credential Harvesting";
    case "FINANCIAL_FRAUD_BEC":
      return "Financial Fraud / BEC";
    case "MALWARE_DROPPER":
      return "Malware Dropper";
    case "BRAND_TYPOSQUATTING":
      return "Brand Typosquatting";
    case "BENIGN_LEGITIMATE":
      return "Benign / Verified";
    default:
      return archetype ? archetype.replace(/_/g, " ") : "Benign";
  }
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

export default function MessageDeepScan() {
  const [sender, setSender] = useState("");
  const [message, setMessage] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [extracting, setExtracting] = useState(false);
  const [error, setError] = useState("");
  const [visionWarning, setVisionWarning] = useState("");
  const [checkedActions, setCheckedActions] = useState({});
  const [copied, setCopied] = useState(false);
  const [dragActive, setDragActive] = useState(false);
  const [uploadedFileName, setUploadedFileName] = useState("");

  const fileInputRef = useRef(null);

  function loadSample() {
    setSender(SAMPLE_SENDER);
    setMessage(SAMPLE_MESSAGE);
    setError("");
    setVisionWarning("");
    setResult(null);
    setCheckedActions({});
  }

  function resetForm() {
    setSender("");
    setMessage("");
    setResult(null);
    setError("");
    setVisionWarning("");
    setCheckedActions({});
    setCopied(false);
    setUploadedFileName("");
  }

  async function handleScreenshotUpload(file) {
    if (!file) return;

    if (!file.type.startsWith("image/")) {
      setError("Please upload an image file (PNG, JPG, JPEG, WEBP).");
      return;
    }

    setExtracting(true);
    setError("");
    setVisionWarning("");
    setUploadedFileName(file.name);

    const formData = new FormData();
    formData.append("file", file);

    try {
      const response = await fetch("http://localhost:8000/api/extract-screenshot", {
        method: "POST",
        body: formData,
      });

      if (!response.ok) {
        throw new Error(`Vision service returned HTTP ${response.status}`);
      }

      const data = await response.json();

      if (data.sender) {
        setSender(data.sender);
      }
      if (data.message) {
        setMessage(data.message);
      }

      if (data.missing_critical_info && data.missing_critical_info.length > 0) {
        setVisionWarning(
          `Partial extraction: ${data.missing_critical_info.join(". ")}. Please review or enter missing details manually before running inspection.`
        );
      }
    } catch (err) {
      console.error("Screenshot extraction error:", err);
      setError(`Screenshot visual extraction failed: ${err.message || "Ensure the APERTURE backend is running."}`);
    } finally {
      setExtracting(false);
    }
  }

  function handleDrop(e) {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleScreenshotUpload(e.dataTransfer.files[0]);
    }
  }

  function handleDrag(e) {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  }

  async function runInspection(event) {
    event.preventDefault();
    setError("");
    setCopied(false);

    if (!sender.trim() && !message.trim()) {
      setError("Enter a sender email header or message body before initiating inspection.");
      return;
    }

    setLoading(true);
    setCheckedActions({});

    const payload = {
      mode: "message",
      sender: sender.trim(),
      message: message.trim(),
      url: "",
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
        threat_archetype: data.threat_archetype || data.playbook?.threat_archetype || "BENIGN_LEGITIMATE",
        input: {
          mode: "message",
          sender: sender.trim(),
          message: message.trim(),
          url: "",
        },
        sender_analysis: data.sender_analysis,
        content_analysis: data.content_analysis,
        url_analysis: data.url_analysis,
        playbook: data.playbook,
      };

      setResult(record);
      saveHistory(record);
    } catch (err) {
      console.error("Vector inspection failed:", err);
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

  return (
    <div className="space-y-7">
      <section>
        <p className="mb-2 text-xs font-semibold tracking-widest text-cyan-400">
          VECTOR DEEPSCAN · MULTIMODAL COMMUNICATIONS ENGINE
        </p>
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h1 className="text-3xl font-bold tracking-tight text-white sm:text-4xl">
              Message & Email DeepScan
            </h1>
            <p className="mt-3 max-w-2xl text-sm leading-6 text-slate-400">
              Deep semantic evaluation across identity headers, social-engineering manipulation,
              and embedded attack vectors. Ingest raw headers or drop email screenshots for Gemini multimodal vision extraction.
            </p>
          </div>
          <span className="inline-flex items-center gap-2 rounded-full border border-cyan-500/20 bg-cyan-500/5 px-3 py-2 text-xs font-medium text-cyan-300">
            <Radio size={14} className="animate-pulse text-cyan-400" />
            Sensor Array Ready
          </span>
        </div>
      </section>

      {/* Multimodal Screenshot Ingestion Dropzone */}
      <section className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
        <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
          <div className="flex items-center gap-2.5">
            <div className="rounded-lg bg-cyan-500/10 p-2 text-cyan-400">
              <ImageIcon size={18} />
            </div>
            <div>
              <h2 className="text-sm font-semibold text-white">Multimodal Screenshot Vision Extraction</h2>
              <p className="text-xs text-slate-400">Upload a screenshot of an email, SMS, or suspicious prompt to extract text automatically using Gemini Vision.</p>
            </div>
          </div>
          {uploadedFileName && (
            <span className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-950 px-3 py-1 text-xs text-slate-300">
              <FileText size={13} className="text-cyan-400" />
              {uploadedFileName}
            </span>
          )}
        </div>

        <div
          onDragEnter={handleDrag}
          onDragLeave={handleDrag}
          onDragOver={handleDrag}
          onDrop={handleDrop}
          onClick={() => fileInputRef.current?.click()}
          className={`flex flex-col items-center justify-center rounded-xl border-2 border-dashed p-6 text-center cursor-pointer transition ${
            dragActive
              ? "border-cyan-400 bg-cyan-500/10"
              : "border-slate-700/80 bg-slate-950/40 hover:border-slate-600 hover:bg-slate-950/60"
          }`}
        >
          <input
            ref={fileInputRef}
            type="file"
            accept="image/png,image/jpeg,image/webp"
            className="hidden"
            onChange={(e) => {
              if (e.target.files && e.target.files[0]) {
                handleScreenshotUpload(e.target.files[0]);
              }
            }}
          />

          {extracting ? (
            <div className="flex flex-col items-center gap-3">
              <LoaderCircle size={28} className="animate-spin text-cyan-400" />
              <p className="text-sm font-medium text-cyan-300">
                Extracting message telemetry from screenshot via Gemini 2.5 Flash Vision...
              </p>
              <p className="text-xs text-slate-500">Isolating sender headers, body paragraphs, and destination URLs</p>
            </div>
          ) : (
            <div className="flex flex-col items-center gap-2">
              <div className="rounded-full bg-slate-800 p-3 text-cyan-400">
                <UploadCloud size={24} />
              </div>
              <p className="text-sm font-medium text-slate-200">
                <span className="text-cyan-400 hover:underline">Click to upload</span> or drag and drop an email screenshot
              </p>
              <p className="text-xs text-slate-500">Supports PNG, JPG, JPEG, WEBP up to 10MB</p>
            </div>
          )}
        </div>

        {visionWarning && (
          <div role="alert" className="mt-4 flex items-start gap-3 rounded-xl border border-amber-500/30 bg-amber-500/10 p-3.5 text-xs leading-5 text-amber-200">
            <AlertTriangle size={17} className="mt-0.5 shrink-0 text-amber-400" />
            <div className="flex-1">
              <span className="font-semibold">⚠️ Telemetry Notice: </span>
              {visionWarning}
            </div>
          </div>
        )}
      </section>

      {/* Main Inspection Form */}
      <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5 sm:p-6">
        <form onSubmit={runInspection} className="space-y-5">
          <div>
            <label htmlFor="sender-email" className="mb-2 block text-sm font-medium text-slate-200">
              Sender Email Header / Display Name
            </label>
            <input
              id="sender-email"
              value={sender}
              onChange={(e) => setSender(e.target.value)}
              placeholder="e.g. Microsoft Security Alert <security-response@gmail.com>"
              className="w-full rounded-xl border border-slate-700 bg-slate-950 px-4 py-3 text-sm text-white outline-none transition placeholder:text-slate-600 focus:border-cyan-400 focus:ring-2 focus:ring-cyan-400/10"
            />
          </div>

          <div>
            <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
              <label htmlFor="message-body" className="text-sm font-medium text-slate-200">
                Email / Communication Body
              </label>
              <button
                type="button"
                onClick={loadSample}
                className="inline-flex items-center gap-1.5 text-xs font-medium text-cyan-400 hover:text-cyan-300"
              >
                <FileSearch size={14} />
                Load Sample Phishing Ingress
              </button>
            </div>
            <textarea
              id="message-body"
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              rows={8}
              placeholder="Paste suspicious message text, phishing lure, or extracted vision body here..."
              className="w-full resize-y rounded-xl border border-slate-700 bg-slate-950 px-4 py-3 text-sm leading-6 text-white outline-none transition placeholder:text-slate-600 focus:border-cyan-400 focus:ring-2 focus:ring-cyan-400/10"
            />
            <p className="mt-2 text-xs text-slate-500">
              Content is processed locally through APERTURE payload sanitization prior to inference.
            </p>
          </div>

          {error && (
            <div role="alert" className="rounded-xl border border-red-500/20 bg-red-500/10 px-4 py-3 text-sm text-red-300">
              {error}
            </div>
          )}

          {loading && (
            <div className="flex items-center gap-3 rounded-xl border border-cyan-500/30 bg-cyan-500/10 px-4 py-3 text-sm text-cyan-300 animate-pulse">
              <LoaderCircle size={18} className="animate-spin text-cyan-400 shrink-0" />
              <span>Initiating Vector Inspection across Sender, Content, and Embedded Hyperlink Vectors...</span>
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
                  Inspecting Vectors...
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
                VECTOR DEEPSCAN TELEMETRY
              </p>
              <h2 className="mt-2 text-2xl font-bold text-white">
                Adversarial Inspection Findings
              </h2>
              <p className="mt-1 text-xs text-slate-500">
                APERTURE DeepScan · {result.timestamp}
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
                    ? "Critical attack indicators confirmed across identity headers and psychological manipulation vectors. Immediate containment required."
                    : verdict === "SUSPICIOUS"
                    ? "High-risk behavioral vectors or unverified sender routing observed. Exercise caution prior to engagement."
                    : "No malicious indicators detected. Communication conforms to standard transactional hygiene."}
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
                    Threat Index
                  </p>
                  <p className="mt-1 max-w-32 text-xs leading-5 text-slate-400">
                    NIST SP 800-61 Calibrated Threat Score
                  </p>
                </div>
              </div>
            </div>
          </section>

          <section className="grid grid-cols-1 gap-4 xl:grid-cols-3">
            <DiagnosticCard title="Sender & Identity Guard" icon={Mail}>
              <div>
                <p className="mb-1 text-xs text-slate-500">Sender Origin</p>
                <p className="break-all text-sm font-medium text-slate-200">
                  {result.sender_analysis.sender_email}
                </p>
              </div>

              <div className="flex flex-wrap gap-2">
                <Flag
                  active={result.sender_analysis.is_spoofed}
                  yesText="Spoofing Flagged"
                  noText="Identity Aligned"
                />
                <Flag
                  active={!result.sender_analysis.display_name_match}
                  yesText="Name Mismatch"
                  noText="Header Match"
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
                  yesText="Urgency Coercion"
                  noText="Neutral Register"
                />
              </div>

              <div>
                <p className="mb-2 text-xs font-medium text-slate-500">
                  Psychological Drivers
                </p>
                {result.content_analysis.psychological_triggers.length ? (
                  <div className="flex flex-wrap gap-2">
                    {result.content_analysis.psychological_triggers.map((trigger) => (
                      <span
                        key={trigger}
                        className="rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-xs text-slate-300"
                      >
                        {trigger}
                      </span>
                    ))}
                  </div>
                ) : (
                  <p className="text-sm text-slate-500">No coercive drivers detected.</p>
                )}
              </div>

              <div>
                <p className="mb-1 text-xs font-medium text-slate-500">
                  Sentiment Evaluation
                </p>
                <p className="text-sm leading-6 text-slate-400">
                  {result.content_analysis.sentiment_analysis}
                </p>
              </div>
            </DiagnosticCard>

            <DiagnosticCard title="Extracted Hyperlinks" icon={Link2}>
              <div>
                <p className="mb-2 text-xs font-medium text-slate-500">
                  Extracted URLs ({result.url_analysis.extracted_urls.length})
                </p>
                {result.url_analysis.extracted_urls.length ? (
                  <div className="space-y-2">
                    {result.url_analysis.extracted_urls.map((item) => (
                      <div
                        key={item}
                        className="flex items-start gap-2 rounded-lg border border-slate-800 bg-slate-950 p-3"
                      >
                        <ExternalLink size={15} className="mt-0.5 shrink-0 text-amber-400" />
                        <span className="break-all text-xs leading-5 text-slate-300">
                          {item}
                        </span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-sm text-slate-500">No embedded hyperlinks detected.</p>
                )}
              </div>

              <div className="flex flex-wrap gap-2">
                <Flag
                  active={result.url_analysis.has_typosquatting}
                  yesText="Lookalike Domain"
                  noText="Clean Hostname"
                />
              </div>

              <p className="text-sm leading-6 text-slate-400">
                {result.url_analysis.domain_risk_summary}
              </p>
            </DiagnosticCard>
          </section>

          {/* Incident Responder Checklist & SOC Notice */}
          {verdict !== "SAFE" && (
            <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5 sm:p-6">
              <div className="flex flex-wrap items-start justify-between gap-4">
                <div className="flex items-start gap-3">
                  <div className="rounded-xl bg-slate-800 p-2.5">
                    <ClipboardCheck size={20} className="text-amber-400" />
                  </div>
                  <div>
                    <h3 className="font-semibold text-white">Incident Containment Deck</h3>
                    <p className="mt-1 text-sm leading-5 text-slate-400">
                      NIST SP 800-61 aligned containment protocol for SecOps analysts.
                    </p>
                  </div>
                </div>
                <span className="rounded-full border border-amber-500/20 bg-amber-500/10 px-3 py-1.5 text-xs font-semibold text-amber-300">
                  {result.playbook.severity_level} SEVERITY
                </span>
              </div>

              <div className="mt-6">
                <div className="mb-3 flex items-center justify-between gap-3 text-xs text-slate-400">
                  <span>Containment Checklist</span>
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
                    SOC Escalation Briefing (MITRE ATT&CK Aligned)
                  </h3>
                  <p className="mt-1 text-sm text-slate-400">
                    Pre-composed Tier-3 technical escalation notice ready for one-click SecOps dispatch.
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
            Telemetry verified by APERTURE Vector DeepScan Engine.
          </p>
        </>
      )}
    </div>
  );
}
