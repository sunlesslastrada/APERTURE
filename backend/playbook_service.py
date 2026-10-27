import os
import re
import uuid
import json
from datetime import datetime, timezone
from typing import List, Optional
from dotenv import load_dotenv

from schemas import IncidentPlaybook, SenderCheck, ContentCheck, URLCheck, PlaybookRequest

load_dotenv()


def calculate_severity(score: int) -> str:
    """NIST-aligned quantitative severity calibration."""
    if score >= 90:
        return "CRITICAL"
    elif score >= 70:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    return "LOW"


def infer_threat_archetype(
    snippet: str,
    sender: str,
    urls: List[str],
    triggers: List[str],
    threat_score: int
) -> str:
    """Classifies threat vectors into defined cybersecurity archetypes."""
    if threat_score < 40:
        return "BENIGN_LEGITIMATE"

    combined = f"{snippet} {sender} {' '.join(urls)} {' '.join(triggers)}".lower()

    # 1. Typosquatting / Homoglyph Indicators
    for u in urls:
        u_lower = u.lower()
        if any(h in u_lower for h in ["0", "1", "vv"]) and any(b in u_lower.replace("0", "o").replace("1", "l") for b in ["microsoft", "paypal", "apple", "google", "amazon", "netflix", "chase"]):
            return "BRAND_TYPOSQUATTING"
        if any(tld in u_lower for tld in [".top", ".xyz", ".biz", ".ru", ".tk"]):
            return "BRAND_TYPOSQUATTING"

    # 2. Financial / BEC Indicators
    if any(k in combined for k in ["wire", "invoice", "payment", "gift card", "bank transfer", "payroll", "ach", "remittance", "swift", "direct deposit", "w-2", "accounting"]):
        return "FINANCIAL_FRAUD_BEC"

    # 3. Malware / Dropper Indicators
    if any(k in combined for k in ["attachment", "macro", "download", "payload", ".exe", ".iso", ".zip", ".vbs", ".scr", "install update"]):
        return "MALWARE_DROPPER"

    # 4. Credential Harvesting (default phishing vector)
    if any(k in combined for k in ["login", "verify", "password", "account", "sso", "credential", "suspend", "unauthorized access", "session", "reset"]):
        return "CREDENTIAL_HARVESTING"

    return "CREDENTIAL_HARVESTING" if threat_score >= 70 else "BRAND_TYPOSQUATTING"


def get_mitre_mapping(archetype: str) -> str:
    """Maps threat archetype to MITRE ATT&CK techniques."""
    mappings = {
        "CREDENTIAL_HARVESTING": "T1566.002 (Phishing: Spearphishing Link) | T1528 (Steal Application Access Token) | T1539 (Steal Web Session Cookie)",
        "FINANCIAL_FRAUD_BEC": "T1566.002 (Phishing: Spearphishing Link) | T1534 (Internal Spearphishing) | T1656 (Impersonation)",
        "MALWARE_DROPPER": "T1566.001 (Phishing: Spearphishing Attachment) | T1204.002 (User Execution: Malicious File) | T1059 (Command and Scripting Interpreter)",
        "BRAND_TYPOSQUATTING": "T1583.001 (Acquire Infrastructure: Domains) | T1566.002 (Phishing: Spearphishing Link)",
        "BENIGN_LEGITIMATE": "N/A (Standard Benign Telemetry)"
    }
    return mappings.get(archetype, "T1566 (Phishing)")


def generate_rule_based_fallback(
    verdict: str,
    threat_score: int,
    sender_email: str,
    is_spoofed: bool,
    urgency_detected: bool,
    psychological_triggers: List[str],
    flagged_urls: List[str],
    raw_snippet: Optional[str] = "",
    threat_archetype: Optional[str] = None
) -> IncidentPlaybook:
    """
    Guaranteed fallback engine: Executes if Gemini API key is missing or throttled.
    Ensures APERTURE never throws a 500 error and generates NIST SP 800-61 / MITRE ATT&CK aligned playbooks.
    """
    severity = calculate_severity(threat_score)
    archetype = threat_archetype or infer_threat_archetype(
        snippet=raw_snippet or "",
        sender=sender_email,
        urls=flagged_urls,
        triggers=psychological_triggers,
        threat_score=threat_score
    )
    mitre_technique = get_mitre_mapping(archetype)
    incident_id = f"AP-{uuid.uuid4().hex[:8].upper()}"
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # MTTC Target calibration
    if severity == "CRITICAL":
        mttc = "< 15 Minutes (Immediate SecOps Tier-3 Escalation)"
    elif severity == "HIGH":
        mttc = "< 30 Minutes (High-Priority Incident Queue)"
    elif severity == "MEDIUM":
        mttc = "< 2 Hours (Standard Analyst Triage)"
    else:
        mttc = "Routine / Informational Telemetry"

    # Actions tailored to threat archetype
    if archetype == "CREDENTIAL_HARVESTING":
        immediate_command = "Revoke all active Azure AD / Okta SSO session tokens and force an Active Directory password reset for targeted user."
        actions = [
            "EMERGENCY IDENTITY LOCK: Invalidate active Azure AD/Okta SSO refresh tokens and terminate all concurrent web sessions.",
            "CREDENTIAL REVOCATION: Force mandatory out-of-band password reset across Active Directory for targeted victim.",
            "MFA CHALLENGE AUDIT: Inspect recent authentication logs for push-fatigue / MFA spray patterns or rogue authenticator app registrations.",
            "MAILBOX INTEGRITY AUDIT: Query Microsoft Graph / Google Workspace API for unauthorized inbox forwarding rules, delegates, and hidden rules.",
            "EDR BROWSER CACHE PURGE: Inspect endpoint for credential auto-fill submission or unauthorized password manager access."
        ]
    elif archetype == "FINANCIAL_FRAUD_BEC":
        immediate_command = "Notify Accounts Payable and Finance Treasury to place an immediate disbursement hold on any pending wire or ACH transactions."
        actions = [
            "FINANCIAL DISBURSEMENT FREEZE: Immediately notify Accounts Payable and Finance Treasury to place hold on pending wire transfers and ACH batches.",
            "OUT-OF-BAND PROTOCOL: Require secondary authorized voice verification with the purported requestor via verified internal extension.",
            "INBOX DELEGATION CHECK: Audit executive mailbox forwarding configurations and audit recent OAuth consents for third-party mail sync tools.",
            "SPF/DKIM/DMARC AUDIT: Inspect email headers for display-name impersonation bypassing perimeter DMARC alignment."
        ]
    elif archetype == "MALWARE_DROPPER":
        immediate_command = "Isolate the host endpoint from the local network VLAN via EDR console to prevent lateral movement."
        actions = [
            "HOST NETWORK ISOLATION: Execute immediate EDR command to isolate targeted endpoint host from corporate VLAN/subnet.",
            "VOLATILE MEMORY PRESERVATION: Trigger automated RAM memory dump and triage image capture before host shutdown for forensic analysis.",
            "EDR PROCESS TREE INSPECTION: Scan endpoint process tree for anomalous parent-child relationships (e.g. Word/Excel spawning PowerShell or cmd.exe).",
            "PERIMETER HASH SINKHOLE: Extract file hash/download URL and push IoC to perimeter firewall and secure email gateway (SEG) blacklist."
        ]
    elif archetype == "BRAND_TYPOSQUATTING":
        immediate_command = "Sinkhole the typosquatted domain across perimeter DNS firewalls and Secure Web Gateway (SWG) blocklists."
        actions = [
            "PERIMETER DNS SINKHOLE: Add typosquatted domain(s) to corporate DNS firewall, proxy blocklist, and Secure Web Gateway (SWG).",
            "REGISTRAR TAKEDOWN DISPATCH: Generate and transmit RFC 2142 abuse notification to destination registrar and hosting provider for malicious domain revocation.",
            "ENDPOINT AUTO-FILL PURGE: Clear stored browser session cache and auto-filled corporate credentials on affected user endpoints.",
            "SIEM TELEMETRY HUNT: Query proxy and DNS logs across the last 30 days for any prior organizational queries resolving to the malicious domain."
        ]
    else:  # BENIGN_LEGITIMATE
        immediate_command = "No active containment required. Record scan in SIEM telemetry log."
        actions = [
            "Standard email hygiene verified. No active containment required.",
            "Continue adhering to zero-trust email verification hygiene and out-of-band verification procedures.",
            "Log threat scan telemetry into SIEM index for baseline model calibration."
        ]

    # Clean formatting for indicators
    triggers_str = ", ".join(psychological_triggers) if psychological_triggers else "None detected"
    urls_str = ", ".join(f"`{u}`" for u in flagged_urls) if flagged_urls else "`None identified`"

    soc_report = f"""### 🚨 APERTURE TIER-3 INCIDENT ESCALATION BRIEFING
- **Incident Category**: `{archetype}`
- **Assigned Severity**: **{severity}** (Global Threat Score: **{threat_score}/100**)
- **MITRE ATT&CK Mapping**: `{mitre_technique}`
- **NIST SP 800-61 Lifecycle Phase**: `Containment, Eradication & Recovery`
- **Estimated MTTC Target**: `{mttc}`
- **Sender & Infrastructure**: `{sender_email}` (Spoofing Flag: `{"YES - High Risk" if is_spoofed else "NO"}`)
- **Attack Surface / IoCs**: {urls_str}
- **Social Engineering Vectors**: `{triggers_str}`

#### ⚡ Immediate Containment Command (NIST Containment Phase):
> {immediate_command}

#### 🛠️ Operational Remediation Steps:
""" + "\n".join(f"{i+1}. {act}" for i, act in enumerate(actions)) + f"""

---
*Report auto-compiled by APERTURE Threat Intelligence & Incident Response Engine.*
*Incident ID: {incident_id} | Timestamp: {timestamp}*
"""

    return IncidentPlaybook(
        immediate_actions=actions,
        admin_alert_draft=soc_report,
        severity_level=severity,
        threat_archetype=archetype
    )


def generate_playbook_with_gemini(
    verdict: str,
    threat_score: int,
    sender_email: str,
    is_spoofed: bool,
    urgency_detected: bool,
    psychological_triggers: List[str],
    flagged_urls: List[str],
    raw_snippet: Optional[str] = "",
    threat_archetype: Optional[str] = None
) -> IncidentPlaybook:
    """
    Uses Gemini 2.5 Flash to generate context-tailored IncidentPlaybook.
    Falls back gracefully to the rule-based fallback engine if the API fails or key is missing.
    """
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key or api_key == "your_gemini_api_key_here":
        return generate_rule_based_fallback(
            verdict=verdict,
            threat_score=threat_score,
            sender_email=sender_email,
            is_spoofed=is_spoofed,
            urgency_detected=urgency_detected,
            psychological_triggers=psychological_triggers,
            flagged_urls=flagged_urls,
            raw_snippet=raw_snippet,
            threat_archetype=threat_archetype
        )

    try:
        from google import genai
        from google.genai import types

        client = genai.Client(api_key=api_key, http_options={"api_version": "v1beta", "timeout": 20000})

        prompt = f"""
You are the autonomous Tier-3 Incident Commander for APERTURE.
Analyze the following threat triage data and generate an actionable, NIST SP 800-61 and MITRE ATT&CK aligned IncidentPlaybook.

THREAT CONTEXT:
- Verdict: {verdict}
- Threat Score: {threat_score}/100
- Threat Archetype: {threat_archetype or 'Infer based on payload'}
- Sender Email: {sender_email} (Spoofed: {is_spoofed})
- Urgency/Fear Tactics: {urgency_detected}
- Psychological Triggers: {', '.join(psychological_triggers)}
- Flagged URLs: {', '.join(flagged_urls)}
- Raw Snippet: {raw_snippet}

REQUIREMENTS:
1. threat_archetype: Strictly one of: "CREDENTIAL_HARVESTING", "FINANCIAL_FRAUD_BEC", "MALWARE_DROPPER", "BRAND_TYPOSQUATTING", "BENIGN_LEGITIMATE".
2. immediate_actions: A list of 3-5 prioritized, concrete containment commands tailored to the archetype (e.g. Active Directory/SSO revocation for credentials, accounts payable freeze for BEC, VLAN isolation for malware, DNS sinkhole for typosquats).
3. admin_alert_draft: A professional markdown-formatted SOC incident escalation briefing formatted as:
### 🚨 APERTURE TIER-3 INCIDENT ESCALATION BRIEFING
- **Incident Category**: [Detected Archetype]
- **Assigned Severity**: [LOW | MEDIUM | HIGH | CRITICAL]
- **MITRE ATT&CK Mapping**: [e.g., T1566.002 - Spearphishing Link]
- **NIST SP 800-61 Lifecycle Phase**: Containment, Eradication & Recovery
- **Estimated MTTC Target**: [e.g., < 15 Minutes (Immediate SecOps Tier-3 Escalation)]
- **Sender & Infrastructure**: [Sender address and spoofing status]
- **Attack Surface / IoCs**: [Flagged URLs, domains, homoglyphs]
- **Social Engineering Vectors**: [Psychological triggers]

#### ⚡ Immediate Containment Command (NIST Containment Phase):
> [Single most urgent action for IT/SecOps]

#### 🛠️ Operational Remediation Steps:
[Numbered list of immediate containment actions]
4. severity_level: Strictly match score thresholds (>=90: "CRITICAL", >=70: "HIGH", >=40: "MEDIUM", <40: "LOW").
"""

        candidate_models = [
            os.getenv("GEMINI_MODEL", "gemini-3.8-flash"),
            "gemini-3.8-flash",
            "gemini-3.5-flash",
            "gemini-3.1-flash-lite"
        ]
        seen = set()
        unique_candidates = [m for m in candidate_models if not (m in seen or seen.add(m))]

        response = None
        last_err = None

        for model_name in unique_candidates:
            try:
                response = client.models.generate_content(
                    model=model_name,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        response_mime_type="application/json",
                        response_schema=IncidentPlaybook,
                        temperature=0.1
                    ),
                )
                if response and response.text:
                    break
            except Exception as model_err:
                last_err = model_err
                err_str = str(model_err)
                is_recoverable = any(
                    k in err_str for k in [
                        "404", "NOT_FOUND", "503", "UNAVAILABLE", "429", "RESOURCE_EXHAUSTED", "504", "DEADLINE_EXCEEDED", "no longer available", "high demand"
                    ]
                )
                if is_recoverable:
                    print(f"[APERTURE Playbook] Model '{model_name}' temporary issue ({err_str[:80]}). Cascading to next candidate...")
                    continue
                raise model_err

        if not response or not response.text:
            if last_err:
                raise last_err
            raise RuntimeError("Empty response received from Gemini engine.")

        data = json.loads(response.text)
        return IncidentPlaybook(**data)

    except Exception as exc:
        print(f"[APERTURE Playbook Error] {exc}. Routing to deterministic fallback.")
        return generate_rule_based_fallback(
            verdict=verdict,
            threat_score=threat_score,
            sender_email=sender_email,
            is_spoofed=is_spoofed,
            urgency_detected=urgency_detected,
            psychological_triggers=psychological_triggers,
            flagged_urls=flagged_urls,
            raw_snippet=raw_snippet,
            threat_archetype=threat_archetype
        )
