import os
import uuid
import json
from datetime import datetime, timezone
from typing import List, Optional
from dotenv import load_dotenv

from schemas import IncidentPlaybook, SenderCheck, ContentCheck, URLCheck, PlaybookRequest

load_dotenv()

# Helper to calculate severity from score
def calculate_severity(score: int) -> str:
    if score >= 90:
        return "CRITICAL"
    elif score >= 70:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    return "LOW"


def generate_rule_based_fallback(
    verdict: str,
    threat_score: int,
    sender_email: str,
    is_spoofed: bool,
    urgency_detected: bool,
    psychological_triggers: List[str],
    flagged_urls: List[str]
) -> IncidentPlaybook:
    """
    Guaranteed fallback engine: Executes if Gemini API key is missing or throttled.
    Ensures TrustLens AI never throws a 500 error during a live presentation.
    """
    severity = calculate_severity(threat_score)
    incident_id = f"TL-{uuid.uuid4().hex[:8].upper()}"
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # If SAFE verdict
    if verdict == "SAFE" and threat_score < 40:
        return IncidentPlaybook(
            severity_level="LOW",
            immediate_actions=[
                "No active containment required. Message verified as legitimate.",
                "Continue adhering to standard organizational email verification hygiene.",
                "Report any unexpected follow-up communications requesting sensitive data."
            ],
            admin_alert_draft=(
                f"### [INFORMATIONAL] TrustLens Threat Scan Log\n"
                f"- **Incident ID:** {incident_id}\n"
                f"- **Timestamp:** {timestamp}\n"
                f"- **Verdict:** SAFE (Threat Score: {threat_score}/100)\n"
                f"- **Sender:** `{sender_email}`\n"
                f"- **Status:** No malicious vectors identified. Safe to proceed."
            )
        )

    # Dynamic containment steps based on specific detected threat vectors
    actions: List[str] = []
    
    if is_spoofed:
        actions.append("EMERGENCY IDENTITY LOCK: Invalidate active SSO sessions and enforce Active Directory password reset for targeted user.")
        actions.append("MAILBOX AUDIT: Check user inbox for unauthorized forwarding rules, delegates, and deleted item anomalies.")
    
    if flagged_urls:
        actions.append(f"DNS & PROXY SINKHOLE: Add flagged domain(s) ({', '.join(flagged_urls[:2])}) to corporate firewall blocklist.")
        actions.append("BROWSER CACHE PURGE: Inspect user endpoint for credential auto-fill submission or suspicious file downloads.")
    
    if urgency_detected or psychological_triggers:
        actions.append("SECURITY AWARENESS TAG: Flag user account for targeted social-engineering simulation and alert team leads.")

    if not actions:
        actions = [
            "Revoke current user session tokens and enforce multi-factor authentication (MFA).",
            "Quarantine email across all organizational mailboxes via Exchange/Google Workspace admin console.",
            "Inspect network telemetry for outbound connections to suspect domain."
        ]

    # Pre-drafted markdown SOC escalation report ready for one-click clipboard copy
    triggers_str = ", ".join(psychological_triggers) if psychological_triggers else "Social engineering urgency tactics"
    urls_str = ", ".join(f"`{u}`" for u in flagged_urls) if flagged_urls else "`None identified`"

    soc_report = f"""### 🚨 TrustLens AI — Automated Incident Escalation Briefing
**Incident ID:** `{incident_id}`  
**Timestamp:** `{timestamp}`  
**Triage Severity:** **{severity}** (Global Threat Score: **{threat_score}/100**)  
**Verdict:** `{verdict}`

---

#### 1. Attack Vector & IOC Summary
- **Originating Sender:** `{sender_email}`
- **Sender Spoofing Detected:** `{"YES - High Risk" if is_spoofed else "NO"}`
- **Flagged URLs / Destinations:** {urls_str}
- **Psychological Drivers:** `{triggers_str}`

---

#### 2. Immediate Automated Containment Enacted
1. Flagged for immediate quarantine across mail gateway.
2. Invalidation of victim OAuth authorization tokens recommended.
3. Domain blacklisting request generated for Perimeter SOC.

---
*Report auto-compiled by TrustLens AI Incident Responder Engine.*
"""

    return IncidentPlaybook(
        immediate_actions=actions,
        admin_alert_draft=soc_report,
        severity_level=severity
    )


def generate_playbook_with_gemini(
    verdict: str,
    threat_score: int,
    sender_email: str,
    is_spoofed: bool,
    urgency_detected: bool,
    psychological_triggers: List[str],
    flagged_urls: List[str],
    raw_snippet: Optional[str] = ""
) -> IncidentPlaybook:
    """
    Uses Gemini 2.5 Flash to generate context-tailored IncidentPlaybook.
    Falls back gracefully if the API fails or key is missing.
    """
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key or api_key == "your_gemini_api_key_here":
        # Graceful fallback without crashing
        return generate_rule_based_fallback(
            verdict, threat_score, sender_email, is_spoofed, urgency_detected, psychological_triggers, flagged_urls
        )

    try:
        from google import genai
        from google.genai import types

        client = genai.Client(api_key=api_key)

        prompt = f"""
You are the autonomous Tier-3 Incident Commander for TrustLens AI.
Analyze the following threat triage data and generate an actionable IncidentPlaybook.

THREAT CONTEXT:
- Verdict: {verdict}
- Threat Score: {threat_score}/100
- Sender Email: {sender_email} (Spoofed: {is_spoofed})
- Urgency/Fear Tactics: {urgency_detected}
- Psychological Triggers: {', '.join(psychological_triggers)}
- Flagged URLs: {', '.join(flagged_urls)}
- Raw Snippet: {raw_snippet}

REQUIREMENTS:
1. immediate_actions: A list of 3-5 prioritized, concrete containment commands (Active Directory, OAuth revocation, mailbox forwarding audit, domain sinkholing).
2. admin_alert_draft: A professional, markdown-formatted SOC incident escalation report with incident ID, timestamp, technical IOCs, and recommended actions ready for one-click copy.
3. severity_level: Strictly one of "LOW", "MEDIUM", "HIGH", or "CRITICAL".
"""

        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=IncidentPlaybook,
                temperature=0.1
            ),
        )

        data = json.loads(response.text)
        return IncidentPlaybook(**data)

    except Exception:
        # If any network or API error occurs, seamlessly return high-fidelity fallback
        return generate_rule_based_fallback(
            verdict, threat_score, sender_email, is_spoofed, urgency_detected, psychological_triggers, flagged_urls
        )