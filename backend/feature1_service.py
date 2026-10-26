import os
import re
import json
import urllib.parse
from typing import List, Tuple, Optional
from dotenv import load_dotenv

from schemas import (
    AnalyzePayload,
    ThreatAnalysisResponse,
    SenderCheck,
    ContentCheck,
    URLCheck,
    IncidentPlaybook
)
from playbook_service import generate_rule_based_fallback, calculate_severity

load_dotenv()

# Regex patterns for heuristic fallback analysis
URL_PATTERN = re.compile(
    r'https?://(?:www\.)?[-a-zA-Z0-9@:%._+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b[-a-zA-Z0-9()@:%_+.~#?&/=]*',
    re.IGNORECASE
)
EMAIL_PATTERN = re.compile(r'[\w.-]+@[\w.-]+\.\w+', re.IGNORECASE)

KNOWN_FREE_MAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com", "mail.com", "protonmail.com"
}
SUSPICIOUS_TLDS = {
    "top", "xyz", "biz", "ru", "work", "click", "buzz", "country", "live", "gq", "ml", "cf", "tk"
}
BRAND_KEYWORDS = [
    "microsoft", "paypal", "apple", "google", "amazon", "netflix", "bank", "chase", "wells", "support", "security"
]
URGENCY_KEYWORDS = [
    "urgent", "immediately", "immediate", "suspended", "suspension", "suspend", "action required",
    "terminate", "unauthorized", "unusual activity", "locked", "expire", "critical", "compromised",
    "verify your account", "verify identity", "failure to act", "within 24 hours", "within 30 minutes"
]


def extract_sender_info(raw_sender: str) -> Tuple[str, str]:
    """Extract display name and email address from raw sender string."""
    raw_sender = raw_sender.strip()
    match = re.search(r'^(.*?)\s*<([\w.-]+@[\w.-]+\.\w+)>$', raw_sender)
    if match:
        return match.group(1).strip().strip('"\''), match.group(2).strip()
    email_match = EMAIL_PATTERN.search(raw_sender)
    if email_match:
        return "", email_match.group(0).strip()
    return "", raw_sender


def analyze_heuristics_fallback(payload: AnalyzePayload) -> ThreatAnalysisResponse:
    """
    High-fidelity deterministic fallback engine for Feature 1.
    Executes if GEMINI_API_KEY is missing, rate-limited, or offline.
    Guarantees APERTURE never returns a 500 status code.
    """
    mode = payload.mode
    raw_sender = (payload.sender or "").strip()
    raw_message = (payload.message or "").strip()
    raw_url = (payload.url or "").strip()

    # 1. Extract URLs
    extracted_urls: List[str] = []
    if mode == "url" and raw_url:
        extracted_urls.append(raw_url)
    elif mode == "message" and raw_message:
        extracted_urls = URL_PATTERN.findall(raw_message)

    # 2. Sender Analysis
    display_name, sender_email = extract_sender_info(raw_sender)
    if not sender_email and mode == "message":
        sender_email = "unknown-sender@unspecified.domain"
    elif not sender_email and mode == "url":
        sender_email = "direct-url-submission@aperture.local"

    sender_domain = sender_email.split("@")[-1].lower() if "@" in sender_email else ""
    is_spoofed = False
    display_name_match = True
    domain_reputation_notes = ""

    display_lower = display_name.lower()
    impersonated_brand = None
    for brand in BRAND_KEYWORDS:
        if brand in display_lower:
            impersonated_brand = brand
            break

    if impersonated_brand:
        if sender_domain in KNOWN_FREE_MAIL_DOMAINS:
            is_spoofed = True
            display_name_match = False
            domain_reputation_notes = (
                f"High-risk spoofing: Display name claims '{display_name}', but originates "
                f"from a consumer email provider (@{sender_domain})."
            )
        elif impersonated_brand not in sender_domain:
            is_spoofed = True
            display_name_match = False
            domain_reputation_notes = (
                f"Brand mismatch: Sender claims '{display_name}' but domain is '{sender_domain}'."
            )
        else:
            domain_reputation_notes = f"Sender domain aligns with reported organization '{display_name}'."
    else:
        if sender_domain in KNOWN_FREE_MAIL_DOMAINS:
            domain_reputation_notes = f"Consumer webmail domain (@{sender_domain}) detected."
        elif sender_domain:
            domain_reputation_notes = f"Domain '{sender_domain}' evaluated. No obvious identity spoofing detected."
        else:
            domain_reputation_notes = "No sender email header provided for deep identity verification."

    # 3. Content Analysis
    urgency_detected = False
    psychological_triggers: List[str] = []
    text_to_check = f"{raw_message} {raw_sender}".lower()

    for kw in URGENCY_KEYWORDS:
        if kw in text_to_check:
            urgency_detected = True
            if "suspend" in kw or "lock" in kw or "terminate" in kw:
                if "Threat of account suspension" not in psychological_triggers:
                    psychological_triggers.append("Threat of account suspension")
            elif "24 hours" in kw or "30 minutes" in kw or "immediately" in kw or "urgent" in kw:
                if "Artificial urgency" not in psychological_triggers:
                    psychological_triggers.append("Artificial urgency")
            elif "verify" in kw or "activity" in kw or "compromised" in kw:
                if "Fear of unauthorized access" not in psychological_triggers:
                    psychological_triggers.append("Fear of unauthorized access")

    if not psychological_triggers and urgency_detected:
        psychological_triggers.append("Coercive / High-Pressure Urgency")

    if urgency_detected:
        sentiment_analysis = (
            "Manipulative and pressuring language detected designed to induce panic and force compliance "
            "without authenticating through verified channels."
        )
    else:
        sentiment_analysis = (
            "Neutral communication tone. No aggressive behavioral extortion or artificial urgency triggers identified."
        )

    # 4. URL & Typosquatting Analysis
    has_typosquatting = False
    suspicious_redirects = False
    domain_risk_reasons: List[str] = []

    for url_item in extracted_urls:
        try:
            parsed = urllib.parse.urlparse(url_item if "://" in url_item else f"http://{url_item}")
            hostname = parsed.hostname or ""
            parts = hostname.lower().split(".")
            tld = parts[-1] if len(parts) > 1 else ""

            # Check typosquatting / homoglyphs
            if any(char in hostname for char in ["0", "1", "vv"]):
                if any(brand in hostname.replace("0", "o").replace("1", "l") for brand in BRAND_KEYWORDS):
                    has_typosquatting = True
                    domain_risk_reasons.append(f"Typosquatting/homoglyph detected in hostname '{hostname}'.")

            # Check suspicious TLD
            if tld in SUSPICIOUS_TLDS:
                domain_risk_reasons.append(f"Suspicious high-abuse top level domain (.{tld}) observed.")

            # Check multi-level deception (e.g. paypal.com.attacker.com)
            if len(parts) >= 3:
                for brand in BRAND_KEYWORDS:
                    if brand in parts[:-2]:
                        has_typosquatting = True
                        domain_risk_reasons.append(
                            f"Deceptive subdomain hijacking: brand name '{brand}' placed in subdomain of '{hostname}'."
                        )

            # Check IP address as host
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname):
                suspicious_redirects = True
                domain_risk_reasons.append(f"Direct raw IP address URL ({hostname}) bypassing standard DNS.")

        except Exception:
            pass

    if domain_risk_reasons:
        domain_risk_summary = " ".join(domain_risk_reasons)
    elif extracted_urls:
        domain_risk_summary = f"{len(extracted_urls)} URL(s) inspected. No recognized typosquatting or homoglyphs found."
    else:
        domain_risk_summary = "No hyperlinks identified in payload."

    # 5. Threat Score & Verdict Determination
    threat_score = 15  # baseline safe score

    if is_spoofed:
        threat_score += 40
    if urgency_detected:
        threat_score += 25
    if has_typosquatting:
        threat_score += 45
    if suspicious_redirects:
        threat_score += 20
    if len(psychological_triggers) >= 2:
        threat_score += 15

    threat_score = min(max(threat_score, 5), 98)

    # Threshold mapping according to specification
    if threat_score >= 70:
        verdict = "PHISHING"
    elif threat_score >= 40:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    # 6. Generate Playbook via Fallback
    sender_analysis = SenderCheck(
        sender_email=sender_email,
        display_name_match=display_name_match,
        domain_reputation_notes=domain_reputation_notes,
        is_spoofed=is_spoofed
    )
    content_analysis = ContentCheck(
        urgency_tactics_detected=urgency_detected,
        psychological_triggers=psychological_triggers,
        sentiment_analysis=sentiment_analysis
    )
    url_analysis = URLCheck(
        extracted_urls=extracted_urls,
        has_typosquatting=has_typosquatting,
        suspicious_redirects=suspicious_redirects,
        domain_risk_summary=domain_risk_summary
    )

    playbook = generate_rule_based_fallback(
        verdict=verdict,
        threat_score=threat_score,
        sender_email=sender_email,
        is_spoofed=is_spoofed,
        urgency_detected=urgency_detected,
        psychological_triggers=psychological_triggers,
        flagged_urls=extracted_urls
    )

    return ThreatAnalysisResponse(
        verdict=verdict,
        threat_score=threat_score,
        sender_analysis=sender_analysis,
        content_analysis=content_analysis,
        url_analysis=url_analysis,
        playbook=playbook
    )


async def run_threat_analysis(payload: AnalyzePayload) -> ThreatAnalysisResponse:
    """
    Executes single-pass threat analysis using Gemini 2.5 Flash with structured output.
    Falls back gracefully to heuristic analysis if the Gemini API is unavailable.
    """
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key or api_key == "your_gemini_api_key_here":
        return analyze_heuristics_fallback(payload)

    try:
        from google import genai
        from google.genai import types

        client = genai.Client(api_key=api_key)

        prompt = f"""
You are an Autonomous Tier-3 SOC Security Analyst for APERTURE, a real-time AI-driven Threat Intelligence and Incident Remediation system.
Perform a single-pass, comprehensive threat analysis and incident containment triage on the following input.

INPUT PAYLOAD:
- Mode: {payload.mode}
- Sender Header: {payload.sender or 'N/A'}
- Message Body: {payload.message or 'N/A'}
- Target URL: {payload.url or 'N/A'}

ANALYSIS REQUIREMENTS:

1. Phase 1 - Sender & Identity Guard:
   - Dissect the sender string. Check for display-name spoofing (e.g., display name "Microsoft Support" with a consumer webmail address like @gmail.com or an lookalike domain).
   - Populate `sender_analysis`: `sender_email` (string), `display_name_match` (bool), `domain_reputation_notes` (string), and `is_spoofed` (bool).

2. Phase 2 - Behavioral & Psychological Context:
   - Identify psychological manipulation: artificial urgency, threats of account suspension/closure, legal/financial fear, credential harvesting cues.
   - Populate `content_analysis`: `urgency_tactics_detected` (bool), `psychological_triggers` (list of strings), and `sentiment_analysis` (string).

3. Phase 3 - URL & Typosquatting Inspection:
   - Extract hyperlinks (from message or bare URL). Identify typosquatting, character homoglyphs (e.g., micros0ft.com, paypa1.com), deceptive subdomains (e.g., login.microsoft.com.attacker.biz), or raw IP destinations.
   - Populate `url_analysis`: `extracted_urls` (list of strings), `has_typosquatting` (bool), `suspicious_redirects` (bool), and `domain_risk_summary` (string).

4. Scoring & Verdict Consistency (MANDATORY):
   - Threat Score: 0 to 100.
   - Verdict Mapping:
     * Threat Score >= 70: strictly "PHISHING"
     * Threat Score 40 to 69: strictly "SUSPICIOUS"
     * Threat Score < 40: strictly "SAFE"

5. Incident Playbook Generation:
   - Generate `playbook`:
     * `immediate_actions`: 3 to 5 prioritized, concrete containment steps (e.g., invalidate active SSO sessions, revoke OAuth tokens, audit mailbox auto-forward rules, DNS sinkholing).
     * `admin_alert_draft`: Professional Markdown SOC escalation briefing ready for one-click copy, including Incident ID, timestamp, target domain, originating sender, threat score, attack vectors, and containment actions.
     * `severity_level`: Strictly match the score thresholds:
       - Score >= 90: "CRITICAL"
       - Score >= 70: "HIGH"
       - Score >= 40: "MEDIUM"
       - Score < 40: "LOW"
"""

        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=ThreatAnalysisResponse,
                temperature=0.1
            ),
        )

        data = json.loads(response.text)
        result = ThreatAnalysisResponse(**data)

        # Enforce consistency safeguards on verdict & severity
        if result.threat_score >= 70:
            result.verdict = "PHISHING"
        elif result.threat_score >= 40:
            result.verdict = "SUSPICIOUS"
        else:
            result.verdict = "SAFE"

        result.playbook.severity_level = calculate_severity(result.threat_score)
        return result

    except Exception:
        # Seamlessly fallback without throwing 500
        return analyze_heuristics_fallback(payload)
