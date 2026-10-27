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
    IncidentPlaybook,
    ScreenshotExtractionResponse
)
from playbook_service import (
    generate_rule_based_fallback,
    calculate_severity,
    infer_threat_archetype,
    get_mitre_mapping
)

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
    "microsoft", "paypal", "apple", "google", "amazon", "netflix", "bank", "chase", "wells", "support", "security", "docusign", "dropbox", "adp"
]
URGENCY_KEYWORDS = [
    "urgent", "immediately", "immediate", "suspended", "suspension", "suspend", "action required",
    "terminate", "unauthorized", "unusual activity", "locked", "expire", "critical", "compromised",
    "verify your account", "verify identity", "failure to act", "within 24 hours", "within 30 minutes",
    "legal action", "final notice", "payroll hold", "law enforcement"
]
CREDENTIAL_KEYWORDS = [
    "login", "sign in", "password", "credential", "sso", "session", "reset password", "verify identity", "update payment"
]
FINANCIAL_KEYWORDS = [
    "wire", "invoice", "payment", "gift card", "bank transfer", "payroll", "ach", "remittance", "swift", "direct deposit", "w-2"
]
MALWARE_KEYWORDS = [
    "attachment", "macro", "download", "payload", ".exe", ".iso", ".zip", ".vbs", ".scr", "invoice.pdf.exe"
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
    Calibrated with NIST SP 800-61 and MITRE ATT&CK risk scoring benchmarks.
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

    # 2. Sender Analysis & Calibration (+25 to +35 pts for Direct Impersonation / Free Webmail)
    display_name, sender_email = extract_sender_info(raw_sender)
    if not sender_email and mode == "message":
        sender_email = "unknown-sender@unspecified.domain"
    elif not sender_email and mode == "url":
        sender_email = "direct-url-submission@aperture.local"

    sender_domain = sender_email.split("@")[-1].lower() if "@" in sender_email else ""
    is_spoofed = False
    display_name_match = True
    domain_reputation_notes = ""
    sender_weight = 0

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
            sender_weight = 35  # High-risk consumer webmail impersonating enterprise brand
            domain_reputation_notes = (
                f"Direct Sender Impersonation (MITRE T1656): Display name claims enterprise entity '{display_name}', "
                f"but originates from public consumer webmail provider (@{sender_domain})."
            )
        elif impersonated_brand not in sender_domain:
            is_spoofed = True
            display_name_match = False
            sender_weight = 30
            domain_reputation_notes = (
                f"Organizational Domain Mismatch: Sender display name '{display_name}' does not align with domain '{sender_domain}'."
            )
        else:
            domain_reputation_notes = f"Sender domain aligns with reported entity '{display_name}'."
    else:
        if sender_domain in KNOWN_FREE_MAIL_DOMAINS:
            domain_reputation_notes = f"Consumer webmail domain (@{sender_domain}) evaluated."
            sender_weight = 10
        elif sender_domain:
            domain_reputation_notes = f"Domain '{sender_domain}' evaluated. No overt identity spoofing detected."
        else:
            domain_reputation_notes = "No sender email header provided for deep identity verification."

    # 3. Content Analysis & Psychological Vectors (+15 to +25 pts for Urgency/Lockout)
    urgency_detected = False
    psychological_triggers: List[str] = []
    text_to_check = f"{raw_message} {raw_sender}".lower()
    content_weight = 0

    for kw in URGENCY_KEYWORDS:
        if kw in text_to_check:
            urgency_detected = True
            if "suspend" in kw or "lock" in kw or "terminate" in kw:
                if "Threat of account suspension" not in psychological_triggers:
                    psychological_triggers.append("Threat of account suspension")
            elif "24 hours" in kw or "30 minutes" in kw or "immediately" in kw or "urgent" in kw:
                if "Artificial urgency" not in psychological_triggers:
                    psychological_triggers.append("Artificial urgency")
            elif "legal" in kw or "law enforcement" in kw or "final notice" in kw:
                if "Legal extortion / intimidation" not in psychological_triggers:
                    psychological_triggers.append("Legal extortion / intimidation")
            elif "verify" in kw or "activity" in kw or "compromised" in kw:
                if "Fear of unauthorized access" not in psychological_triggers:
                    psychological_triggers.append("Fear of unauthorized access")

    if urgency_detected:
        content_weight += 20
        if len(psychological_triggers) >= 2:
            content_weight += 5

    # Check for Credential Harvesting intent (+30 to +40 pts)
    has_credential_intent = any(cw in text_to_check for cw in CREDENTIAL_KEYWORDS)
    if has_credential_intent and (extracted_urls or is_spoofed or urgency_detected):
        content_weight += 30

    # Check for Financial Fraud intent (+25 to +35 pts)
    has_financial_intent = any(fw in text_to_check for fw in FINANCIAL_KEYWORDS)
    if has_financial_intent:
        content_weight += 25

    # Check for Malware intent (+35 to +45 pts)
    has_malware_intent = any(mw in text_to_check for mw in MALWARE_KEYWORDS)
    if has_malware_intent:
        content_weight += 35

    if urgency_detected or has_credential_intent or has_financial_intent:
        sentiment_analysis = (
            "Manipulative, high-urgency behavioral extortion vectors identified designed to induce cognitive "
            "overload and force non-standard authorization outside approved channels."
        )
    else:
        sentiment_analysis = (
            "Standard business communication register. No aggressive extortion, coercive urgency, or psychological manipulation detected."
        )

    # 4. URL & Typosquatting Analysis (+30 to +40 pts for Homoglyphs/Lookalikes)
    has_typosquatting = False
    suspicious_redirects = False
    domain_risk_reasons: List[str] = []
    url_weight = 0

    for url_item in extracted_urls:
        try:
            parsed = urllib.parse.urlparse(url_item if "://" in url_item else f"http://{url_item}")
            hostname = parsed.hostname or ""
            parts = hostname.lower().split(".")
            tld = parts[-1] if len(parts) > 1 else ""

            # Homoglyphs / Typosquatting
            if any(char in hostname for char in ["0", "1", "vv"]):
                if any(brand in hostname.replace("0", "o").replace("1", "l") for brand in BRAND_KEYWORDS):
                    has_typosquatting = True
                    url_weight += 35
                    domain_risk_reasons.append(f"High-risk homoglyph/typosquatting identified in hostname '{hostname}'.")

            # Suspicious high-abuse TLDs
            if tld in SUSPICIOUS_TLDS:
                url_weight += 25
                domain_risk_reasons.append(f"Destination resolves through high-abuse top-level domain (.{tld}).")

            # Deceptive multi-level subdomain stacking (e.g. paypal.com.account-verify.top)
            if len(parts) >= 3:
                for brand in BRAND_KEYWORDS:
                    if brand in parts[:-2]:
                        has_typosquatting = True
                        url_weight += 35
                        domain_risk_reasons.append(
                            f"Deceptive subdomain stacking: brand '{brand}' positioned in subdomains of '{hostname}'."
                        )

            # Raw IP Address destination
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname):
                suspicious_redirects = True
                url_weight += 25
                domain_risk_reasons.append(f"Destination hostname is a bare IPv4 address ({hostname}) bypassing corporate DNS controls.")

        except Exception:
            pass

    if domain_risk_reasons:
        domain_risk_summary = " ".join(domain_risk_reasons)
    elif extracted_urls:
        domain_risk_summary = f"{len(extracted_urls)} hyperlink(s) inspected. No malicious homoglyphs, deceptive subdomains, or blacklisted TLDs detected."
    else:
        domain_risk_summary = "No hyperlinks identified in payload."

    # 5. Composite Threat Score Calibration
    raw_score = 10 + sender_weight + content_weight + url_weight
    threat_score = min(max(raw_score, 5), 98)

    # Clean zero-risk check
    if not is_spoofed and not urgency_detected and not has_typosquatting and not has_credential_intent and not has_financial_intent:
        threat_score = min(threat_score, 20)

    # Threshold mapping according to specification
    if threat_score >= 70:
        verdict = "PHISHING"
    elif threat_score >= 40:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    # Infer threat archetype
    archetype = infer_threat_archetype(
        snippet=raw_message or raw_url,
        sender=sender_email,
        urls=extracted_urls,
        triggers=psychological_triggers,
        threat_score=threat_score
    )

    # 6. Generate Context-Aware Playbook via Fallback
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
        flagged_urls=extracted_urls,
        raw_snippet=raw_message or raw_url,
        threat_archetype=archetype
    )

    return ThreatAnalysisResponse(
        verdict=verdict,
        threat_score=threat_score,
        threat_archetype=archetype,
        sender_analysis=sender_analysis,
        content_analysis=content_analysis,
        url_analysis=url_analysis,
        playbook=playbook
    )


async def run_threat_analysis(payload: AnalyzePayload) -> ThreatAnalysisResponse:
    """
    Executes single-pass threat analysis using Gemini 2.5 Flash with structured output.
    Calibrated with NIST SP 800-61 and MITRE ATT&CK enterprise taxonomies.
    Falls back gracefully to deterministic analysis if the Gemini API is unavailable.
    """
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key or api_key == "your_gemini_api_key_here":
        return analyze_heuristics_fallback(payload)

    try:
        from google import genai
        from google.genai import types

        client = genai.Client(api_key=api_key)

        prompt = f"""
You are an Autonomous Tier-3 SOC Security Analyst for APERTURE, an enterprise-grade Threat Intelligence and Dynamic Incident Remediation platform.
Analyze the following ingress payload in a single-pass inference cycle.

CALIBRATION & INDUSTRY BENCHMARKS:
1. Threat Vector Classification (threat_archetype): Strictly classify into ONE archetype:
   - "CREDENTIAL_HARVESTING": Fake login portals, password resets, session verification, OAuth consent abuse.
   - "FINANCIAL_FRAUD_BEC": Invoice alteration, wire transfer requests, gift card scams, executive impersonation.
   - "MALWARE_DROPPER": Suspicious file download links, macro attachments, disguised payloads.
   - "BRAND_TYPOSQUATTING": Character homoglyphs, lookalike hostnames, deceptive subdomain stacking.
   - "BENIGN_LEGITIMATE": Authentic enterprise notices, authenticated transactional communications.

2. Risk Weight Calibration (threat_score: 0 to 100):
   - Direct Sender Impersonation / Free Webmail for Enterprise Claims: +25 to +35 pts
   - Homoglyph / Punycode / Brand Typosquatting in URL: +30 to +40 pts
   - High-Urgency Psychological Triggers (Account lockout, legal threat): +15 to +25 pts
   - Credential Harvesting Intent (Password/SSO prompt link): +30 to +40 pts
   - Financial Fraud / Wire Request: +25 to +35 pts
   - Malware / Dangerous Payload: +35 to +45 pts

3. Verdict & Severity Thresholds (MANDATORY):
   - Threat Score >= 70: strictly "PHISHING"
   - Threat Score 40 to 69: strictly "SUSPICIOUS"
   - Threat Score < 40: strictly "SAFE"
   - Severity Level: Score >= 90: "CRITICAL", Score >= 70: "HIGH", Score >= 40: "MEDIUM", Score < 40: "LOW".

4. Taxonomic Framework Alignment:
   - Reference MITRE ATT&CK techniques (e.g. T1566.002 Spearphishing Link, T1566.001 Spearphishing Attachment, T1528 Steal Application Access Token, T1656 Impersonation).
   - Structure incident phases following the NIST SP 800-61 lifecycle (Detection & Analysis -> Containment -> Eradication -> Recovery).

5. Production-Grade SOC Markdown Escalation Memo (playbook.admin_alert_draft):
   Must follow this exact structure:
   ### 🚨 APERTURE TIER-3 INCIDENT ESCALATION BRIEFING
   - **Incident Category**: [Detected Archetype]
   - **Assigned Severity**: [LOW | MEDIUM | HIGH | CRITICAL]
   - **MITRE ATT&CK Mapping**: [e.g., T1566.002 - Spearphishing Link]
   - **NIST SP 800-61 Lifecycle Phase**: Containment, Eradication & Recovery
   - **Estimated MTTC Target**: [e.g., < 15 Minutes (Immediate SecOps Tier-3 Escalation)]
   - **Sender & Infrastructure**: [Sender address, display name match, reputation notes]
   - **Attack Surface / IoCs**: [Extracted target domains, lookalike homoglyphs, or links]
   - **Social Engineering Vectors**: [Detected psychological triggers]

   #### ⚡ Immediate Containment Command (NIST Containment Phase):
   > [Single most urgent administrative action for SecOps/IT admins]

   #### 🛠️ Operational Remediation Steps:
   1. [Step 1]
   2. [Step 2]
   3. [Step 3]

6. Context-Specific Immediate Actions (playbook.immediate_actions):
   Provide 3 to 5 concrete containment actions tailored directly to the detected archetype (e.g., tenant session invalidation for credentials, AP wire hold for BEC, EDR host isolation for malware, DNS sinkhole for typosquats).

INPUT PAYLOAD:
- Mode: {payload.mode}
- Sender Header: {payload.sender or 'N/A'}
- Message Body: {payload.message or 'N/A'}
- Target URL: {payload.url or 'N/A'}
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
        result.playbook.threat_archetype = result.threat_archetype
        return result

    except Exception as exc:
        print(f"[APERTURE Engine] External AI inference exception: {exc}. Switching to deterministic fallback.")
        return analyze_heuristics_fallback(payload)


async def extract_from_screenshot(image_bytes: bytes, mime_type: str = "image/png") -> ScreenshotExtractionResponse:
    """
    Multimodal vision extraction using Gemini 2.5 Flash.
    Extracts sender, message body, links, and detects missing critical telemetry from uploaded screenshot.
    """
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key or api_key == "your_gemini_api_key_here":
        return ScreenshotExtractionResponse(
            sender="",
            message="[OCR Fallback: Gemini API key not detected. Enter communication body manually or configure GEMINI_API_KEY.]",
            detected_urls=[],
            missing_critical_info=["Gemini API key is required for automated OCR vision parsing."]
        )

    try:
        from google import genai
        from google.genai import types

        client = genai.Client(api_key=api_key)

        prompt = """
Extract the cybersecurity analysis fields from this email/message screenshot:
1. sender: The sender's email or display name header (if clearly visible).
2. message: The main body text, alerts, or core message.
3. detected_urls: Any links or domains visible in the screenshot.
4. missing_critical_info: A list of any missing critical elements (e.g., if sender header is cropped out, or body is incomplete).
"""
        part = types.Part.from_bytes(data=image_bytes, mime_type=mime_type)

        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=[part, prompt],
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=ScreenshotExtractionResponse,
                temperature=0.1
            ),
        )

        data = json.loads(response.text)
        return ScreenshotExtractionResponse(**data)
    except Exception as exc:
        print(f"[APERTURE Vision] Screenshot extraction error: {exc}")
        return ScreenshotExtractionResponse(
            sender="",
            message="",
            detected_urls=[],
            missing_critical_info=[f"Extraction failed: {str(exc)}. Please enter details manually."]
        )
