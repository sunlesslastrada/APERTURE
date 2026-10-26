from pydantic import BaseModel, Field
from typing import List, Optional

# --- Incoming Analysis Payload ---

class AnalyzePayload(BaseModel):
    mode: str = "message"  # "message" or "url"
    sender: Optional[str] = ""
    message: Optional[str] = ""
    url: Optional[str] = ""


# --- Feature 1 Diagnostic Contracts ---

class SenderCheck(BaseModel):
    sender_email: str
    display_name_match: bool
    domain_reputation_notes: str
    is_spoofed: bool

class ContentCheck(BaseModel):
    urgency_tactics_detected: bool
    psychological_triggers: List[str]
    sentiment_analysis: str

class URLCheck(BaseModel):
    extracted_urls: List[str]
    has_typosquatting: bool
    suspicious_redirects: bool
    domain_risk_summary: str


# --- Feature 2: Incident Playbook Contracts ---

class IncidentPlaybook(BaseModel):
    immediate_actions: List[str] = Field(
        ..., 
        description="Prioritized, vector-specific mitigation steps (e.g., invalidate active sessions, revoke OAuth tokens, audit mailbox auto-forward rules)"
    )
    admin_alert_draft: str = Field(
        ..., 
        description="Pre-composed, professional SOC/IT escalation briefing in markdown format with technical IOCs ready for one-click copy"
    )
    severity_level: str = Field(
        ..., 
        description="Severity level: LOW, MEDIUM, HIGH, or CRITICAL"
    )


# --- Full Integrated Response Contract ---

class ThreatAnalysisResponse(BaseModel):
    verdict: str         # SAFE, SUSPICIOUS, PHISHING
    threat_score: int    # 0 - 100
    sender_analysis: SenderCheck
    content_analysis: ContentCheck
    url_analysis: URLCheck
    playbook: IncidentPlaybook


# --- Standalone Testing Input Schema for Feature 2 ---

class PlaybookRequest(BaseModel):
    verdict: str = Field(default="PHISHING", description="SAFE, SUSPICIOUS, or PHISHING")
    threat_score: int = Field(default=85, ge=0, le=100)
    sender_email: str = Field(default="support@paypa1-security.com")
    is_spoofed: bool = Field(default=True)
    urgency_detected: bool = Field(default=True)
    psychological_triggers: List[str] = Field(default_factory=lambda: ["Urgency", "Account Suspension", "Financial Fear"])
    flagged_urls: List[str] = Field(default_factory=lambda: ["https://paypa1-security.com/verify-login"])
    raw_snippet: Optional[str] = Field(default="Your account will be suspended in 24 hours. Click here to verify.")
