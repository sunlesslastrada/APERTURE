from schemas import (
    ThreatAnalysisResponse,
    SenderCheck,
    ContentCheck,
    URLCheck,
    IncidentPlaybook
)
from playbook_service import generate_playbook_with_gemini


def build_full_threat_response(
    verdict: str,
    threat_score: int,
    sender_analysis: SenderCheck,
    content_analysis: ContentCheck,
    url_analysis: URLCheck,
    raw_snippet: str = ""
) -> ThreatAnalysisResponse:
    """
    Integration Hook for Feature 1 Teammate:
    Call this inside POST /api/analyze to automatically generate and
    attach Feature 2's Incident Playbook to the primary response.
    """
    # Generate Feature 2 Incident Playbook
    playbook: IncidentPlaybook = generate_playbook_with_gemini(
        verdict=verdict,
        threat_score=threat_score,
        sender_email=sender_analysis.sender_email,
        is_spoofed=sender_analysis.is_spoofed,
        urgency_detected=content_analysis.urgency_tactics_detected,
        psychological_triggers=content_analysis.psychological_triggers,
        flagged_urls=url_analysis.extracted_urls,
        raw_snippet=raw_snippet
    )

    # Return the unified contract expected by the React frontend
    return ThreatAnalysisResponse(
        verdict=verdict,
        threat_score=threat_score,
        sender_analysis=sender_analysis,
        content_analysis=content_analysis,
        url_analysis=url_analysis,
        playbook=playbook
    )