import os
from fastapi import APIRouter, HTTPException
from schemas import IncidentPlaybook, PlaybookRequest
from playbook_service import generate_playbook_with_gemini

router = APIRouter(prefix="/api/incident", tags=["Incident Responder"])


@router.post("/playbook", response_model=IncidentPlaybook)
async def create_incident_playbook(request: PlaybookRequest):
    """
    Generate an actionable incident containment checklist & SOC escalation report.
    Powered by Gemini 2.5 Flash with automatic fallback.
    """
    try:
        playbook = generate_playbook_with_gemini(
            verdict=request.verdict,
            threat_score=request.threat_score,
            sender_email=request.sender_email,
            is_spoofed=request.is_spoofed,
            urgency_detected=request.urgency_detected,
            psychological_triggers=request.psychological_triggers,
            flagged_urls=request.flagged_urls,
            raw_snippet=request.raw_snippet,
            threat_archetype=request.threat_archetype
        )
        return playbook
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate playbook: {str(e)}")


@router.get("/health")
async def health_check():
    """Check service health and whether Gemini AI is connected or in fallback mode."""
    api_key = os.getenv("GEMINI_API_KEY")
    is_live = bool(api_key and api_key != "your_gemini_api_key_here")
    return {
        "status": "online",
        "service": "APERTURE - Incident Responder (Feature 2)",
        "ai_engine": "Gemini 2.5 Flash (Live)" if is_live else "Rule-Based Fallback Engine (Demo Safe)",
        "version": "1.0.0"
    }
