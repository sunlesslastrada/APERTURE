import re
import uvicorn
from typing import Optional
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from schemas import AnalyzePayload, ThreatAnalysisResponse, ScreenshotExtractionResponse
from incident_router import router as incident_router
from feature1_service import (
    run_threat_analysis,
    analyze_heuristics_fallback,
    extract_from_screenshot
)

app = FastAPI(
    title="APERTURE — Threat Intelligence & Incident Remediation API",
    description="Unified enterprise API gateway for APERTURE.AI. Developed by Aditya Tiwari, Aditya Raj, and Aditya Rawat.",
    version="1.0.0"
)

# CORS Configuration
origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount Feature 2 incident router
app.include_router(incident_router)


def sanitize_input(text: Optional[str]) -> str:
    """Strip dangerous unprintable control characters while preserving valid multi-line text."""
    if not text:
        return ""
    # Strip null bytes and non-printable control characters, preserving \n, \r, and \t
    cleaned = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)
    return cleaned.strip()


@app.get("/")
def root():
    return {
        "project": "APERTURE",
        "description": "Real-time AI-driven Threat Intelligence and Incident Remediation API",
        "frameworks": ["NIST SP 800-61", "MITRE ATT&CK"],
        "docs_url": "/docs",
        "status": "operational"
    }


@app.post("/api/analyze", response_model=ThreatAnalysisResponse)
async def analyze_threat(payload: AnalyzePayload):
    """
    Primary Threat Intelligence & Remediation Endpoint:
    Performs multi-vector single-pass analysis across Sender, Content, and URL vectors,
    concurrently generating an archetype-specific Incident Playbook.
    """
    try:
        sanitized = AnalyzePayload(
            mode=payload.mode.strip().lower() if payload.mode else "message",
            sender=sanitize_input(payload.sender),
            message=sanitize_input(payload.message),
            url=sanitize_input(payload.url)
        )
        return await run_threat_analysis(sanitized)
    except Exception as exc:
        print(f"[APERTURE Gateway] Exception encountered: {exc}. Providing resilient fallback.")
        return analyze_heuristics_fallback(payload)


@app.post("/api/extract-screenshot", response_model=ScreenshotExtractionResponse)
async def extract_screenshot_telemetry(file: UploadFile = File(...)):
    """
    Multimodal Vision Ingestion Endpoint:
    Accepts an email/SMS/alert screenshot and extracts sender, message text,
    visible URLs, and notes any missing critical telemetry.
    """
    try:
        content_type = file.content_type or "image/png"
        image_bytes = await file.read()
        if not image_bytes:
            raise HTTPException(status_code=400, detail="Empty image file received.")
        return await extract_from_screenshot(image_bytes, mime_type=content_type)
    except HTTPException:
        raise
    except Exception as exc:
        print(f"[APERTURE Gateway] Screenshot processing error: {exc}")
        return ScreenshotExtractionResponse(
            sender="",
            message="",
            detected_urls=[],
            missing_critical_info=[f"Extraction error: {str(exc)}"]
        )


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
