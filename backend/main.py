import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from schemas import AnalyzePayload, ThreatAnalysisResponse
from incident_router import router as incident_router
from feature1_service import run_threat_analysis

app = FastAPI(
    title="APERTURE — Threat Intelligence & Incident Remediation API",
    description="Unified API gateway for APERTURE.AI. Developed by Aditya Tiwari, Aditya Raj, and Aditya Rawat.",
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


@app.get("/")
def root():
    return {
        "project": "APERTURE",
        "description": "Real-time AI-driven Threat Intelligence and Incident Remediation API",
        "docs_url": "/docs",
        "status": "operational"
    }


@app.post("/api/analyze", response_model=ThreatAnalysisResponse)
async def analyze_threat(payload: AnalyzePayload):
    """
    Primary Threat Intelligence & Remediation Endpoint:
    Single-pass multi-vector analysis across Sender, Content, and URL vectors,
    concurrently generating an interactive Incident Playbook.
    """
    return await run_threat_analysis(payload)


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
