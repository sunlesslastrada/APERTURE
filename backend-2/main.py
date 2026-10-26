import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from incident_router import router as incident_router

app = FastAPI(
    title="TrustLens AI — Incident Responder API",
    description="Backend service for Feature 2: Automated Incident Responder & Triage Deck. Developed by Aditya Tiwari, Aditya Raj, and Aditya Rawat.",
    version="1.0.0"
)

# Enable CORS for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount Feature 2 endpoints
app.include_router(incident_router)


@app.get("/")
def root():
    return {
        "project": "TrustLens AI",
        "module": "Feature 2 - Automated Incident Responder & Triage Deck",
        "docs_url": "/docs",
        "status": "operational"
    }


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)