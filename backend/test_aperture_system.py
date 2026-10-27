import io
import os
import sys

# Ensure immediate unbuffered output
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(line_buffering=True)

from dotenv import load_dotenv

# Ensure backend directory is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
load_dotenv()

from schemas import (
    AnalyzePayload,
    ThreatAnalysisResponse,
    SenderCheck,
    ContentCheck,
    URLCheck,
    IncidentPlaybook,
    ScreenshotExtractionResponse,
    PlaybookRequest,
)
from feature1_service import (
    get_candidate_models,
    analyze_heuristics_fallback,
    run_threat_analysis,
    extract_from_screenshot,
)
from playbook_service import (
    generate_rule_based_fallback,
    generate_playbook_with_gemini,
)
from main import app, sanitize_input
from fastapi.testclient import TestClient


def run_all_tests():
    print("=" * 60)
    print("APERTURE SYSTEM VERIFICATION: RUNNING ALL ELEMENT TESTS")
    print("=" * 60)

    passed_count = 0
    total_count = 0

    def assert_test(name, condition, details=""):
        nonlocal passed_count, total_count
        total_count += 1
        if condition:
            passed_count += 1
            print(f" [PASS] {name}")
        else:
            print(f" [FAIL] {name}: {details}")

    # 1. Schemas Validation
    print("\n--- 1. Data Contracts & Schemas Validation ---")
    try:
        payload = AnalyzePayload(mode="message", sender="admin@bank.com", message="Urgent: verify password", url="http://fake.com")
        assert_test("AnalyzePayload instantiation", payload.mode == "message" and payload.sender == "admin@bank.com")

        sender_chk = SenderCheck(
            sender_email="admin@bank.com",
            display_name_match=False,
            domain_reputation_notes="Sender mismatch",
            is_spoofed=True
        )
        content_chk = ContentCheck(
            urgency_tactics_detected=True,
            psychological_triggers=["fear"],
            sentiment_analysis="Coercive urgency detected"
        )
        url_chk = URLCheck(
            extracted_urls=["http://fake.com"],
            has_typosquatting=True,
            suspicious_redirects=False,
            domain_risk_summary="Suspicious domain"
        )
        playbook = IncidentPlaybook(
            severity_level="CRITICAL",
            threat_archetype="CREDENTIAL_HARVESTING",
            immediate_actions=["Revoke credentials", "Block sender IP"],
            admin_alert_draft="### 🚨 APERTURE TIER-3 INCIDENT ESCALATION BRIEFING\n- Assigned Severity: CRITICAL"
        )
        resp = ThreatAnalysisResponse(
            verdict="PHISHING",
            threat_score=85,
            threat_archetype="CREDENTIAL_HARVESTING",
            sender_analysis=sender_chk,
            content_analysis=content_chk,
            url_analysis=url_chk,
            playbook=playbook
        )
        assert_test("ThreatAnalysisResponse full contract serialization", resp.threat_score == 85 and resp.verdict == "PHISHING")

        screenshot_resp = ScreenshotExtractionResponse(
            sender="service@paypal.notice.com",
            message="Your account will be suspended within 24 hours.",
            detected_urls=["https://paypa1-update.com/login"],
            missing_critical_info=[]
        )
        assert_test("ScreenshotExtractionResponse serialization", len(screenshot_resp.detected_urls) == 1)

    except Exception as e:
        assert_test("Schemas instantiation", False, str(e))

    # 2. Candidate Models Selection
    print("\n--- 2. Model Cascade & Configuration ---")
    candidates = get_candidate_models()
    assert_test("Primary model is gemini-3.8-flash", candidates[0] == "gemini-3.8-flash" or candidates[0] == os.getenv("GEMINI_MODEL", "gemini-3.8-flash"), f"Got {candidates}")
    assert_test("Candidate fallback cascade contains alternatives", len(candidates) >= 2, f"Got {candidates}")

    # 3. Input Sanitization
    print("\n--- 3. Input Sanitization ---")
    dirty_text = "Hello\x00World!\x08 This is a \ntest \t with non-printables \x1f preserved."
    cleaned = sanitize_input(dirty_text)
    assert_test("Null bytes & control characters stripped", "\x00" not in cleaned and "\x08" not in cleaned and "\x1f" not in cleaned)
    assert_test("Newlines and tabs preserved", "\n" in cleaned and "\t" in cleaned)

    # 4. Deterministic Heuristics Engine (Fallback)
    print("\n--- 4. Feature 1 Deterministic Heuristics Fallback ---")
    # Case A: Credential Harvesting with spoofed sender
    payload_phish = AnalyzePayload(
        mode="message",
        sender="security@micro-soft-support.com",
        message="Urgent: Your Microsoft 365 session has expired! Click here to update your credentials immediately or your mailbox will be terminated within 2 hours: http://login-microsoft-auth.com",
        url="http://login-microsoft-auth.com"
    )
    result_phish = analyze_heuristics_fallback(payload_phish)
    assert_test("Phishing payload detected as PHISHING", result_phish.verdict == "PHISHING", f"Verdict: {result_phish.verdict}, Score: {result_phish.threat_score}")
    assert_test("Threat score calibrated >= 70 for credential harvest", result_phish.threat_score >= 70, f"Score: {result_phish.threat_score}")
    assert_test("Archetype identified as CREDENTIAL_HARVESTING", result_phish.threat_archetype == "CREDENTIAL_HARVESTING", f"Archetype: {result_phish.threat_archetype}")
    assert_test("Playbook generated with NIST SP 800-61 stages", "NIST SP 800-61" in result_phish.playbook.admin_alert_draft)
    assert_test("Playbook generated with MITRE ATT&CK reference", "MITRE ATT&CK" in result_phish.playbook.admin_alert_draft)

    # Case B: Typosquatting / Homoglyph URL mode
    payload_url = AnalyzePayload(
        mode="url",
        sender="",
        message="",
        url="https://paypa1-security-verification.com/login"
    )
    result_url = analyze_heuristics_fallback(payload_url)
    assert_test("Typosquat detected as PHISHING/SUSPICIOUS", result_url.verdict in ["PHISHING", "SUSPICIOUS"], f"Verdict: {result_url.verdict}, Score: {result_url.threat_score}")
    assert_test("URL typosquatting detected flag set", result_url.url_analysis.has_typosquatting, f"Analysis: {result_url.url_analysis}")

    # Case C: Safe message
    payload_safe = AnalyzePayload(
        mode="message",
        sender="newsletter@acme-corp.com",
        message="Here is our monthly team engineering update. Hope everyone has a great week!",
        url="https://acme-corp.com"
    )
    result_safe = analyze_heuristics_fallback(payload_safe)
    assert_test("Safe payload detected as SAFE", result_safe.verdict == "SAFE", f"Verdict: {result_safe.verdict}, Score: {result_safe.threat_score}")

    # 5. Playbook Service Fallbacks
    print("\n--- 5. Feature 2 Playbook Service Fallbacks ---")
    for arch in ["CREDENTIAL_HARVESTING", "FINANCIAL_FRAUD_BEC", "MALWARE_DROPPER", "BRAND_TYPOSQUATTING", "BENIGN_LEGITIMATE"]:
        pb = generate_rule_based_fallback(
            verdict="PHISHING" if arch != "BENIGN_LEGITIMATE" else "SAFE",
            threat_score=88 if arch != "BENIGN_LEGITIMATE" else 15,
            sender_email="test@domain.com",
            is_spoofed=True,
            urgency_detected=True,
            psychological_triggers=["fear", "urgency"],
            flagged_urls=["http://test.com"],
            raw_snippet="Sample test snippet",
            threat_archetype=arch
        )
        assert_test(f"Playbook generated for archetype {arch}", len(pb.immediate_actions) >= 3 and pb.threat_archetype == arch)

    # 6. Live FastAPI API Gateway Endpoints via TestClient
    print("\n--- 6. FastAPI Gateway Endpoints via TestClient ---")
    client = TestClient(app)

    # Endpoint 1: Root / Health Check
    res_root = client.get("/")
    assert_test("GET / returns 200 OK", res_root.status_code == 200)
    assert_test("GET / metadata confirms APERTURE", res_root.json().get("project") == "APERTURE")

    # Endpoint 2: Feature 2 Health
    res_inc_health = client.get("/api/incident/health")
    assert_test("GET /api/incident/health returns 200 OK", res_inc_health.status_code == 200)

    # Endpoint 3: POST /api/incident/playbook
    playbook_req = {
        "verdict": "PHISHING",
        "threat_score": 85,
        "sender_email": "spoof@paypal.com",
        "is_spoofed": True,
        "urgency_detected": True,
        "psychological_triggers": ["account lockout"],
        "flagged_urls": ["http://paypa1-verify.com"],
        "raw_snippet": "Your account will be suspended within 24 hours.",
        "threat_archetype": "CREDENTIAL_HARVESTING"
    }
    res_pb = client.post("/api/incident/playbook", json=playbook_req)
    assert_test("POST /api/incident/playbook returns 200 OK", res_pb.status_code == 200)
    assert_test("POST /api/incident/playbook returns IncidentPlaybook schema", "immediate_actions" in res_pb.json() and "admin_alert_draft" in res_pb.json())

    # Endpoint 4: POST /api/analyze (Message mode)
    print("Testing POST /api/analyze (Live Gemini 3.8 Flash inference)...")
    res_analyze = client.post("/api/analyze", json={
        "mode": "message",
        "sender": "payroll@spoofed-company.com",
        "message": "URGENT: Your direct deposit information failed. Verify credentials here: http://secure-portal.com",
        "url": "http://secure-portal.com"
    })
    assert_test("POST /api/analyze returns 200 OK", res_analyze.status_code == 200)
    data_analyze = res_analyze.json()
    assert_test("POST /api/analyze contains all multi-vector keys", "sender_analysis" in data_analyze and "content_analysis" in data_analyze and "url_analysis" in data_analyze and "playbook" in data_analyze)

    # Endpoint 5: POST /api/analyze (URL mode)
    res_analyze_url = client.post("/api/analyze", json={
        "mode": "url",
        "sender": "",
        "message": "",
        "url": "https://accounts-googIe-security.com"
    })
    assert_test("POST /api/analyze (url mode) returns 200 OK", res_analyze_url.status_code == 200)

    # Endpoint 6: POST /api/extract-screenshot with 1x1 dummy PNG
    # Minimal 1x1 transparent PNG bytes
    dummy_png = (
        b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01'
        b'\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\nIDATx\x9cc\x00\x01'
        b'\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82'
    )
    files = {"file": ("test_screenshot.png", dummy_png, "image/png")}
    res_extract = client.post("/api/extract-screenshot", files=files)
    assert_test("POST /api/extract-screenshot returns 200 OK", res_extract.status_code == 200)
    extract_data = res_extract.json()
    assert_test("POST /api/extract-screenshot returns ScreenshotExtractionResponse schema", "sender" in extract_data and "message" in extract_data and "detected_urls" in extract_data and "missing_critical_info" in extract_data)

    print("\n" + "=" * 60)
    print(f"VERIFICATION SUMMARY: {passed_count}/{total_count} TESTS PASSED")
    print("=" * 60)
    return passed_count == total_count


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
