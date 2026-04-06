"""
AI endpoints injected into main FastAPI app.
Add these routes to main.py at the bottom before uvicorn block.
This file is imported by main.py.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from database import get_db, Bucket, Scan, SensitiveFinding
from ai_engine import (
    check_ollama_status, analyze_findings, suggest_scan_config,
    chat_assistant, generate_report_narrative
)

ai_router = APIRouter(prefix="/api/ai", tags=["AI"])


@ai_router.get("/status")
async def ai_status():
    """Check if Ollama is running and available."""
    return await check_ollama_status()


@ai_router.post("/analyze/{bucket_id}")
async def analyze_bucket(bucket_id: int, db: Session = Depends(get_db)):
    """Run AI analysis on a specific bucket's findings and permissions."""
    bucket = db.query(Bucket).filter_by(id=bucket_id).first()
    if not bucket:
        raise HTTPException(404, "Bucket not found")

    findings = db.query(SensitiveFinding).filter_by(bucket_id=bucket_id).all()
    findings_list = [
        {"pattern_name": f.pattern_name, "severity": f.severity, "match_preview": f.match_preview}
        for f in findings
    ]
    permissions = {
        "can_list": bucket.can_list,
        "can_read": bucket.can_read,
        "can_write": bucket.can_write,
        "can_delete": bucket.can_delete,
    }
    result = await analyze_findings(bucket.name, findings_list, permissions)
    return result


@ai_router.post("/suggest-config")
async def suggest_config(payload: dict):
    """Suggest scan configuration from natural language target description."""
    desc = payload.get("description", "")
    if not desc:
        raise HTTPException(400, "description is required")
    return await suggest_scan_config(desc)


@ai_router.post("/chat")
async def chat(payload: dict):
    """General AI security assistant chat."""
    message = payload.get("message", "")
    context = payload.get("context", {})
    if not message:
        raise HTTPException(400, "message is required")
    response = await chat_assistant(message, context)
    return {"response": response}


@ai_router.post("/report/{scan_id}")
async def generate_report(scan_id: int, db: Session = Depends(get_db)):
    """Generate AI executive summary narrative for a scan."""
    scan = db.query(Scan).filter_by(id=scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")

    scan_data = {
        "name": scan.name,
        "buckets_found": len(scan.buckets),
        "critical": sum(1 for b in scan.buckets if b.risk_level == "critical"),
        "high": sum(1 for b in scan.buckets if b.risk_level == "high"),
        "total_sensitive": sum(b.sensitive_count for b in scan.buckets),
        "total_vulnerable": sum(1 for b in scan.buckets if b.can_read or b.can_write or b.can_delete),
    }
    narrative = await generate_report_narrative(scan_data)
    return {"narrative": narrative, "scan": scan_data}
