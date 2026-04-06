"""
S3-Hunter Pro — FastAPI Backend (main.py)
WebSocket hub + REST API for the React dashboard.
"""
import asyncio
import json
import logging
import os
import pathlib
import shutil
import zipfile
import io
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, Optional

import boto3
import aiofiles
from botocore import UNSIGNED
from botocore.config import Config
from botocore.exceptions import ClientError
from fastapi import (
    FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException,
    UploadFile, File, BackgroundTasks, Query
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import (
    init_db, get_db, SessionLocal,
    Scan, Bucket, BucketFile, SensitiveFinding, Wordlist,
)
from scanner import ScanWorker, get_active_scan, register_scan
from report import export_json, export_csv
from ai_routes import ai_router

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger("s3hunter.main")

UPLOAD_DIR = pathlib.Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)

# ── WebSocket connection manager ─────────────────────────────────────────────
class ConnectionManager:
    def __init__(self):
        self.active: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        self.active.remove(ws)

    async def broadcast(self, data: dict):
        dead = []
        for ws in self.active:
            try:
                await ws.send_text(json.dumps(data, default=str))
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.active.remove(ws)


manager = ConnectionManager()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="S3-Hunter Pro API",
    version="1.0.0",
    description="AWS S3 Security Testing Framework",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(ai_router)


# ── Pydantic schemas ──────────────────────────────────────────────────────────
class ScanCreate(BaseModel):
    name: str
    wordlist_id: Optional[int] = None
    direct_payloads: Optional[str] = None
    wordlist_path: Optional[str] = None
    concurrency: int = 50
    prefixes: str = ""
    suffixes: str = ""
    regions: str = "us-east-1"
    anon_mode: bool = True
    aws_key: Optional[str] = None
    aws_secret: Optional[str] = None
    write_test: bool = False
    delete_test: bool = False


# ── WebSocket endpoint ────────────────────────────────────────────────────────
@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await manager.connect(ws)
    try:
        while True:
            data = await ws.receive_text()
            msg = json.loads(data)
            if msg.get("type") == "ping":
                await ws.send_text(json.dumps({"type": "pong"}))
    except WebSocketDisconnect:
        manager.disconnect(ws)


# ── Scan endpoints ────────────────────────────────────────────────────────────
@app.post("/api/scans")
async def create_scan(payload: ScanCreate, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    wl_path = payload.wordlist_path
    wl_name = None
    total_lines = 0

    if payload.direct_payloads:
        lines = [line.strip() for line in payload.direct_payloads.split("\n") if line.strip()]
        wl_name = f"quick-target-{datetime.utcnow().strftime('%H%M%S')}.txt"
        dest_path = UPLOAD_DIR / wl_name
        dest_path.write_text("\n".join(lines))
        wl_path = str(dest_path)
        total_lines = len(lines)
    elif payload.wordlist_id:
        wl = db.query(Wordlist).filter_by(id=payload.wordlist_id).first()
        if not wl:
            raise HTTPException(404, "Wordlist not found")
        wl_path = wl.path
        wl_name = wl.name
        total_lines = wl.line_count

    if wl_path and pathlib.Path(wl_path).exists():
        if not total_lines:
            with open(wl_path, "rb") as f:
                total_lines = sum(1 for _ in f)
        wl_name = wl_name or pathlib.Path(wl_path).name

    scan = Scan(
        name=payload.name,
        wordlist_path=wl_path,
        wordlist_name=wl_name,
        total_lines=total_lines,
        concurrency=payload.concurrency,
        prefixes=payload.prefixes,
        suffixes=payload.suffixes,
        regions=payload.regions,
        anon_mode=payload.anon_mode,
        aws_key=payload.aws_key if not payload.anon_mode else None,
        aws_secret=payload.aws_secret if not payload.anon_mode else None,
        write_test=payload.write_test,
        delete_test=payload.delete_test,
        status="pending",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    worker = ScanWorker(scan.id, manager.broadcast)
    register_scan(worker)
    background_tasks.add_task(worker.run)

    return {"scan_id": scan.id, "status": "started"}


@app.get("/api/scans")
def list_scans(db: Session = Depends(get_db)):
    scans = db.query(Scan).order_by(Scan.created_at.desc()).all()
    return [
        {
            "id": s.id,
            "name": s.name,
            "status": s.status,
            "wordlist_name": s.wordlist_name,
            "total_lines": s.total_lines,
            "checkpoint": s.checkpoint,
            "progress": round(s.checkpoint / max(s.total_lines, 1) * 100, 1),
            "buckets_found": len(s.buckets),
            "created_at": s.created_at.isoformat() if s.created_at else None,
        }
        for s in scans
    ]


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter_by(id=scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")
    return {
        "id": scan.id,
        "name": scan.name,
        "status": scan.status,
        "wordlist_name": scan.wordlist_name,
        "wordlist_path": scan.wordlist_path,
        "total_lines": scan.total_lines,
        "checkpoint": scan.checkpoint,
        "progress": round(scan.checkpoint / max(scan.total_lines, 1) * 100, 1),
        "concurrency": scan.concurrency,
        "regions": scan.regions,
        "anon_mode": scan.anon_mode,
        "write_test": scan.write_test,
        "delete_test": scan.delete_test,
        "created_at": scan.created_at.isoformat() if scan.created_at else None,
        "buckets_found": len(scan.buckets),
    }


@app.post("/api/scans/{scan_id}/pause")
def pause_scan(scan_id: int, db: Session = Depends(get_db)):
    worker = get_active_scan(scan_id)
    if not worker:
        raise HTTPException(404, "No active scan with this ID")
    worker.pause()
    db.query(Scan).filter_by(id=scan_id).update({"status": "paused"})
    db.commit()
    return {"status": "paused"}


@app.post("/api/scans/{scan_id}/resume")
def resume_scan(scan_id: int, db: Session = Depends(get_db)):
    worker = get_active_scan(scan_id)
    if not worker:
        raise HTTPException(404, "No active scan with this ID")
    worker.resume()
    db.query(Scan).filter_by(id=scan_id).update({"status": "running"})
    db.commit()
    return {"status": "resumed"}


@app.post("/api/scans/{scan_id}/stop")
def stop_scan(scan_id: int, db: Session = Depends(get_db)):
    worker = get_active_scan(scan_id)
    if worker:
        worker.stop()
    db.query(Scan).filter_by(id=scan_id).update({"status": "stopped"})
    db.commit()
    return {"status": "stopped"}


@app.delete("/api/scans/{scan_id}")
def delete_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter_by(id=scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")
    db.delete(scan)
    db.commit()
    return {"deleted": scan_id}

@app.post("/api/scans/retest")
async def retest_bucket(payload: dict, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    bucket_name = payload.get("bucket_name")
    if not bucket_name:
        raise HTTPException(400, "bucket_name required")
    scan = Scan(
        name=f"Retest: {bucket_name}",
        wordlist_name="Quick Retest",
        total_lines=1,
        concurrency=1,
        prefixes="",
        suffixes="",
        regions="us-east-1",
        anon_mode=True,
        write_test=True, # AI initiated usually has writes enabled
        delete_test=True,
        status="pending",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    
    wl_path = UPLOAD_DIR / f"retest-{scan.id}.txt"
    wl_path.write_text(bucket_name + "\n")
    scan.wordlist_path = str(wl_path)
    db.commit()

    worker = ScanWorker(scan.id, manager.broadcast)
    register_scan(worker)
    background_tasks.add_task(worker.run)
    return {"scan_id": scan.id, "status": "started", "message": f"Retesting {bucket_name}"}


# ── Bucket endpoints ──────────────────────────────────────────────────────────
@app.get("/api/buckets")
def list_buckets(scan_id: Optional[int] = None, db: Session = Depends(get_db)):
    q = db.query(Bucket)
    if scan_id:
        q = q.filter_by(scan_id=scan_id)
    buckets = q.order_by(Bucket.found_at.desc()).all()
    return [
        {
            "id": b.id,
            "scan_id": b.scan_id,
            "name": b.name,
            "payload_used": b.payload_used,
            "region": b.region,
            "url": b.url,
            "risk_level": b.risk_level,
            "can_list": b.can_list,
            "can_read": b.can_read,
            "can_write": b.can_write,
            "can_delete": b.can_delete,
            "object_count": b.object_count,
            "total_size_bytes": b.total_size_bytes,
            "sensitive_count": b.sensitive_count,
            "is_takeover_candidate": b.is_takeover_candidate,
            "proxy_detected": b.proxy_detected,
            "found_at": b.found_at.isoformat() if b.found_at else None,
        }
        for b in buckets
    ]


@app.get("/api/buckets/{bucket_id}/files")
def get_bucket_files(bucket_id: int, prefix: str = "", db: Session = Depends(get_db)):
    bucket = db.query(Bucket).filter_by(id=bucket_id).first()
    if not bucket:
        raise HTTPException(404, "Bucket not found")
    q = db.query(BucketFile).filter_by(bucket_id=bucket_id)
    files = q.order_by(BucketFile.key).limit(100000).all()
    return {
        "bucket": {"id": bucket.id, "name": bucket.name, "region": bucket.region},
        "files": [
            {
                "key": f.key,
                "size": f.size,
                "last_modified": f.last_modified.isoformat() if f.last_modified else None,
                "content_type": f.content_type,
                "is_sensitive": f.is_sensitive,
                "etag": f.etag,
            }
            for f in files
        ],
    }


@app.get("/api/buckets/{bucket_id}/findings")
def get_bucket_findings(bucket_id: int, db: Session = Depends(get_db)):
    findings = db.query(SensitiveFinding).filter_by(bucket_id=bucket_id).all()
    return [
        {
            "id": f.id,
            "file_key": f.file_key,
            "pattern_name": f.pattern_name,
            "severity": f.severity,
            "match_preview": f.match_preview,
            "found_at": f.found_at.isoformat() if f.found_at else None,
        }
        for f in findings
    ]


@app.get("/api/buckets/{bucket_id}/download")
def download_file(bucket_id: int, key: str, inline: bool = False, db: Session = Depends(get_db)):
    bucket = db.query(Bucket).filter_by(id=bucket_id).first()
    if not bucket:
        raise HTTPException(404, "Bucket not found")
    scan = db.query(Scan).filter_by(id=bucket.scan_id).first()

    try:
        if scan and scan.anon_mode:
            client = boto3.client("s3", config=Config(signature_version=UNSIGNED))
        elif scan and scan.aws_key:
            client = boto3.client("s3", aws_access_key_id=scan.aws_key, aws_secret_access_key=scan.aws_secret)
        else:
            client = boto3.client("s3", config=Config(signature_version=UNSIGNED))

        resp = client.get_object(Bucket=bucket.name, Key=key)
        filename = pathlib.PurePosixPath(key).name
        return StreamingResponse(
            resp["Body"].iter_chunks(chunk_size=8192),
            media_type=resp.get("ContentType", "application/octet-stream"),
            headers={"Content-Disposition": f'{"inline" if inline else "attachment"}; filename="{filename}"'},
        )
    except ClientError as e:
        raise HTTPException(403, f"Cannot download: {e.response['Error']['Code']}")


# ── Wordlist / Payload endpoints ──────────────────────────────────────────────
@app.get("/api/wordlists")
def list_wordlists(db: Session = Depends(get_db)):
    wls = db.query(Wordlist).order_by(Wordlist.created_at.desc()).all()
    return [
        {
            "id": w.id,
            "name": w.name,
            "path": w.path,
            "line_count": w.line_count,
            "size_bytes": w.size_bytes,
            "is_builtin": w.is_builtin,
            "created_at": w.created_at.isoformat() if w.created_at else None,
        }
        for w in wls
    ]


@app.post("/api/wordlists/upload")
async def upload_wordlist(file: UploadFile = File(...), db: Session = Depends(get_db)):
    dest = UPLOAD_DIR / file.filename
    size = 0
    lines = 0
    async with aiofiles.open(dest, "wb") as f:
        while chunk := await file.read(65536):
            await f.write(chunk)
            size += len(chunk)
            lines += chunk.count(b"\n")

    wl = Wordlist(name=file.filename, path=str(dest), line_count=lines, size_bytes=size)
    db.add(wl)
    db.commit()
    db.refresh(wl)
    return {"id": wl.id, "name": wl.name, "line_count": lines, "size_bytes": size}


@app.post("/api/wordlists/custom")
async def create_custom_wordlist(payload: dict, db: Session = Depends(get_db)):
    """Create a wordlist from textarea content."""
    name = payload.get("name", f"custom-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.txt")
    content = payload.get("content", "")
    lines = [l.strip() for l in content.splitlines() if l.strip()]
    dest = UPLOAD_DIR / name
    dest.write_text("\n".join(lines))

    wl = Wordlist(
        name=name,
        path=str(dest),
        line_count=len(lines),
        size_bytes=dest.stat().st_size,
    )
    db.add(wl)
    db.commit()
    db.refresh(wl)
    return {"id": wl.id, "name": wl.name, "line_count": len(lines)}


@app.delete("/api/wordlists/{wl_id}")
def delete_wordlist(wl_id: int, db: Session = Depends(get_db)):
    wl = db.query(Wordlist).filter_by(id=wl_id).first()
    if not wl:
        raise HTTPException(404, "Wordlist not found")
    if not wl.is_builtin:
        try:
            pathlib.Path(wl.path).unlink(missing_ok=True)
        except Exception:
            pass
    db.delete(wl)
    db.commit()
    return {"deleted": wl_id}


# ── Report endpoints ──────────────────────────────────────────────────────────
@app.get("/api/reports/{scan_id}/json")
def download_report_json(scan_id: int, db: Session = Depends(get_db)):
    content = export_json(scan_id, db)
    return StreamingResponse(
        io.BytesIO(content.encode()),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=s3hunter-scan-{scan_id}.json"},
    )


@app.get("/api/reports/{scan_id}/csv")
def download_report_csv(scan_id: int, db: Session = Depends(get_db)):
    content = export_csv(scan_id, db)
    return StreamingResponse(
        io.BytesIO(content.encode()),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=s3hunter-scan-{scan_id}.csv"},
    )


# ── Dashboard stats endpoint ──────────────────────────────────────────────────
@app.get("/api/stats")
def global_stats(db: Session = Depends(get_db)):
    total_scans   = db.query(Scan).count()
    total_buckets = db.query(Bucket).count()
    total_vuln    = db.query(Bucket).filter(
        (Bucket.can_write == True) | (Bucket.can_delete == True) | (Bucket.can_read == True)
    ).count()
    total_sensitive = db.query(SensitiveFinding).count()
    critical       = db.query(Bucket).filter_by(risk_level="critical").count()
    high           = db.query(Bucket).filter_by(risk_level="high").count()

    return {
        "total_scans": total_scans,
        "total_buckets": total_buckets,
        "total_vulnerable": total_vuln,
        "total_sensitive": total_sensitive,
        "critical": critical,
        "high": high,
    }


# ── SPA / Static Frontend ───────────────────────────────────────────────────
# Mount the frontend 'dist' directory created by 'npm run build'
# If index.html exists, it will be served as the main landing page.
FRONTEND_DIST = pathlib.Path(__file__).parent.parent / "frontend" / "dist"

if FRONTEND_DIST.exists():
    app.mount("/assets", StaticFiles(directory=str(FRONTEND_DIST / "assets")), name="assets")

    @app.get("/{path:path}")
    async def serve_spa(path: str):
        # Always serve index.html for unknown paths to support frontend routing
        if path.startswith("api") or path.startswith("ws"):
            raise HTTPException(404)
        index_path = FRONTEND_DIST / "index.html"
        if index_path.exists():
            return FileResponse(index_path)
        return JSONResponse({"detail": "Frontend not built. Run 'npm run build' in the frontend directory."}, status_code=503)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
