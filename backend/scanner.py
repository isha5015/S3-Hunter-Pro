"""
S3-Hunter Pro — Async Scanning Engine
Reads wordlist line-by-line with checkpoint support,
spawns a ThreadPoolExecutor for concurrent bucket probing,
and broadcasts real-time updates via WebSocket.
"""
import asyncio
import logging
import pathlib
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Callable, Optional

from sqlalchemy.orm import Session

from database import SessionLocal, Scan, Bucket, BucketFile, SensitiveFinding
from permissions import check_bucket_exists
from sensitive_scanner import scan_file, is_sensitive_filename

logger = logging.getLogger("s3hunter.scanner")

# Global registry: scan_id -> ScanWorker
_active_scans: dict[int, "ScanWorker"] = {}


def get_active_scan(scan_id: int) -> Optional["ScanWorker"]:
    return _active_scans.get(scan_id)


def register_scan(worker: "ScanWorker"):
    _active_scans[worker.scan_id] = worker


def unregister_scan(scan_id: int):
    _active_scans.pop(scan_id, None)


class ScanWorker:
    """Manages a single scan session."""

    def __init__(self, scan_id: int, broadcast_fn: Callable):
        self.scan_id      = scan_id
        self.broadcast    = broadcast_fn  # async fn(message: dict)
        self._pause_event = asyncio.Event()
        self._pause_event.set()   # not paused by default
        self._stop_flag   = False
        self.stats = {
            "tested": 0, "found": 0, "vulnerable": 0,
            "sensitive": 0, "errors": 0,
        }

    def pause(self):
        self._pause_event.clear()
        logger.info("Scan %d paused", self.scan_id)

    def resume(self):
        self._pause_event.set()
        logger.info("Scan %d resumed", self.scan_id)

    def stop(self):
        self._stop_flag = True
        self._pause_event.set()  # unblock if paused
        logger.info("Scan %d stopped", self.scan_id)

    async def _log(self, message: str, level: str = "info"):
        """Broadcast a raw engine log to the frontend."""
        prefix = "[SCAN]" if level == "info" else "[!!!]" if level == "warn" else "[SYS]"
        await self.broadcast({
            "type": "engine_log",
            "scan_id": self.scan_id,
            "message": f"{prefix} {message}",
            "level": level
        })

    async def run(self):
        db = SessionLocal()
        try:
            scan = db.query(Scan).filter_by(id=self.scan_id).first()
            if not scan:
                return

            scan.status = "running"
            db.commit()
            await self.broadcast({"type": "scan_started", "scan_id": self.scan_id})
            await self._log(f"Initializing elite engine for scan: {scan.name}", "sys")

            # Build target name list
            names = await asyncio.get_event_loop().run_in_executor(
                None, self._build_name_list, scan
            )

            total = len(names)
            start_from = scan.checkpoint
            await self._log(f"Target manifest built: {total} permutations identified.", "sys")

            regions = [r.strip() for r in (scan.regions or "us-east-1").split(",") if r.strip()]
            concurrency = max(1, min(scan.concurrency or 50, 200))

            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor(max_workers=concurrency) as pool:
                batch_size = concurrency * 2
                for batch_start in range(start_from, total, batch_size):
                    if self._stop_flag:
                        break
                    await self._pause_event.wait()

                    batch = names[batch_start: batch_start + batch_size]
                    await self._log(f"Probing batch {batch_start//batch_size + 1} ({len(batch)} targets)...")
                    
                    futures = {
                        pool.submit(
                            check_bucket_exists,
                            name,
                            regions[0],
                            scan.aws_key,
                            scan.aws_secret,
                            scan.anon_mode,
                        ): name
                        for name in batch
                    }

                    for future in as_completed(futures):
                        if self._stop_flag:
                            break
                        await self._pause_event.wait()

                        bucket_name = futures[future]
                        self.stats["tested"] += 1

                        try:
                            result = future.result()
                        except Exception as e:
                            self.stats["errors"] += 1
                            await self._log(f"Fault detected on {bucket_name}: {str(e)[:50]}", "warn")
                            continue

                        if result["is_takeover_candidate"]:
                             await self._log(f"TAKEOVER CANDIDATE: {bucket_name} (NoSuchBucket + AmazonS3 Header)", "warn")

                        if result["exists"] or result["is_takeover_candidate"]:
                            self.stats["found"] += 1
                            await self._log(f"Target acquisition: {bucket_name} [{result['risk_level'].upper()}]")
                            
                            if result["can_write"] or result["can_delete"] or result["can_read"]:
                                self.stats["vulnerable"] += 1

                            db2 = SessionLocal()
                            try:
                                bucket_row = await loop.run_in_executor(
                                    None, self._save_bucket, db2, scan.id, bucket_name, result, bucket_name
                                )
                                sensitive_count = 0
                                if result["can_list"] and result["object_count"] > 0:
                                    await self._log(f"Enumerating object manifest for {bucket_name}...")
                                    total_count, sensitive_count = await loop.run_in_executor(
                                        None, self._enumerate_files, db2, bucket_row,
                                        bucket_name, scan
                                    )
                                    bucket_row.object_count = total_count
                                    if sensitive_count > 0:
                                        await self._log(f"SECRETS EXFILTRATED: {sensitive_count} matches in {bucket_name}", "warn")
                                
                                bucket_row.sensitive_count = sensitive_count
                                if sensitive_count > 0:
                                    self.stats["sensitive"] += sensitive_count
                                db2.commit()

                                await self.broadcast({
                                    "type": "bucket_found",
                                    "scan_id": self.scan_id,
                                    "bucket": {
                                        "id": bucket_row.id,
                                        "name": bucket_name,
                                        "region": result["region"],
                                        "url": result["url"],
                                        "can_list": result["can_list"],
                                        "can_read": result["can_read"],
                                        "can_write": result["can_write"],
                                        "can_delete": result["can_delete"],
                                        "object_count": result["object_count"],
                                        "sensitive_count": sensitive_count,
                                        "risk_level": result["risk_level"],
                                        "is_takeover_candidate": result["is_takeover_candidate"],
                                        "proxy_detected": result["proxy_detected"]
                                    },
                                })
                            finally:
                                db2.close()

                        # Progress update every 10 tests
                        if self.stats["tested"] % 10 == 0:
                            progress_pct = round(
                                (batch_start + self.stats["tested"]) / max(total, 1) * 100, 1
                            )
                            await self.broadcast({
                                "type": "progress",
                                "scan_id": self.scan_id,
                                "stats": self.stats,
                                "progress": progress_pct,
                                "current": batch_start + self.stats["tested"],
                                "total": total,
                            })

                    # Update checkpoint
                    checkpoint = batch_start + batch_size
                    db.query(Scan).filter_by(id=self.scan_id).update({"checkpoint": checkpoint})
                    db.commit()

            final_status = "stopped" if self._stop_flag else "done"
            db.query(Scan).filter_by(id=self.scan_id).update({"status": final_status, "checkpoint": total})
            db.commit()
            await self._log(f"Scan lifecycle completed with status: {final_status}", "sys")
            await self.broadcast({
                "type": "scan_complete",
                "scan_id": self.scan_id,
                "status": final_status,
                "stats": self.stats,
            })

        except Exception as e:
            logger.error("Scan %d error: %s", self.scan_id, e, exc_info=True)
            db.query(Scan).filter_by(id=self.scan_id).update({"status": "error"})
            db.commit()
            await self.broadcast({"type": "error", "scan_id": self.scan_id, "message": str(e)})
        finally:
            db.close()
            unregister_scan(self.scan_id)

    # ── Helpers ──────────────────────────────────────────────────────────────
    def _build_name_list(self, scan: Scan) -> list[str]:
        names = []
        prefixes = [p.strip() for p in (scan.prefixes or "").split(",") if p.strip()]
        suffixes = [s.strip() for s in (scan.suffixes or "").split(",") if s.strip()]

        if scan.wordlist_path and pathlib.Path(scan.wordlist_path).exists():
            with open(scan.wordlist_path, "r", errors="replace") as f:
                for line in f:
                    word = line.strip()
                    if not word or word.startswith("#"):
                        continue
                    names.append(word)
                    for p in prefixes:
                        names.append(f"{p}-{word}")
                        names.append(f"{p}{word}")
                    for s in suffixes:
                        names.append(f"{word}-{s}")
                        names.append(f"{word}{s}")
        
        # Add direct payloads if present
        if hasattr(scan, 'direct_payloads') and scan.direct_payloads:
             for line in scan.direct_payloads.splitlines():
                 word = line.strip()
                 if word: names.append(word)

        # Deduplicate while preserving order
        seen = set()
        unique = []
        for n in names:
            clean = n.lower().strip()
            if 3 <= len(clean) <= 63 and clean not in seen:
                seen.add(clean)
                unique.append(clean)
        return unique

    def _save_bucket(self, db: Session, scan_id: int, name: str, result: dict, payload_used: str) -> Bucket:
        existing = db.query(Bucket).filter_by(scan_id=scan_id, name=name).first()
        if existing:
            return existing
        b = Bucket(
            scan_id=scan_id,
            name=name,
            payload_used=payload_used,
            region=result["region"],
            url=result["url"],
            can_list=result["can_list"],
            can_read=result["can_read"],
            can_write=result["can_write"],
            can_delete=result["can_delete"],
            object_count=result["object_count"],
            total_size_bytes=result["total_size_bytes"],
            risk_level=result["risk_level"],
            is_takeover_candidate=result["is_takeover_candidate"],
            proxy_detected=result["proxy_detected"],
        )
        db.add(b)
        db.commit()
        db.refresh(b)
        return b

    def _enumerate_files(self, db: Session, bucket_row: Bucket, bucket_name: str, scan: Scan) -> tuple[int, int]:
        """List objects in bucket, save to DB, and scan sensitive files. Returns (total_count, sensitive_count)."""
        import boto3
        from botocore import UNSIGNED
        from botocore.config import Config

        total_count = 0
        sensitive_count = 0
        try:
            if scan.anon_mode or not (scan.aws_key and scan.aws_secret):
                client = boto3.client("s3", config=Config(signature_version=UNSIGNED))
            else:
                client = boto3.client(
                    "s3",
                    aws_access_key_id=scan.aws_key,
                    aws_secret_access_key=scan.aws_secret,
                )

            paginator = client.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=bucket_name):
                for obj in page.get("Contents", []):
                    total_count += 1
                    key = obj["Key"]
                    is_sensitive = is_sensitive_filename(key)
                    bf = BucketFile(
                        bucket_id=bucket_row.id,
                        key=key,
                        size=obj.get("Size", 0),
                        last_modified=obj.get("LastModified"),
                        content_type=None,
                        is_sensitive=is_sensitive,
                        etag=obj.get("ETag", "").strip('"'),
                    )
                    db.add(bf)

                    # Scan content if file looks sensitive and we can read
                    if is_sensitive and bucket_row.can_read:
                        findings = scan_file(bucket_name, key, scan.aws_key, scan.aws_secret, scan.anon_mode)
                        for f in findings:
                            sf = SensitiveFinding(
                                bucket_id=bucket_row.id,
                                file_key=key,
                                pattern_name=f["pattern_name"],
                                severity=f["severity"],
                                match_preview=f["match_preview"],
                            )
                            db.add(sf)
                            sensitive_count += 1

            db.commit()
        except Exception as e:
            logger.debug("enumerate_files %s: %s", bucket_name, e)
        return total_count, sensitive_count
