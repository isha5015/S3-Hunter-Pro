"""
S3-Hunter Pro — Report Exporter
Generates JSON and CSV reports for a completed scan.
"""
import csv
import io
import json
from datetime import datetime

from sqlalchemy.orm import Session

from database import Scan, Bucket, SensitiveFinding


def _bucket_to_dict(b: Bucket) -> dict:
    return {
        "id": b.id,
        "name": b.name,
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
        "found_at": b.found_at.isoformat() if b.found_at else None,
        "sensitive_findings": [
            {
                "file_key": sf.file_key,
                "pattern_name": sf.pattern_name,
                "severity": sf.severity,
                "match_preview": sf.match_preview,
            }
            for sf in (b.findings or [])
        ],
    }


def export_json(scan_id: int, db: Session) -> str:
    scan = db.query(Scan).filter_by(id=scan_id).first()
    if not scan:
        return json.dumps({"error": "Scan not found"})

    buckets = db.query(Bucket).filter_by(scan_id=scan_id).all()
    data = {
        "report_generated": datetime.utcnow().isoformat(),
        "tool": "S3-Hunter Pro",
        "scan": {
            "id": scan.id,
            "name": scan.name,
            "wordlist": scan.wordlist_name,
            "status": scan.status,
            "checkpoint": scan.checkpoint,
            "total_lines": scan.total_lines,
            "regions": scan.regions,
            "anon_mode": scan.anon_mode,
            "write_test": scan.write_test,
            "delete_test": scan.delete_test,
            "created_at": scan.created_at.isoformat() if scan.created_at else None,
        },
        "summary": {
            "total_buckets_found": len(buckets),
            "critical": sum(1 for b in buckets if b.risk_level == "critical"),
            "high": sum(1 for b in buckets if b.risk_level == "high"),
            "medium": sum(1 for b in buckets if b.risk_level == "medium"),
            "low": sum(1 for b in buckets if b.risk_level == "low"),
            "total_sensitive_findings": sum(b.sensitive_count for b in buckets),
        },
        "buckets": [_bucket_to_dict(b) for b in buckets],
    }
    return json.dumps(data, indent=2, default=str)


def export_csv(scan_id: int, db: Session) -> str:
    scan = db.query(Scan).filter_by(id=scan_id).first()
    buckets = db.query(Bucket).filter_by(scan_id=scan_id).all() if scan else []

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Bucket Name", "Region", "URL", "Risk Level",
        "Can List", "Can Read", "Can Write", "Can Delete",
        "Object Count", "Total Size (bytes)", "Sensitive Findings", "Found At",
    ])
    for b in buckets:
        writer.writerow([
            b.name, b.region, b.url, b.risk_level,
            b.can_list, b.can_read, b.can_write, b.can_delete,
            b.object_count, b.total_size_bytes, b.sensitive_count,
            b.found_at.isoformat() if b.found_at else "",
        ])
    return output.getvalue()
