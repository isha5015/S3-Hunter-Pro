"""
S3-Hunter Pro — Database Models (SQLAlchemy + SQLite)
"""
from datetime import datetime
from sqlalchemy import (
    create_engine, Column, Integer, String, Text,
    DateTime, Boolean, Float, ForeignKey, JSON
)
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

DATABASE_URL = "sqlite:///./s3hunter.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
    echo=False,
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# ── Dependency ──────────────────────────────────────────────────────────────
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ── Models ───────────────────────────────────────────────────────────────────
class Scan(Base):
    __tablename__ = "scans"

    id            = Column(Integer, primary_key=True, index=True)
    name          = Column(String(256), nullable=False)
    wordlist_path = Column(Text, nullable=True)
    wordlist_name = Column(String(256), nullable=True)
    total_lines   = Column(Integer, default=0)
    checkpoint    = Column(Integer, default=0)          # last processed line
    concurrency   = Column(Integer, default=50)
    prefixes      = Column(Text, default="")            # comma-separated
    suffixes      = Column(Text, default="")
    regions       = Column(Text, default="us-east-1")   # comma-separated
    status        = Column(String(32), default="pending")  # pending/running/paused/done/stopped
    aws_key       = Column(Text, nullable=True)
    aws_secret    = Column(Text, nullable=True)
    anon_mode     = Column(Boolean, default=True)
    write_test    = Column(Boolean, default=False)
    delete_test   = Column(Boolean, default=False)
    created_at    = Column(DateTime, default=datetime.utcnow)
    updated_at    = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    buckets        = relationship("Bucket", back_populates="scan", cascade="all, delete")


class Bucket(Base):
    __tablename__ = "buckets"

    id                  = Column(Integer, primary_key=True, index=True)
    scan_id             = Column(Integer, ForeignKey("scans.id"), nullable=False)
    name                = Column(String(256), nullable=False, index=True)
    payload_used        = Column(String(256), nullable=True)
    region              = Column(String(64), nullable=True)
    url                 = Column(Text, nullable=True)
    can_list            = Column(Boolean, default=False)
    can_read            = Column(Boolean, default=False)
    can_write           = Column(Boolean, default=False)
    can_delete          = Column(Boolean, default=False)
    object_count        = Column(Integer, default=0)
    total_size_bytes    = Column(Float, default=0)
    sensitive_count     = Column(Integer, default=0)
    risk_level          = Column(String(16), default="unknown")  # low/medium/high/critical
    is_takeover_candidate = Column(Boolean, default=False)
    proxy_detected      = Column(JSON, default=list)
    found_at            = Column(DateTime, default=datetime.utcnow)

    scan    = relationship("Scan", back_populates="buckets")
    files   = relationship("BucketFile", back_populates="bucket", cascade="all, delete")
    findings = relationship("SensitiveFinding", back_populates="bucket", cascade="all, delete")


class BucketFile(Base):
    __tablename__ = "bucket_files"

    id            = Column(Integer, primary_key=True, index=True)
    bucket_id     = Column(Integer, ForeignKey("buckets.id"), nullable=False)
    key           = Column(Text, nullable=False)
    size          = Column(Float, default=0)
    last_modified = Column(DateTime, nullable=True)
    content_type  = Column(String(128), nullable=True)
    is_sensitive  = Column(Boolean, default=False)
    etag          = Column(String(128), nullable=True)

    bucket = relationship("Bucket", back_populates="files")


class SensitiveFinding(Base):
    __tablename__ = "sensitive_findings"

    id            = Column(Integer, primary_key=True, index=True)
    bucket_id     = Column(Integer, ForeignKey("buckets.id"), nullable=False)
    file_key      = Column(Text, nullable=False)
    pattern_name  = Column(String(128), nullable=False)
    severity      = Column(String(16), default="high")   # info/medium/high/critical
    match_preview = Column(Text, nullable=True)
    found_at      = Column(DateTime, default=datetime.utcnow)

    bucket = relationship("Bucket", back_populates="findings")


class Wordlist(Base):
    __tablename__ = "wordlists"

    id         = Column(Integer, primary_key=True, index=True)
    name       = Column(String(256), nullable=False)
    path       = Column(Text, nullable=False)
    line_count = Column(Integer, default=0)
    size_bytes = Column(Integer, default=0)
    is_builtin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)


def init_db():
    Base.metadata.create_all(bind=engine)
    _seed_builtin_wordlists()


def _seed_builtin_wordlists():
    """Create built-in wordlists on first run."""
    import os, pathlib
    wl_dir = pathlib.Path("wordlists")
    wl_dir.mkdir(exist_ok=True)

    builtin = {
        "common-buckets.txt": _common_bucket_names(),
        "aws-services.txt": _aws_service_names(),
        "company-patterns.txt": _company_patterns(),
    }

    db = SessionLocal()
    try:
        for fname, lines in builtin.items():
            fpath = wl_dir / fname
            if not fpath.exists():
                fpath.write_text("\n".join(lines))
            existing = db.query(Wordlist).filter_by(path=str(fpath)).first()
            if not existing:
                wl = Wordlist(
                    name=fname,
                    path=str(fpath),
                    line_count=len(lines),
                    size_bytes=fpath.stat().st_size,
                    is_builtin=True,
                )
                db.add(wl)
        db.commit()
    finally:
        db.close()


def _common_bucket_names():
    return [
        "backup","backups","data","files","uploads","assets","media","images",
        "videos","docs","documents","config","configs","logs","archive","archives",
        "static","public","private","internal","dev","development","staging","prod",
        "production","test","testing","qa","uat","sandbox","demo","temp","tmp",
        "cache","cdn","storage","s3","bucket","mybucket","company","corporate",
        "web","app","api","admin","database","db","sql","mysql","postgres","mongodb",
        "secrets","keys","creds","credentials","passwords","tokens","certificates",
        "certs","ssl","ssh","vpn","firewall","security","audit","compliance",
        "finance","hr","legal","marketing","engineering","infra","infrastructure",
        "kubernetes","k8s","helm","terraform","ansible","docker","jenkins","gitlab",
        "github","jira","confluence","slack","email","mail","smtp","reports",
        "analytics","metrics","monitoring","alerts","billing","invoices","payments",
    ]


def _aws_service_names():
    return [
        "lambda","ec2","ecs","eks","rds","dynamodb","sqs","sns","ses","cloudfront",
        "cloudwatch","cloudtrail","cloudformation","codecommit","codebuild",
        "codepipeline","codedeploy","elasticbeanstalk","lightsail","amplify",
        "cognito","iam","kms","secrets-manager","parameter-store","glue","athena",
        "redshift","emr","sagemaker","rekognition","comprehend","textract",
    ]


def _company_patterns():
    return [
        "{company}-backup","{company}-data","{company}-files","{company}-assets",
        "{company}-media","{company}-images","{company}-logs","{company}-archive",
        "{company}-static","{company}-public","{company}-private","{company}-dev",
        "{company}-staging","{company}-prod","{company}-test","{company}-qa",
        "{company}-internal","{company}-external","{company}-uploads",
        "backup-{company}","data-{company}","files-{company}","assets-{company}",
    ]
