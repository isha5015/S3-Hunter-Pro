"""
S3-Hunter Pro — Sensitive Data Scanner
Regex-based scanner that checks S3 object content for secrets/credentials.
"""
import re
import logging
import boto3
from botocore import UNSIGNED
from botocore.config import Config
from botocore.exceptions import ClientError

logger = logging.getLogger("s3hunter.sensitive")

MAX_FILE_SIZE = 1 * 1024 * 1024  # 1 MB max per file

# ── Pattern registry ──────────────────────────────────────────────────────────
PATTERNS = [
    # AWS & Cloud
    {"name": "AWS Access Key",      "severity": "critical", "regex": re.compile(r"AKIA[0-9A-Z]{16}")},
    {"name": "AWS Secret Key",      "severity": "critical", "regex": re.compile(r"(['\"])([A-Za-z0-9/+=]{40})\1")},
    {"name": "AWS Session Token",   "severity": "critical", "regex": re.compile(r"aws_session_token")},
    {"name": "Google Cloud API Key","severity": "critical", "regex": re.compile(r"AIza[0-9A-Za-z\\-_]{35}")},
    {"name": "Azure Shared Key",    "severity": "critical", "regex": re.compile(r"AccountKey=[a-zA-Z0-9+/=]{88}")},
    
    # Version Control & CI/CD
    {"name": "GitHub Personal Token","severity": "critical", "regex": re.compile(r"gh[pousr]_[A-Za-z0-9]{36}")},
    {"name": "GitLab Private Token", "severity": "critical", "regex": re.compile(r"glpat-[0-9a-zA-Z\\-_]{20}")},
    {"name": "Jenkins API Token",    "severity": "high",     "regex": re.compile(r"([a-f0-9]{32})")},
    
    # Databases
    {"name": "Database Connection String", "severity": "high", "regex": re.compile(r"(mongodb|postgres|mysql|redis|mssql|oracle)://[^\s\"']+")},
    {"name": "MongoDB Atlas URI",    "severity": "critical", "regex": re.compile(r"mongodb\+srv://[a-zA-Z0-9.\-_]+:[a-zA-Z0-9.\-_]+@[a-zA-Z0-9.\-_]+")},
    
    # Communication & Social
    {"name": "Slack Webhook URL",    "severity": "high",     "regex": re.compile(r"https://hooks.slack.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+")},
    {"name": "Slack User Token",     "severity": "critical", "regex": re.compile(r"xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}")},
    {"name": "Discord Webhook",      "severity": "medium",   "regex": re.compile(r"discordapp\.com/api/webhooks/[0-9]+/[a-zA-Z0-9-_]+")},
    {"name": "Twilio Account SID",   "severity": "medium",   "regex": re.compile(r"AC[a-f0-9]{32}")},
    
    # Financial & Payments
    {"name": "Stripe Restricted Key", "severity": "critical", "regex": re.compile(r"rk_(live|test)_[0-9a-zA-Z]{24}")},
    {"name": "Stripe Secret Key",     "severity": "critical", "regex": re.compile(r"sk_(live|test)_[0-9a-zA-Z]{24}")},
    {"name": "Square Access Token",   "severity": "critical", "regex": re.compile(r"sq0atp-[0-9A-Za-z\\-_]{22}")},
    {"name": "PayPal Braintree Token","severity": "high",     "regex": re.compile(r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}")},
    
    # Encryption & Infrastructure
    {"name": "Private Key Block",   "severity": "critical", "regex": re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")},
    {"name": "SSH Private Key",      "severity": "critical", "regex": re.compile(r"-----BEGIN SSH PRIVATE KEY-----")},
    
    # Misc Sensitive
    {"name": "Generic Password",    "severity": "medium",   "regex": re.compile(r"(?i)(password|passwd|pwd|secret|auth|token)\s*[:=]\s*['\"]?([^\s'\"]{6,})['\"]?")},
    {"name": "JWT Token",           "severity": "medium",   "regex": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")},
    {"name": "Internal IP Address",  "severity": "info",     "regex": re.compile(r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b")},
    {"name": "Credit Card Number",   "severity": "high",     "regex": re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})\b")},
]

# File extensions that are likely to contain secrets
SENSITIVE_EXTENSIONS = {
    ".env", ".cfg", ".conf", ".config", ".ini", ".yaml", ".yml",
    ".json", ".xml", ".pem", ".key", ".p12", ".pfx", ".cer",
    ".properties", ".toml", ".sh", ".bash", ".zsh", ".py",
    ".rb", ".php", ".js", ".ts", ".go", ".java", ".sql",
    ".bak", ".backup", ".dump", ".log",
}


def is_sensitive_filename(key: str) -> bool:
    """Return True if the file extension or name pattern suggests secrets."""
    import pathlib
    p = pathlib.PurePosixPath(key)
    ext = p.suffix.lower()
    name = p.name.lower()
    if ext in SENSITIVE_EXTENSIONS:
        return True
    sensitive_names = {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".htpasswd",
                       "wp-config.php", "database.yml", "secrets.yml", ".npmrc",
                       ".pypirc", "credentials", "shadow", "passwd"}
    return name in sensitive_names


def scan_file(bucket_name: str, key: str,
              aws_key: str = None, aws_secret: str = None,
              anon: bool = True) -> list[dict]:
    """
    Download up to MAX_FILE_SIZE bytes from the object and scan for patterns.
    Returns a list of findings: { pattern_name, severity, match_preview }.
    """
    findings = []
    try:
        if anon or not (aws_key and aws_secret):
            client = boto3.client("s3", config=Config(signature_version=UNSIGNED))
        else:
            client = boto3.client("s3", aws_access_key_id=aws_key, aws_secret_access_key=aws_secret)

        resp = client.get_object(Bucket=bucket_name, Key=key, Range=f"bytes=0-{MAX_FILE_SIZE - 1}")
        content = resp["Body"].read().decode("utf-8", errors="replace")

        seen = set()
        for pattern in PATTERNS:
            for match in pattern["regex"].finditer(content):
                hit = match.group(0)[:80]
                uid = (pattern["name"], hit)
                if uid not in seen:
                    seen.add(uid)
                    findings.append({
                        "pattern_name": pattern["name"],
                        "severity": pattern["severity"],
                        "match_preview": hit,
                    })
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code not in ("AccessDenied", "AllAccessDisabled", "NoSuchKey"):
            logger.debug("scan_file %s/%s -> %s", bucket_name, key, code)
    except Exception as e:
        logger.debug("scan_file error: %s", e)

    return findings
