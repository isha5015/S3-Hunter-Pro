"""
S3-Hunter Pro — Permission Checker (Boto3)
Tests LIST / READ / WRITE / DELETE on discovered S3 buckets.
"""
import io
import logging
import boto3
from botocore import UNSIGNED
from botocore.config import Config
from botocore.exceptions import ClientError, EndpointResolutionError, NoRegionError

logger = logging.getLogger("s3hunter.permissions")

CANARY_KEY  = "s3hunter-probe-DO-NOT-DELETE.txt"
CANARY_DATA = b"S3-Hunter Pro permission canary probe. Safe to delete."


def _get_client(region: str = "us-east-1", aws_key: str = None, aws_secret: str = None, anon: bool = True):
    """Return a Boto3 S3 client — anonymous or authenticated."""
    if anon or not (aws_key and aws_secret):
        return boto3.client(
            "s3",
            region_name=region,
            config=Config(signature_version=UNSIGNED, retries={"max_attempts": 2}),
        )
    return boto3.client(
        "s3",
        region_name=region,
        aws_access_key_id=aws_key,
        aws_secret_access_key=aws_secret,
        config=Config(retries={"max_attempts": 2}),
    )


def _check_waf_cdn(headers: dict) -> list[str]:
    """Identify WAF/CDN presence from response headers."""
    found = []
    h_str = str(headers).lower()
    if "cloudfront" in h_str or headers.get("X-Amz-Cf-Id"):
        found.append("AWS CloudFront")
    if "cloudflare" in h_str:
        found.append("Cloudflare")
    if "akamai" in h_str:
        found.append("Akamai")
    if "fastly" in h_str:
        found.append("Fastly")
    return found


def check_bucket_exists(bucket_name: str, region: str = "us-east-1",
                         aws_key: str = None, aws_secret: str = None,
                         anon: bool = True) -> dict:
    """
    Return a result dict:
      { exists, can_list, can_read, can_write, can_delete,
        region, url, object_count, total_size_bytes, risk_level, error,
        is_takeover_candidate, proxy_detected }
    """
    result = {
        "exists": False,
        "can_list": False,
        "can_read": False,
        "can_write": False,
        "can_delete": False,
        "region": region,
        "url": f"https://{bucket_name}.s3.amazonaws.com",
        "object_count": 0,
        "total_size_bytes": 0.0,
        "risk_level": "unknown",
        "error": None,
        "first_key": None,
        "is_takeover_candidate": False,
        "proxy_detected": [],
    }

    client = _get_client(region, aws_key, aws_secret, anon)

    # ── 1. LIST ────────────────────────────────────────────────────────────
    try:
        resp = client.list_objects_v2(Bucket=bucket_name, MaxKeys=100)
        result["exists"]    = True
        result["can_list"]  = True
        result["proxy_detected"] = _check_waf_cdn(resp.get("ResponseMetadata", {}).get("HTTPHeaders", {}))
        
        contents = resp.get("Contents", [])
        result["object_count"]     = len(contents)
        result["total_size_bytes"] = sum(o.get("Size", 0) for o in contents)
        if contents:
            result["first_key"] = contents[0]["Key"]

        # Try to detect region from header
        try:
            loc = boto3.client("s3", config=Config(signature_version=UNSIGNED)).get_bucket_location(Bucket=bucket_name)
            actual_region = loc.get("LocationConstraint") or "us-east-1"
            result["region"] = actual_region
            result["url"] = f"https://{bucket_name}.s3.{actual_region}.amazonaws.com"
        except Exception:
            pass

    except ClientError as e:
        code = e.response["Error"]["Code"]
        headers = e.response.get("ResponseMetadata", {}).get("HTTPHeaders", {})
        result["proxy_detected"] = _check_waf_cdn(headers)

        if code in ("NoSuchBucket", "404"):
            # Check if headers suggest it's actually an S3 endpoint (Takeover candidate)
            # If server is 'AmazonS3' but bucket doesn't exist, it's a takeover candidate if a CNAME points here.
            if headers.get("Server") == "AmazonS3":
                 result["is_takeover_candidate"] = True
            return result
        
        if code == "InvalidBucketName":
            return result
        
        # Any other ClientError means the bucket actually exists, but we lack permissions or used the wrong endpoint.
        result["exists"] = True
        
        if code == "PermanentRedirect":
            redirected = e.response.get("Error", {}).get("Endpoint", "")
            result["region"] = redirected.split(".")[2] if redirected.count(".") >= 3 else region
        elif code not in ("AllAccessDisabled", "AccessDenied"):
            result["error"] = code
    except Exception as e:
        result["error"] = str(e)
        return result

    if not result["exists"]:
        return result

    # ── 2. READ ────────────────────────────────────────────────────────────
    if result["first_key"]:
        try:
            client.get_object(Bucket=bucket_name, Key=result["first_key"])
            result["can_read"] = True
        except ClientError as e:
            if e.response["Error"]["Code"] not in ("AccessDenied", "AllAccessDisabled"):
                result["can_read"] = True  # object may not exist; listing worked
        except Exception:
            pass

    # ── 3. WRITE ───────────────────────────────────────────────────────────
    try:
        client.put_object(Bucket=bucket_name, Key=CANARY_KEY, Body=io.BytesIO(CANARY_DATA))
        result["can_write"] = True
        # ── 4. DELETE ──────────────────────────────────────────────────────
        try:
            client.delete_object(Bucket=bucket_name, Key=CANARY_KEY)
            result["can_delete"] = True
        except Exception:
            pass
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("AccessDenied", "AllAccessDisabled"):
            logger.debug("write check unexpected error: %s", e)
    except Exception:
        pass

    result["risk_level"] = _compute_risk(result)
    return result


def _compute_risk(r: dict) -> str:
    if r["is_takeover_candidate"]:
        return "critical"
    if r["can_write"] or r["can_delete"]:
        return "critical"
    if r["can_read"]:
        return "high"
    if r["can_list"]:
        return "medium"
    if r["exists"]:
        return "low"
    return "unknown"
