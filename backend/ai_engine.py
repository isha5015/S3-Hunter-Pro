"""
S3-Hunter Pro — AI Analysis Engine (ai_engine.py)
Uses local Ollama LLM (GPU-accelerated on RTX 4050) to:
  1. Analyze sensitive findings and generate risk assessments
  2. Auto-suggest scan configurations from a target description
  3. Analyze HTTP request/response patterns from bucket access attempts
  4. Provide remediation advice
"""
import json
import logging
import httpx
import asyncio
from typing import Optional

logger = logging.getLogger("s3hunter.ai")

OLLAMA_BASE = "http://localhost:11434"
DEFAULT_MODEL = "llama3.2:3b"  # Fast, fits in 6GB VRAM on RTX 4050
FALLBACK_MODEL = "gemma2:2b"

SYSTEM_PROMPT = """You are S3-Hunter AI, an expert AWS security analyst embedded in the S3-Hunter Pro penetration testing framework.
You analyze S3 bucket misconfigurations, sensitive data leaks, and security findings.
Always respond with precise, actionable security insights. Be concise and technical.
When asked to respond in JSON, respond ONLY with valid JSON and no other text."""


async def _ollama_chat(prompt: str, system: str = SYSTEM_PROMPT,
                       model: str = DEFAULT_MODEL, timeout: int = 60) -> str:
    """Send a chat request to local Ollama instance."""
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ],
        "stream": False,
        "options": {
            "temperature": 0.3,
            "num_ctx": 4096,
        }
    }
    async with httpx.AsyncClient(timeout=timeout) as client:
        try:
            resp = await client.post(f"{OLLAMA_BASE}/api/chat", json=payload)
            resp.raise_for_status()
            data = resp.json()
            return data["message"]["content"].strip()
        except httpx.ConnectError:
            raise RuntimeError("Ollama not running. Start with: ollama serve")
        except Exception as e:
            logger.error("Ollama error: %s", e)
            raise


async def check_ollama_status() -> dict:
    """Check if Ollama is running and which models are available."""
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(f"{OLLAMA_BASE}/api/tags")
            models = [m["name"] for m in resp.json().get("models", [])]
            preferred = DEFAULT_MODEL if DEFAULT_MODEL in models else (
                FALLBACK_MODEL if FALLBACK_MODEL in models else (models[0] if models else None)
            )
            return {"running": True, "models": models, "preferred_model": preferred}
    except Exception:
        return {"running": False, "models": [], "preferred_model": None}


async def analyze_findings(bucket_name: str, findings: list[dict], permissions: dict) -> dict:
    """
    AI analysis of a bucket's sensitive findings and permissions.
    Returns: { risk_score, risk_summary, attack_scenarios, remediation, priority }
    """
    perm_str = ", ".join(
        k for k, v in permissions.items() if v and k.startswith("can_")
    ) or "none detected"

    findings_summary = "\n".join(
        f"- [{f.get('severity','?').upper()}] {f.get('pattern_name')}: {f.get('match_preview','')[:60]}"
        for f in findings[:20]
    ) or "No sensitive data found in scanned files."

    prompt = f"""Analyze this AWS S3 bucket security assessment:

**Bucket:** {bucket_name}
**Permissions:** {perm_str}
**Sensitive Findings ({len(findings)} total):**
{findings_summary}

Respond ONLY with a JSON object in this exact format:
{{
  "risk_score": <1-10 integer>,
  "risk_summary": "<2-3 sentence summary of the risk>",
  "attack_scenarios": ["<scenario 1>", "<scenario 2>", "<scenario 3>"],
  "remediation": ["<fix 1>", "<fix 2>", "<fix 3>"],
  "priority": "<immediate|high|medium|low>",
  "estimated_impact": "<business impact description>"
}}"""

    try:
        raw = await _ollama_chat(prompt)
        # Extract JSON block if wrapped in markdown
        if "```" in raw:
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        return json.loads(raw.strip())
    except json.JSONDecodeError:
        logger.warning("AI returned non-JSON for findings analysis, using fallback")
        return _fallback_analysis(findings, permissions)
    except Exception as e:
        logger.error("AI findings analysis failed: %s", e)
        return _fallback_analysis(findings, permissions)


async def suggest_scan_config(target_description: str) -> dict:
    """
    Given a natural language description of a target, suggest optimal scan settings.
    Returns: { wordlist_suggestions, prefixes, suffixes, regions, concurrency, notes }
    """
    prompt = f"""You are helping configure an S3 bucket enumeration scan.

Target description: "{target_description}"

Based on this target, suggest optimal scan configuration. Respond ONLY with JSON:
{{
  "prefixes": ["<prefix1>", "<prefix2>"],
  "suffixes": ["<suffix1>", "<suffix2>"],
  "recommended_regions": ["<region1>", "<region2>"],
  "concurrency": <number 10-100>,
  "wordlist_type": "<category: company|financial|healthcare|tech|ecommerce|general>",
  "additional_names": ["<specific bucket name to try 1>", "<name2>", "<name3>"],
  "reasoning": "<brief explanation of why these settings>",
  "estimated_risk_areas": ["<area1>", "<area2>"]
}}"""

    try:
        raw = await _ollama_chat(prompt)
        if "```" in raw:
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        return json.loads(raw.strip())
    except Exception as e:
        logger.error("AI config suggestion failed: %s", e)
        return {
            "prefixes": [], "suffixes": [],
            "recommended_regions": ["us-east-1"],
            "concurrency": 50,
            "wordlist_type": "general",
            "additional_names": [],
            "reasoning": f"AI unavailable: {e}",
            "estimated_risk_areas": [],
        }


async def analyze_request_pattern(request_log: list[dict]) -> dict:
    """
    Analyze HTTP request/response patterns from scan attempts.
    Returns patterns, anomalies, and bypass suggestions.
    """
    log_str = "\n".join(
        f"[{r.get('status_code', '?')}] {r.get('bucket', '?')} - {r.get('error', 'OK')}"
        for r in request_log[:50]
    )

    prompt = f"""Analyze these S3 bucket enumeration HTTP responses:

{log_str}

Identify patterns, WAF blocks, rate limiting, or other anomalies.
Respond ONLY with JSON:
{{
  "patterns_detected": ["<pattern1>", "<pattern2>"],
  "rate_limited": <true|false>,
  "waf_detected": <true|false>,
  "bypass_suggestions": ["<suggestion1>", "<suggestion2>"],
  "interesting_findings": ["<finding1>"],
  "recommended_delay_ms": <number>
}}"""

    try:
        raw = await _ollama_chat(prompt)
        if "```" in raw:
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        return json.loads(raw.strip())
    except Exception as e:
        return {"patterns_detected": [], "rate_limited": False, "waf_detected": False,
                "bypass_suggestions": [], "interesting_findings": [], "recommended_delay_ms": 0}


async def generate_report_narrative(scan_data: dict) -> str:
    """Generate a human-readable executive summary narrative for a scan."""
    prompt = f"""Write a concise executive security report summary (3-4 paragraphs) for this S3 security assessment:

Scan: {scan_data.get('name', 'Unknown')}
Buckets Found: {scan_data.get('buckets_found', 0)}
Critical Risk: {scan_data.get('critical', 0)}
High Risk: {scan_data.get('high', 0)}
Sensitive Findings: {scan_data.get('total_sensitive', 0)}
Vulnerable Buckets: {scan_data.get('total_vulnerable', 0)}

Write as a professional penetration testing report summary. Be specific about risks and business impact."""

    try:
        return await _ollama_chat(prompt)
    except Exception as e:
        return f"AI narrative unavailable. Scan completed with {scan_data.get('buckets_found', 0)} buckets found."


async def chat_assistant(message: str, context: dict = None) -> str:
    """General-purpose security assistant chat for the UI."""
    ctx_str = ""
    if context:
        ctx_str = f"\n\nCurrent scan context: {json.dumps(context, default=str)[:500]}"

    prompt = f"{message}{ctx_str}"
    try:
        return await _ollama_chat(prompt)
    except Exception as e:
        return f"AI Assistant unavailable: {str(e)}. Ensure Ollama is running with: ollama serve"


def _fallback_analysis(findings: list, permissions: dict) -> dict:
    """Rule-based fallback when AI is unavailable."""
    critical = sum(1 for f in findings if f.get("severity") == "critical")
    high = sum(1 for f in findings if f.get("severity") == "high")
    can_write = permissions.get("can_write", False)
    can_delete = permissions.get("can_delete", False)
    can_read = permissions.get("can_read", False)

    score = min(10, critical * 3 + high * 2 + (3 if can_write else 0) + (2 if can_delete else 0) + (1 if can_read else 0))
    priority = "immediate" if score >= 8 else "high" if score >= 5 else "medium" if score >= 3 else "low"

    return {
        "risk_score": score,
        "risk_summary": f"Bucket has {len(findings)} sensitive findings with {critical} critical. "
                        f"Write: {can_write}, Delete: {can_delete}, Read: {can_read}.",
        "attack_scenarios": [
            "Data exfiltration of exposed sensitive files" if can_read else "",
            "Malware/backdoor upload via write access" if can_write else "",
            "Ransomware attack via delete permissions" if can_delete else "",
        ],
        "remediation": [
            "Apply bucket policy to restrict public access",
            "Enable S3 Block Public Access settings",
            "Rotate any exposed credentials immediately",
        ],
        "priority": priority,
        "estimated_impact": "High business risk due to exposed sensitive data and misconfigured permissions.",
    }
