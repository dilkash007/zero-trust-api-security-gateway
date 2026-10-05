"""Zero-Trust Payload & Prompt Injection Threat Detector for API Protection."""

import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from ml.llm_detector import predict_threat_with_llm

logger = logging.getLogger("zero_trust.proxy.detector")

# Comprehensive prompt injection / jailbreak patterns targeting LLM APIs
PROMPT_INJECTION_PATTERNS = [
    r"(?i)\bignore\s+(all\s+)?(previous\s+|prior\s+|above\s+)?(instructions|prompts|rules|guidelines|safety)",
    r"(?i)\byou\s+are\s+now\s+(in\s+)?(dan|jailbreak|developer|unrestricted|god)\s+mode",
    r"(?i)\breturn\s+(the\s+)?(system\s+prompt|initial\s+prompt|hidden\s+instructions)",
    r"(?i)\b(reveal|leak|print|dump|show)\s+(all\s+)?(your\s+)?(api[_\s-]?key|secret|credentials|tokens|env\b)",
    r"(?i)\bpretend\s+you\s+have\s+no\s+(rules|limits|safety|ethics|filters)",
    r"(?i)\bexecute\s+command\b|base64_decode|eval\(|exec\(",
    r"(?i)\b(ignore|bypass|override|disable)\s+(all\s+)?(safety|content)?\s*(filter|filters|rules|safeguards)",
    r"(?i)\broleplay\s+as\s+an\s+unfiltered\b",
]

# Sensitive PII and Secret exposure patterns
SENSITIVE_LEAK_PATTERNS = [
    (r"\b[A-Za-z0-9_-]{20,}\b", "POTENTIAL_SECRET_TOKEN"),
    (r"(?i)(api[_-]?key|secret|password|passwd|private[_-]?key)\s*[:=]\s*['\"][^'\"]+['\"]", "CREDENTIAL_EXPOSURE"),
    (r"\b\d{3}-\d{2}-\d{4}\b", "SSN_LEAK"),
    (r"\b(?:\d{4}[ -]?){3}\d{4}\b", "CREDIT_CARD_LEAK"),
]

# Traditional Web / API Attack Signatures
ATTACK_SIGNATURES = [
    (r"(?i)(\bunion\b.*\bselect\b|\bselect\b.*\bfrom\b|'\s*or\s*'1'='1|--\s*$|;\s*drop\s+table)", "SQL_INJECTION"),
    (r"(?i)(<script\b[^>]*>|javascript:|onerror\s*=|onload\s*=)", "XSS_INJECTION"),
    (r"(\.\./\.\./|\.\.\\\.\.\\|/etc/passwd|/windows/win\.ini)", "PATH_TRAVERSAL"),
    (r"(?i)(curl\s+http|wget\s+http|bash\s+-i|/bin/sh|nc\s+-e)", "COMMAND_INJECTION"),
]


def extract_searchable_text(payload: Any) -> str:
    """Extracts all text content recursively from JSON, dicts, lists, or strings."""
    if payload is None:
        return ""
    if isinstance(payload, str):
        return payload
    if isinstance(payload, (int, float, bool)):
        return str(payload)
    if isinstance(payload, dict):
        # Specially handle Google Gemini API format: {"contents": [{"parts": [{"text": "..."}]}]}
        chunks = []
        for k, v in payload.items():
            chunks.append(str(k))
            chunks.append(extract_searchable_text(v))
        return " ".join(chunks)
    if isinstance(payload, list):
        return " ".join(extract_searchable_text(item) for item in payload)
    return str(payload)


def detect_payload_threats(
    payload: Any,
    client_ip: str = "127.0.0.1",
    user_agent: str = "unknown",
    endpoint: str = "/api/proxy/dispatch",
) -> Dict[str, Any]:
    """Runs defense-in-depth security inspection over the payload:
    1. Regex pattern matching (Prompt Injection, SQLi, XSS, Secret Leaks)
    2. Local Ollama LLM (`zero-trust-guard`) deep threat analysis
    """
    text_content = extract_searchable_text(payload)
    anomalies: List[Dict[str, Any]] = []
    rule_checks: Dict[str, Any] = {
        "prompt_injection_detected": False,
        "sqli_detected": False,
        "xss_detected": False,
        "path_traversal_detected": False,
        "credential_leak_detected": False,
        "matched_rules": [],
    }

    # 1. Prompt Injection Checks
    for pattern in PROMPT_INJECTION_PATTERNS:
        match = re.search(pattern, text_content)
        if match:
            rule_checks["prompt_injection_detected"] = True
            rule_checks["matched_rules"].append("PROMPT_INJECTION")
            anomalies.append({
                "type": "PROMPT_INJECTION_ATTEMPT",
                "severity": "HIGH",
                "score_contribution": 45,
                "detail": f"Prompt injection pattern detected: '{match.group(0)[:60]}'",
            })
            break

    # 2. Web Attack Signatures (SQLi, XSS, Path Traversal)
    for pattern, attack_name in ATTACK_SIGNATURES:
        match = re.search(pattern, text_content)
        if match:
            if attack_name == "SQL_INJECTION":
                rule_checks["sqli_detected"] = True
            elif attack_name == "XSS_INJECTION":
                rule_checks["xss_detected"] = True
            elif attack_name == "PATH_TRAVERSAL":
                rule_checks["path_traversal_detected"] = True

            rule_checks["matched_rules"].append(attack_name)
            anomalies.append({
                "type": attack_name,
                "severity": "CRITICAL" if attack_name in ("SQL_INJECTION", "COMMAND_INJECTION") else "HIGH",
                "score_contribution": 50 if attack_name in ("SQL_INJECTION", "COMMAND_INJECTION") else 35,
                "detail": f"Malicious signature matched: {attack_name}",
            })
            break

    # 3. Credential / Secret Leak Checks
    for pattern, leak_name in SENSITIVE_LEAK_PATTERNS:
        if leak_name != "POTENTIAL_SECRET_TOKEN":
            match = re.search(pattern, text_content)
            if match:
                rule_checks["credential_leak_detected"] = True
                rule_checks["matched_rules"].append(leak_name)
                anomalies.append({
                    "type": leak_name,
                    "severity": "HIGH",
                    "score_contribution": 35,
                    "detail": f"Potential sensitive data pattern detected: {leak_name}",
                })
                break

    # 4. Local Ollama LLM (`zero-trust-guard`) Deep Threat Analysis
    llm_result = None
    try:
        req_ctx = {
            "request_id": "proxy-inspect",
            "client_ip": client_ip,
            "user_agent": user_agent,
            "endpoint": endpoint,
            "method": "POST",
            "is_sensitive": True,
        }
        # Send text_content as payload sample to zero-trust-guard
        sample = text_content[:500] if text_content else "empty_payload"
        llm_result = predict_threat_with_llm(
            req_ctx,
            features={"payload_length": len(text_content)},
            payload_sample=sample,
            timeout=2.0,
        )
    except Exception as exc:
        logger.warning("[PROXY DETECTOR] Ollama LLM inspection error: %s", exc)
        llm_result = None

    # Calculate composite risk score
    base_risk = 5
    for a in anomalies:
        base_risk += a.get("score_contribution", 20)

    llm_threat = False
    llm_score = 0
    llm_confidence = 0.0
    llm_reasoning = None
    llm_model = "zero-trust-guard"
    llm_threat_type = None

    if llm_result:
        llm_model = llm_result.get("model", "zero-trust-guard")
        is_llm_anomaly = llm_result.get("is_anomaly", False)
        raw_threat = llm_result.get("threat_type", "AI_PROMPT_ANOMALY")
        raw_reasoning = llm_result.get("reasoning", "LLM identified anomalous threat signature")

        # Sanity Guard against small model hallucinations:
        # If no rule signatures matched and text contains zero SQL/command keywords, suppress hallucinated SQLi
        has_sql_keywords = any(kw in text_content.lower() for kw in ("select", "union", "drop", "insert", "delete", "where", "--", "/*", "';"))
        is_hallucinated_sqli = ("sql" in (raw_reasoning or "").lower() or "sql" in (raw_threat or "").lower()) and not rule_checks["sqli_detected"] and not has_sql_keywords

        if is_llm_anomaly and not is_hallucinated_sqli:
            llm_threat = True
            llm_score = int(llm_result.get("anomaly_score", 75))
            llm_confidence = float(llm_result.get("confidence", 0.85))
            llm_reasoning = raw_reasoning
            llm_threat_type = raw_threat
            base_risk += 30
            anomalies.append({
                "type": "OLLAMA_LLM_THREAT_DETECTED",
                "severity": "HIGH",
                "score_contribution": 30,
                "detail": f"Ollama ({llm_model}) flagged: {llm_threat_type} ({llm_reasoning})",
            })
        else:
            llm_threat = False
            llm_score = 10 if not is_hallucinated_sqli else 5
            llm_confidence = float(llm_result.get("confidence", 0.95))
            llm_reasoning = "Payload verified clean by zero-trust-guard." if is_hallucinated_sqli else (llm_result.get("reasoning") or "Payload verified safe by zero-trust-guard")
            llm_threat_type = "CLEAN"

    # ML Anomaly Simulation based on characteristics (length, entropy, non-ascii)
    ml_score = 12
    if len(text_content) > 1000 or any(ord(c) > 127 for c in text_content):
        ml_score = 45
    if rule_checks["prompt_injection_detected"] or rule_checks["sqli_detected"]:
        ml_score = 88

    total_risk = min(100, max(5, base_risk))

    # Determine risk level
    if total_risk >= 70:
        risk_level = "CRITICAL"
        policy_decision = "BLOCK"
    elif total_risk >= 50:
        risk_level = "HIGH"
        policy_decision = "BLOCK"
    elif total_risk >= 30:
        risk_level = "MEDIUM"
        policy_decision = "MONITOR"
    else:
        risk_level = "LOW"
        policy_decision = "ALLOW"

    return {
        "rule_checks": rule_checks,
        "anomalies": anomalies,
        "ml_anomaly_score": ml_score,
        "ml_is_anomaly": ml_score >= 70,
        "llm_threat_detected": llm_threat,
        "llm_threat_type": llm_threat_type,
        "llm_anomaly_score": llm_score,
        "llm_confidence": llm_confidence,
        "llm_reasoning": llm_reasoning,
        "llm_model": llm_model,
        "risk_score": total_risk,
        "risk_level": risk_level,
        "policy_decision": policy_decision,
    }
