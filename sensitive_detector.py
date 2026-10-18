"""Rule-based sensitive-data detection and local masking.

This is a defense-in-depth heuristic, not a complete secret scanner or access
control system. Findings never contain the original matched value.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, NamedTuple


class Rule(NamedTuple):
    rule_id: str
    category: str
    severity: str
    pattern: re.Pattern[str]
    placeholder: str
    group: int = 0


RULES: tuple[Rule, ...] = (
    Rule("PRIVATE_KEY_BLOCK", "private_key", "CRITICAL", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", re.I), "[PRIVATE KEY REDACTED]"),
    Rule("PASSWORD_ASSIGNMENT", "password", "CRITICAL", re.compile(r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*([^\s,;]+)"), "[PASSWORD REDACTED]", 1),
    Rule("CREDENTIAL_CONFIG", "secret", "CRITICAL", re.compile(r"(?i)\b(?:secret_key|api_key|access_token|auth_token|client_secret)\s*[:=]\s*([^\s,;]+)"), "[SECRET REDACTED]", 1),
    Rule("API_KEY_LIKE", "api_key", "CRITICAL", re.compile(r"\b(?:sk-[A-Za-z0-9_-]{16,}|(?:AKIA|ASIA)[A-Z0-9]{16}|gh[pousr]_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{16,})\b"), "[SECRET REDACTED]"),
    Rule("BEARER_TOKEN", "token", "HIGH", re.compile(r"(?i)\bBearer\s+([A-Za-z0-9._~+/=-]{16,})"), "[SECRET REDACTED]", 1),
    Rule("LABELLED_ACCOUNT", "account_number", "HIGH", re.compile(r"(?i)\b(?:account_number|acct(?:ount)?_?no|bank_account)\s*[:=]\s*([0-9][0-9 -]{5,22}[0-9])"), "[ACCOUNT NUMBER REDACTED]", 1),
    Rule("EMAIL", "email", "MEDIUM", re.compile(r"(?i)(?<![\w.+-])(?!customer_email=|email=)[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+(?![\w-])"), "[EMAIL REDACTED]"),
    Rule("LABELLED_PHONE", "phone", "MEDIUM", re.compile(r"(?i)\b(?:customer_phone|phone|mobile|telephone)\s*[:=]\s*(\+?\d[\d ()-]{7,17}\d)"), "[PHONE REDACTED]", 1),
    Rule("INDIAN_PHONE", "phone", "MEDIUM", re.compile(r"(?<!\d)(?:\+91[ -]?)?[6-9]\d{4}[ -]?\d{5}(?!\d)|(?<!\d)(?:\+91[ -]?)?[6-9]\d{9}(?!\d)"), "[PHONE REDACTED]"),
    Rule("PAN_FORMAT", "pan", "HIGH", re.compile(r"(?i)(?<![A-Z0-9])[A-Z]{5}\d{4}[A-Z](?![A-Z0-9])"), "[PAN REDACTED]"),
    Rule("LABELLED_AADHAAR", "aadhaar", "HIGH", re.compile(r"(?i)\b(?:aadhaar|aadhar|uid)\s*[:=]\s*(\d{4}[ -]?\d{4}[ -]?\d{4})"), "[ID REDACTED]", 1),
)

SEVERITY_WEIGHTS = {"LOW": 5, "MEDIUM": 12, "HIGH": 25, "CRITICAL": 40}
PLACEHOLDERS = {r.category: r.placeholder for r in RULES}


def _verhoeff_valid(number: str) -> bool:
    """Return whether digits satisfy the Aadhaar-style Verhoeff checksum."""
    d = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]]
    p = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]]
    c = 0
    for i, digit in enumerate(reversed(number)):
        c = d[c][p[i % 8][int(digit)]]
    return c == 0


def _collect(text: str) -> List[dict]:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    candidates: List[dict] = []
    for rule in RULES:
        for match in rule.pattern.finditer(text):
            start, end = match.span(rule.group)
            value = match.group(rule.group)
            if rule.rule_id == "LABELLED_AADHAAR":
                digits = re.sub(r"\D", "", value)
                if len(digits) != 12 or digits.startswith("0") or digits.startswith("1") or not _verhoeff_valid(digits):
                    continue
            candidates.append({"category": rule.category, "rule_id": rule.rule_id,
                               "severity": rule.severity, "start": start, "end": end,
                               "redacted_preview": rule.placeholder, "placeholder": rule.placeholder})
    # Resolve intersections by priority, then longer match. Rejected candidates
    # are fully covered by the selected higher-priority range and are redundant.
    priority = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    candidates.sort(key=lambda x: (x["start"], -priority[x["severity"]], -(x["end"]-x["start"])))
    selected: List[dict] = []
    for item in candidates:
        if any(item["start"] < old["end"] and old["start"] < item["end"] for old in selected):
            continue
        selected.append(item)
    return sorted(selected, key=lambda x: x["start"])


def calculate_risk(findings: list) -> dict:
    """Score findings deterministically; this heuristic is not an AI prediction."""
    score = min(100, sum(SEVERITY_WEIGHTS.get(str(f.get("severity", "")).upper(), 0) for f in findings if isinstance(f, dict)))
    level = "LOW" if score == 0 else "MEDIUM" if score < 25 else "HIGH" if score < 50 else "CRITICAL"
    return {"risk_score": score, "risk_level": level}


def detect_sensitive(text: str) -> dict:
    """Detect known sensitive patterns without returning matched values."""
    findings = _collect(text)
    risk = calculate_risk(findings)
    return {"contains_sensitive_data": bool(findings), "findings": [{k: v for k, v in f.items() if k != "placeholder"} for f in findings],
            "categories": list(dict.fromkeys(f["category"] for f in findings)), **risk}


def mask_sensitive(text: str) -> str:
    """Mask all selected matches, preserving surrounding text and punctuation."""
    findings = _collect(text)
    for finding in reversed(findings):
        text = text[:finding["start"]] + finding["placeholder"] + text[finding["end"]:]
    return text


def sanitize_text(text: str) -> dict:
    """Return masked text and a summary that contains no original secret."""
    detected = detect_sensitive(text)
    sanitized = mask_sensitive(text)
    return {"original_length": len(text), "sanitized_text": sanitized, "was_modified": sanitized != text,
            "detection_summary": {"categories": detected["categories"], "risk_score": detected["risk_score"], "risk_level": detected["risk_level"]}}


if __name__ == "__main__":  # pragma: no cover
    from demo_detector import main
    main()
