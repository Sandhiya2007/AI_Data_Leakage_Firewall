# IBM Z Datathon — Member 3: Sensitive Data Detection and Masking

This module uses named Python regular-expression rules and local processing. It does not use a language model, network service, or external package. It is a defense-in-depth heuristic: it cannot find every secret, and its score is not a policy decision. The backend must enforce permissions before reading sensitive fields; policy code independently chooses ALLOW, MASK, or BLOCK.

## Files and interface

`sensitive_detector.py` exports `detect_sensitive(text)`, `mask_sensitive(text)`, `sanitize_text(text)`, and `calculate_risk(findings)`. Findings contain `category`, `rule_id`, `severity`, `start`, `end`, and a placeholder-only `redacted_preview`; raw matched values are never returned. Positions are Python string character offsets and refer to the input before masking.

Rules cover email, Indian phone formats (including +91), common API key and bearer token forms, password assignments, credential-bearing configuration fields, private key blocks, PAN format, checksum-validated labelled Aadhaar values, and explicitly labelled account numbers. Aadhaar candidates require an explicit label and Verhoeff checksum to reduce accidental matches. PAN validation checks its format only.

Overlapping spans are resolved by severity (CRITICAL, HIGH, MEDIUM, LOW), then by longer span. Only the chosen spans are masked. Severity weights are LOW=5, MEDIUM=12, HIGH=25, CRITICAL=40; findings are summed and capped at 100. Scores map to LOW (0), MEDIUM (1–24), HIGH (25–49), and CRITICAL (50–100). This transparent score is a heuristic, not a trained AI prediction or authorization result.

## Setup and run

Python 3.9+ is recommended; there are no third-party dependencies. From the project directory on LinuxONE:

```sh
python3 --version
python3 -m unittest discover -s tests -v
python3 demo_detector.py
```

Windows PowerShell equivalents:

```powershell
py -m unittest discover -s tests -v
py demo_detector.py
```

## Integration for Member 5

For a user prompt, inspect `detect_sensitive(prompt)` and pass its findings/score to the policy engine; this module does not authorize access. For an AI response, sanitize immediately before display:

```python
from sensitive_detector import detect_sensitive, sanitize_text

prompt_report = detect_sensitive(user_prompt)
# policy_engine decides whether the request may proceed; do not rely on this score for authorization.
safe = sanitize_text(response)
return safe["sanitized_text"]
```

Do not log raw prompts, matched secrets, or unmasked responses. Use synthetic data in demos and tests. Do not connect to or validate credentials. The demonstration prints categories, score and level, masked output, and modification status only.

Example structure (values are synthetic):

```python
{
  "contains_sensitive_data": True,
  "findings": [{"category": "email", "rule_id": "EMAIL", "severity": "MEDIUM",
                "start": 8, "end": 23, "redacted_preview": "[EMAIL REDACTED]"}],
  "categories": ["email"], "risk_score": 12, "risk_level": "MEDIUM"
}
```

`sanitize_text` returns `original_length`, `sanitized_text`, `was_modified`, and `detection_summary` (categories, risk score, risk level); the summary does not contain original values.

## Limitations

Regex rules can miss novel, encoded, split, or unusual secrets. Phone and labelled-number rules can still match non-sensitive values that resemble their formats. Aadhaar detection is intentionally conservative and PAN uses format checks rather than issuer validation. Very large strings are processed in memory and may consume time proportional to their length. Non-string input raises `TypeError` predictably. Masking is not a substitute for backend access control, output review, or secure logging.
