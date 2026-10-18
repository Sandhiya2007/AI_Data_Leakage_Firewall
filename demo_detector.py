"""Safe synthetic demonstration; prints only sanitized text."""
from sensitive_detector import sanitize_text


def main() -> None:
    scenarios = {
        "A — ordinary text": "The service is available on weekdays.",
        "B — customer contact": "Contact customer_email=maya@example.test or +91 98765 43210.",
        "C — synthetic credentials": "api_key=sk-1234567890abcdefghijkl password=synthetic-pass-123",
        "D — labelled identifiers": "account_number=123456789012 PAN ABCDE1234F",
        "E — outgoing response": "Your profile email is user@example.test.",
    }
    for label, text in scenarios.items():
        result = sanitize_text(text)
        summary = result["detection_summary"]
        print(f"{label}: categories={summary['categories']}, risk={summary['risk_score']} {summary['risk_level']}, modified={result['was_modified']}")
        print(f"  sanitized: {result['sanitized_text']}")


if __name__ == "__main__":
    main()
