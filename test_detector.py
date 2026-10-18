import unittest

from sensitive_detector import calculate_risk, detect_sensitive, mask_sensitive, sanitize_text


class DetectorTests(unittest.TestCase):
    def test_email_detection_and_masking(self):
        text = "Contact person@example.test today"
        self.assertIn("email", detect_sensitive(text)["categories"])
        self.assertEqual(mask_sensitive(text), "Contact [EMAIL REDACTED] today")

    def test_labelled_email(self):
        self.assertEqual(mask_sensitive("customer_email=alice@example.test"), "customer_email=[EMAIL REDACTED]")

    def test_indian_phone(self):
        self.assertIn("phone", detect_sensitive("Call +91 98765 43210")["categories"])
        self.assertIn("[PHONE REDACTED]", mask_sensitive("Call 9876543210"))

    def test_labelled_phone(self):
        self.assertIn("[PHONE REDACTED]", mask_sensitive("customer_phone=9876543210"))

    def test_api_key(self):
        self.assertIn("[SECRET REDACTED]", mask_sensitive("key sk-1234567890abcdefghijkl"))

    def test_bearer_token(self):
        self.assertIn("[SECRET REDACTED]", mask_sensitive("Bearer abcdefghijklmnopqrstuvwxyz123"))

    def test_password(self):
        self.assertEqual(mask_sensitive("password=synthetic123!"), "password=[PASSWORD REDACTED]")

    def test_private_key_marker(self):
        text = "-----BEGIN PRIVATE KEY-----\nsynthetic-material\n-----END PRIVATE KEY-----"
        self.assertEqual(mask_sensitive(text), "[PRIVATE KEY REDACTED]")

    def test_pan(self):
        self.assertEqual(mask_sensitive("PAN ABCDE1234F"), "PAN [PAN REDACTED]")

    def test_aadhaar_unlabelled_false_positive_avoided(self):
        self.assertFalse(detect_sensitive("123456789012")["contains_sensitive_data"])

    def test_labelled_aadhaar_valid_checksum(self):
        self.assertIn("aadhaar", detect_sensitive("aadhaar=234567890124")["categories"])

    def test_account_label(self):
        self.assertIn("[ACCOUNT NUMBER REDACTED]", mask_sensitive("account_number=123456789012"))

    def test_secret_key_field(self):
        self.assertIn("[SECRET REDACTED]", mask_sensitive("secret_key=synthetic-secret-value"))

    def test_multiple_categories(self):
        result = detect_sensitive("alice@example.test and password=hunter2")
        self.assertEqual(set(result["categories"]), {"email", "password"})

    def test_repeated_occurrences(self):
        self.assertEqual(mask_sensitive("a@b.test a@b.test"), "[EMAIL REDACTED] [EMAIL REDACTED]")

    def test_unicode_and_multiline(self):
        output = mask_sensitive("नमस्ते\nemail=alice@example.test")
        self.assertIn("[EMAIL REDACTED]", output)
        self.assertTrue(output.startswith("नमस्ते\n"))

    def test_empty(self):
        self.assertFalse(detect_sensitive("")["contains_sensitive_data"])
        self.assertEqual(mask_sensitive(""), "")

    def test_normal_text(self):
        self.assertEqual(mask_sensitive("hello, ordinary world!"), "hello, ordinary world!")

    def test_risk_boundaries(self):
        self.assertEqual(calculate_risk([]), {"risk_score": 0, "risk_level": "LOW"})
        self.assertEqual(calculate_risk([{"severity": "CRITICAL"}] * 3)["risk_score"], 100)
        self.assertEqual(calculate_risk([{"severity": "MEDIUM"}, {"severity": "MEDIUM"}])["risk_level"], "MEDIUM")

    def test_overlap_credential_beats_generic_token(self):
        text = "api_key=syntheticvalue123456789"
        self.assertEqual(mask_sensitive(text), "api_key=[SECRET REDACTED]")

    def test_findings_never_include_raw_secret(self):
        secret = "password=synthetic-do-not-return"
        result = detect_sensitive(secret)
        self.assertNotIn("synthetic-do-not-return", repr(result))
        self.assertIn("redacted_preview", result["findings"][0])

    def test_sanitize_structure(self):
        result = sanitize_text("email a@b.test")
        self.assertEqual(result["original_length"], len("email a@b.test"))
        self.assertTrue(result["was_modified"])
        self.assertIn("risk_level", result["detection_summary"])

    def test_large_input(self):
        text = "x" * 100000 + " a@b.test"
        self.assertIn("[EMAIL REDACTED]", mask_sensitive(text))

    def test_malformed_type(self):
        with self.assertRaises(TypeError):
            detect_sensitive(None)

    def test_safe_outgoing_response(self):
        result = sanitize_text("Your email is user@example.test")
        self.assertNotIn("user@example.test", result["sanitized_text"])

    def test_flask_import_contract(self):
        from sensitive_detector import calculate_risk as risk, detect_sensitive as detect, mask_sensitive as mask, sanitize_text as sanitize
        self.assertTrue(all(callable(fn) for fn in (risk, detect, mask, sanitize)))


if __name__ == "__main__":
    unittest.main()
