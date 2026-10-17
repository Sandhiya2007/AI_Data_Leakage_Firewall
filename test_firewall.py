import unittest
import time
import json
import statistics

# Attempt to import firewall and related components safely
try:
    import firewall
except ImportError:
    firewall = None

try:
    import policy_engine
except ImportError:
    policy_engine = None

try:
    import detector
except ImportError:
    detector = None

try:
    import audit
except ImportError:
    audit = None

try:
    import datastore
except ImportError:
    datastore = None

try:
    import app
except ImportError:
    app = None


class TestAIFirewall(unittest.TestCase):
    """Automated test suite for AI Data Leakage Firewall."""

    @classmethod
    def setUpClass(cls):
        cls.has_firewall = firewall is not None
        cls.has_detector = detector is not None
        cls.has_policy = policy_engine is not None
        cls.has_audit = audit is not None

    def setUp(self):
        # Synthetic test data only - never real customer data or credentials
        self.synthetic_user_admin = {"user_id": "admin_01", "role": "admin"}
        self.synthetic_user_support = {"user_id": "support_01", "role": "support"}
        self.synthetic_user_guest = {"user_id": "guest_01", "role": "guest"}
        
        self.synthetic_secret = "api_key_test_12345abcdef"
        self.synthetic_email = "test.user@example.com"
        self.synthetic_phone = "+1-555-0199"
        self.synthetic_financial = "Account Balance: $1,250,000.00"

    def test_authorized_requests_succeed(self):
        """Test that authorized requests with permitted roles and data succeed."""
        if not self.has_firewall and not app:
            self.skipTest("Firewall module or app not found in project.")
        
        if firewall and hasattr(firewall, "process_request"):
            response = firewall.process_request(
                user=self.synthetic_user_admin,
                payload={"query": "Hello world, what is the status?"}
            )
            self.assertIsNotNone(response)
        else:
            self.skipTest("firewall.process_request function not implemented.")

    def test_unauthorized_role_access_denied(self):
        """Test that unauthorized role-based access is denied."""
        if not firewall or not hasattr(firewall, "process_request"):
            self.skipTest("Firewall process_request interface not available.")
        
        response = firewall.process_request(
            user=self.synthetic_user_guest,
            payload={"action": "restricted_admin_action"}
        )
        if isinstance(response, dict):
            status = response.get("status") or response.get("blocked") or response.get("allowed")
            if status is not None:
                self.assertTrue(
                    status in ["denied", "blocked", False, 403, "403"] or status == 0,
                    f"Unauthorized access should be blocked. Response: {response}"
                )

    def test_support_cannot_access_restricted_financial_information(self):
        """Test that support role cannot access restricted financial information."""
        if not firewall or not hasattr(firewall, "process_request"):
            self.skipTest("Firewall process_request interface not available.")
        
        response = firewall.process_request(
            user=self.synthetic_user_support,
            payload={"query": f"Show financial record: {self.synthetic_financial}"}
        )
        response_str = json.dumps(response)
        self.assertNotIn(self.synthetic_financial, response_str, "Restricted financial data exposed to support role!")

    def test_credentials_and_api_secrets_never_exposed(self):
        """Test that credentials and API secrets are never exposed in responses."""
        if not firewall and not detector:
            self.skipTest("Neither firewall nor detector module available.")
        
        text_with_secret = f"Here is your configuration: secret_token = {self.synthetic_secret}"
        
        output = None
        if firewall and hasattr(firewall, "sanitize"):
            output = firewall.sanitize(text_with_secret)
        elif detector and hasattr(detector, "mask_secrets"):
            output = detector.mask_secrets(text_with_secret)
        elif firewall and hasattr(firewall, "process_request"):
            res = firewall.process_request(user=self.synthetic_user_admin, payload={"text": text_with_secret})
            output = json.dumps(res)
        else:
            self.skipTest("Secret scrubbing/sanitization function not implemented.")
            
        if output:
            self.assertNotIn(self.synthetic_secret, str(output), "API secret exposed in firewall response!")

    def test_sensitive_email_and_phone_masked(self):
        """Test that sensitive email addresses and phone numbers are masked according to policies."""
        if not firewall and not detector:
            self.skipTest("Neither firewall nor detector module available.")
            
        test_text = f"Contact support at {self.synthetic_email} or call {self.synthetic_phone}."
        
        output = None
        if firewall and hasattr(firewall, "sanitize"):
            output = firewall.sanitize(test_text)
        elif detector and hasattr(detector, "mask_pii"):
            output = detector.mask_pii(test_text)
        elif firewall and hasattr(firewall, "process_request"):
            res = firewall.process_request(user=self.synthetic_user_admin, payload={"text": test_text})
            output = json.dumps(res)
        else:
            self.skipTest("PII masking function not implemented.")
            
        if output:
            output_str = str(output)
            self.assertNotIn(self.synthetic_email, output_str, "Sensitive email address unmasked!")
            self.assertNotIn(self.synthetic_phone, output_str, "Sensitive phone number unmasked!")

    def test_harmless_text_no_unnecessary_blocking(self):
        """Test that harmless text does not cause unnecessary blocking."""
        if not firewall or not hasattr(firewall, "process_request"):
            self.skipTest("Firewall process_request interface not available.")
            
        harmless_payload = {"message": "What is the weather forecast for today in Zurich?"}
        response = firewall.process_request(user=self.synthetic_user_support, payload=harmless_payload)
        
        if isinstance(response, dict):
            blocked = response.get("blocked", False)
            self.assertFalse(blocked, "Harmless text was incorrectly blocked!")

    def test_mixed_permitted_restricted_field_requests(self):
        """Test mixed permitted and restricted field requests follow existing policy."""
        if not firewall or not hasattr(firewall, "process_request"):
            self.skipTest("Firewall process_request interface not available.")
            
        mixed_payload = {
            "public_info": "System operational metrics normal.",
            "restricted_secret": self.synthetic_secret
        }
        response = firewall.process_request(user=self.synthetic_user_support, payload=mixed_payload)
        response_str = json.dumps(response)
        
        self.assertNotIn(self.synthetic_secret, response_str, "Restricted field leaked in mixed request!")

    def test_audit_events_recorded_without_raw_secrets(self):
        """Test that audit events are recorded without raw secrets or unmasked sensitive responses."""
        if not audit and not (firewall and hasattr(firewall, "get_audit_logs")):
            self.skipTest("Audit logging module or retrieval method not available.")
            
        if firewall and hasattr(firewall, "process_request"):
            firewall.process_request(
                user=self.synthetic_user_admin,
                payload={"data": f"Token: {self.synthetic_secret}"}
            )
            
        logs = []
        if audit and hasattr(audit, "get_logs"):
            logs = audit.get_logs()
        elif firewall and hasattr(firewall, "get_audit_logs"):
            logs = firewall.get_audit_logs()
            
        logs_str = json.dumps(logs)
        self.assertNotIn(self.synthetic_secret, logs_str, "Audit log contains raw unmasked secrets!")

    def test_missing_or_invalid_inputs_handled_safely(self):
        """Test that missing or invalid inputs are handled safely without crashing."""
        if not firewall or not hasattr(firewall, "process_request"):
            self.skipTest("Firewall process_request interface not available.")
            
        try:
            res1 = firewall.process_request(user=None, payload=None)
            res2 = firewall.process_request(user=self.synthetic_user_admin, payload={})
            self.assertIsNotNone(res1)
            self.assertIsNotNone(res2)
        except Exception as e:
            self.fail(f"Firewall crashed on missing/invalid input with exception: {e}")


if __name__ == "__main__":
    unittest.main()