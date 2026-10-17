"""Automated tests for the RBAC policy engine. Run with python test_policy.py."""

import unittest

from policy_engine import ALLOW, BLOCK, MASK, evaluate_request


class PolicyEngineTests(unittest.TestCase):
    def test_admin_can_access_authorized_fields(self):
        result = evaluate_request("Admin", ["customer_id", "balance"])

        self.assertEqual(result["decision"], ALLOW)
        self.assertEqual(result["allowed_fields"], ["balance", "customer_id"])
        self.assertEqual(result["masked_fields"], [])
        self.assertEqual(result["risk_score"], 0)

    def test_analyst_receives_masking_instructions_for_contact_fields(self):
        result = evaluate_request("Analyst", ["name", "email", "phone"])

        self.assertEqual(result["decision"], MASK)
        self.assertEqual(result["allowed_fields"], ["name"])
        self.assertEqual(result["masked_fields"], ["email", "phone"])
        self.assertEqual(result["risk_score"], 10)

    def test_support_cannot_access_financial_fields(self):
        result = evaluate_request("Support", ["customer_id", "balance"])

        self.assertEqual(result["decision"], BLOCK)
        self.assertEqual(result["allowed_fields"], [])
        self.assertEqual(result["masked_fields"], [])
        self.assertIn("not permitted", result["reason"])

    def test_unknown_role_is_denied(self):
        result = evaluate_request("Guest", ["customer_id"])

        self.assertEqual(result["decision"], BLOCK)
        self.assertEqual(result["allowed_fields"], [])
        self.assertEqual(result["masked_fields"], [])

    def test_unknown_field_blocks_the_entire_request(self):
        result = evaluate_request("Admin", ["customer_id", "medical_record"])

        self.assertEqual(result["decision"], BLOCK)
        self.assertEqual(result["allowed_fields"], [])
        self.assertEqual(result["masked_fields"], [])
        self.assertIn("unknown field", result["reason"])

    def test_api_secret_is_prohibited_even_for_admin(self):
        result = evaluate_request("Admin", ["customer_id", "api_secret"])

        self.assertEqual(result["decision"], BLOCK)
        self.assertEqual(result["allowed_fields"], [])
        self.assertEqual(result["masked_fields"], [])
        self.assertIn("always prohibited", result["reason"])

    def test_password_is_prohibited_even_for_admin(self):
        result = evaluate_request("Admin", ["password"])

        self.assertEqual(result["decision"], BLOCK)
        self.assertEqual(result["allowed_fields"], [])
        self.assertEqual(result["masked_fields"], [])

    def test_suspicious_activity_blocks_the_request(self):
        result = evaluate_request(
            "Admin",
            ["customer_id"],
            signals={"suspicious_activity": True},
        )

        self.assertEqual(result["decision"], BLOCK)
        self.assertEqual(result["allowed_fields"], [])
        self.assertEqual(result["risk_score"], 40)
        self.assertIn("blocking security signal", result["reason"])

    def test_malformed_signals_fail_closed(self):
        result = evaluate_request("Admin", ["customer_id"], signals=["untrusted"])

        self.assertEqual(result["decision"], BLOCK)
        self.assertEqual(result["allowed_fields"], [])
        self.assertEqual(result["masked_fields"], [])

    def test_risk_score_is_rule_based_and_capped(self):
        result = evaluate_request(
            "Analyst",
            ["email", "phone"],
            signals={
                "untrusted_device": True,
                "high_request_volume": True,
            },
        )

        self.assertEqual(result["decision"], MASK)
        self.assertEqual(result["risk_score"], 45)
        self.assertIn("rule-based risk signals", result["reason"])


if __name__ == "__main__":
    unittest.main()
