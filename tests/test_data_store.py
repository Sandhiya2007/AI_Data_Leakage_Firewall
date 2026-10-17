
import unittest
from seed_data import seed_customers
from data_store import get_customer, get_customer_count


class TestDataStore(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        seed_customers()

    def test_admin_access(self):
        result = get_customer(
            "C1001",
            "admin",
            ["name", "email", "balance"]
        )

        self.assertIn("email", result)
        self.assertIn("balance", result)

    def test_analyst_restriction(self):
        result = get_customer(
            "C1001",
            "analyst",
            ["name", "email", "balance"]
        )

        self.assertNotIn("name", result)
        self.assertNotIn("email", result)
        self.assertIn("balance", result)

    def test_support_restriction(self):
        result = get_customer(
            "C1001",
            "support",
            ["name", "email", "balance"]
        )

        self.assertIn("name", result)
        self.assertNotIn("email", result)
        self.assertNotIn("balance", result)

    def test_invalid_role(self):
        with self.assertRaises(ValueError):
            get_customer(
                "C1001",
                "guest",
                ["email"]
            )

    def test_unknown_field(self):
        with self.assertRaises(ValueError):
            get_customer(
                "C1001",
                "admin",
                ["password"]
            )

    def test_missing_customer(self):
        result = get_customer(
            "C9999",
            "admin",
            ["customer_id"]
        )
        self.assertIsNone(result)

    def test_customer_count(self):
        count = get_customer_count("analyst")
        self.assertEqual(count, 30)


if __name__ == "__main__":
    unittest.main()
