"""Regression tests for security helpers used by the Flask API."""

from datetime import datetime, timedelta
import unittest

from security import InputValidator, PasswordHasher, SessionManager


class PasswordHasherTests(unittest.TestCase):
    def test_bcrypt_hashes_are_not_plaintext_and_verify_correctly(self):
        hashed = PasswordHasher.hash_password("2468")
        self.assertNotEqual(hashed, "2468")
        self.assertTrue(hashed.startswith("$2"))
        self.assertTrue(PasswordHasher.verify_password("2468", hashed))
        self.assertFalse(PasswordHasher.verify_password("0000", hashed))


class SessionManagerTests(unittest.TestCase):
    def test_rejects_malformed_and_future_activity_timestamps(self):
        manager = SessionManager(timeout_minutes=15)
        self.assertFalse(manager.is_session_valid({"last_activity": "not-a-date"}))
        self.assertFalse(manager.is_session_valid({"last_activity": datetime.now() + timedelta(minutes=1)}))

    def test_expires_old_session(self):
        manager = SessionManager(timeout_minutes=15)
        session = manager.create_session("1234567890")
        session["last_activity"] = datetime.now() - timedelta(minutes=16)
        self.assertFalse(manager.is_session_valid(session))


class InputValidatorTests(unittest.TestCase):
    def test_rejects_non_string_identifiers_and_non_finite_amounts(self):
        self.assertIn("string", InputValidator.validate_account_number(1234567890))
        self.assertIn("string", InputValidator.validate_pin(1234))
        for value in ("100", True, float("nan"), float("inf")):
            self.assertIn("finite", InputValidator.validate_amount(value))
        self.assertEqual(InputValidator.sanitize_text({"recipient": "Alice"}), "")


if __name__ == "__main__":
    unittest.main()
