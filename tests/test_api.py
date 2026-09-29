"""
tests/test_api.py

Unit and integration tests for BankBot REST API.
Verifies authentication, session tokens, balance endpoint, transaction endpoint,
rate limiting, input validation, and account data isolation.
"""

import json
import os
import tempfile
import unittest

from app.api import create_app
from security import PasswordHasher


class BankBotAPITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.hasher = PasswordHasher()
        cls.test_db_data = {
            "1234567890": {
                "name": "Test User 1",
                "hashed_pin": cls.hasher.hash_password("0000"),
                "balance": 50000.0,
                "type": "Savings",
                "credit_score": 780,
                "transactions": [
                    {"date": "2026-01-10", "desc": "Salary", "cat": "Income", "amt": 25000, "type": "Credit"},
                    {"date": "2026-01-11", "desc": "Groceries", "cat": "Food", "amt": -1500, "type": "Debit"},
                    {"date": "2026-01-12", "desc": "Utilities", "cat": "Bills", "amt": -3000, "type": "Debit"},
                ]
            },
            "0987654321": {
                "name": "Test User 2",
                "hashed_pin": cls.hasher.hash_password("1111"),
                "balance": 120000.0,
                "type": "Current",
                "credit_score": 810,
                "transactions": [
                    {"date": "2026-01-08", "desc": "Consulting Fee", "cat": "Income", "amt": 60000, "type": "Credit"}
                ]
            }
        }

    def setUp(self):
        # Create temporary database file for test isolation
        self.temp_db_fd, self.temp_db_path = tempfile.mkstemp(suffix=".json")
        os.close(self.temp_db_fd)
        with open(self.temp_db_path, "w", encoding="utf-8") as f:
            json.dump(self.test_db_data, f)

        self.app = create_app(db_file=self.temp_db_path)
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def tearDown(self):
        if os.path.exists(self.temp_db_path):
            os.remove(self.temp_db_path)

    def _login(self, account="1234567890", pin="0000"):
        return self.client.post(
            "/api/login",
            data=json.dumps({"account": account, "pin": pin}),
            content_type="application/json"
        )

    def test_health_endpoint(self):
        resp = self.client.get("/api/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data.get("status"), "healthy")

    def test_unknown_route_and_wrong_method_return_json_errors(self):
        unknown = self.client.get("/api/does-not-exist")
        self.assertEqual(unknown.status_code, 404)
        self.assertIsInstance(unknown.get_json(), dict)

        wrong_method = self.client.get("/api/login")
        self.assertEqual(wrong_method.status_code, 405)
        self.assertIsInstance(wrong_method.get_json(), dict)

    def test_login_success(self):
        resp = self._login()
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("token", data)
        self.assertEqual(data.get("account"), "1234567890")
        self.assertEqual(data.get("name"), "Test User 1")

    def test_login_invalid_pin(self):
        resp = self._login(pin="9999")
        self.assertEqual(resp.status_code, 401)
        data = resp.get_json()
        self.assertIn("error", data)

    def test_login_invalid_account_format(self):
        resp = self._login(account="123", pin="0000")
        self.assertEqual(resp.status_code, 400)
        data = resp.get_json()
        self.assertIn("error", data)

    def test_login_invalid_pin_format(self):
        resp = self._login(account="1234567890", pin="12")
        self.assertEqual(resp.status_code, 400)
        data = resp.get_json()
        self.assertIn("error", data)

    def test_login_rejects_non_string_credentials(self):
        resp = self.client.post(
            "/api/login",
            data=json.dumps({"account": 1234567890, "pin": 0}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("string", resp.get_json()["error"])

    def test_login_rate_limiting_lockout(self):
        # Attempt failed logins up to the max threshold (5 attempts)
        for _ in range(5):
            self._login(pin="9999")
        # 6th attempt should be locked out with 429
        resp = self._login(pin="9999")
        self.assertEqual(resp.status_code, 429)
        data = resp.get_json()
        self.assertIn("locked", data.get("error", "").lower())

    def test_successful_login_resets_prior_failed_attempts(self):
        for _ in range(4):
            self.assertEqual(self._login(pin="9999").status_code, 401)

        self.assertEqual(self._login().status_code, 200)

        for _ in range(5):
            self.assertEqual(self._login(pin="9999").status_code, 401)
        self.assertEqual(self._login(pin="9999").status_code, 429)

    def test_get_balance_authenticated(self):
        login_resp = self._login()
        token = login_resp.get_json()["token"]

        headers = {"Authorization": f"Bearer {token}"}
        resp = self.client.get("/api/balance", headers=headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data.get("account"), "1234567890")
        self.assertEqual(data.get("balance"), 50000.0)
        self.assertEqual(data.get("currency"), "INR")

    def test_get_balance_missing_token(self):
        resp = self.client.get("/api/balance")
        self.assertEqual(resp.status_code, 401)

    def test_get_balance_invalid_token(self):
        headers = {"Authorization": "Bearer non-existent-token"}
        resp = self.client.get("/api/balance", headers=headers)
        self.assertEqual(resp.status_code, 401)

    def test_get_transactions_authenticated(self):
        login_resp = self._login()
        token = login_resp.get_json()["token"]

        headers = {"Authorization": f"Bearer {token}"}
        resp = self.client.get("/api/transactions", headers=headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data.get("account"), "1234567890")
        self.assertEqual(len(data.get("transactions", [])), 3)

    def test_get_transactions_with_limit(self):
        login_resp = self._login()
        token = login_resp.get_json()["token"]

        headers = {"Authorization": f"Bearer {token}"}
        resp = self.client.get("/api/transactions?limit=2", headers=headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(len(data.get("transactions", [])), 2)

    def test_get_transactions_rejects_invalid_limit(self):
        token = self._login().get_json()["token"]
        headers = {"Authorization": f"Bearer {token}"}

        for limit in ("zero", "0", "-2"):
            resp = self.client.get(f"/api/transactions?limit={limit}", headers=headers)
            self.assertEqual(resp.status_code, 400)

    def test_get_transactions_filters_an_inclusive_date_range(self):
        token = self._login().get_json()["token"]
        headers = {"Authorization": f"Bearer {token}"}
        resp = self.client.get(
            "/api/transactions?start_date=2026-01-11&end_date=2026-01-12",
            headers=headers,
        )
        self.assertEqual(resp.status_code, 200)
        payload = resp.get_json()
        self.assertEqual(payload["total_transactions"], 3)
        self.assertEqual(payload["filtered_transactions"], 2)
        self.assertEqual([item["desc"] for item in payload["transactions"]], ["Groceries", "Utilities"])

    def test_get_transactions_rejects_malformed_or_reversed_dates(self):
        token = self._login().get_json()["token"]
        headers = {"Authorization": f"Bearer {token}"}
        for query in ("start_date=2026-99-01", "start_date=2026-01-12&end_date=2026-01-11"):
            resp = self.client.get(f"/api/transactions?{query}", headers=headers)
            self.assertEqual(resp.status_code, 400)

    def test_transfer_requires_authentication(self):
        resp = self.client.post("/api/transfers", json={"recipient": "Alice", "amount": 100})
        self.assertEqual(resp.status_code, 401)

    def test_transfer_persists_balance_and_transaction(self):
        token = self._login().get_json()["token"]
        headers = {"Authorization": f"Bearer {token}"}

        resp = self.client.post(
            "/api/transfers",
            json={"recipient": "<Alice>", "amount": 1234.5},
            headers=headers,
        )
        self.assertEqual(resp.status_code, 201)
        data = resp.get_json()
        self.assertEqual(data["recipient"], "Alice")
        self.assertEqual(data["balance"], 48765.5)
        self.assertEqual(data["transaction"]["amt"], -1234.5)

        with open(self.temp_db_path, encoding="utf-8") as f:
            stored = json.load(f)["1234567890"]
        self.assertEqual(stored["balance"], 48765.5)
        self.assertEqual(stored["transactions"][0], data["transaction"])

    def test_invalid_transfers_do_not_change_account_state(self):
        token = self._login().get_json()["token"]
        headers = {"Authorization": f"Bearer {token}"}
        before = self.client.get("/api/balance", headers=headers).get_json()["balance"]

        invalid_requests = (
            {"recipient": "Alice", "amount": "100"},
            {"recipient": "Alice", "amount": float("nan")},
            {"recipient": "Alice", "amount": 50000.01},
            {"recipient": "", "amount": 100},
        )
        for payload in invalid_requests:
            resp = self.client.post("/api/transfers", json=payload, headers=headers)
            self.assertEqual(resp.status_code, 400)

        after = self.client.get("/api/balance", headers=headers).get_json()["balance"]
        self.assertEqual(after, before)
        with open(self.temp_db_path, encoding="utf-8") as f:
            self.assertEqual(json.load(f)["1234567890"]["balance"], before)

    def test_insufficient_funds_transfer_does_not_change_balance(self):
        token = self._login().get_json()["token"]
        headers = {"Authorization": f"Bearer {token}"}
        with open(self.temp_db_path, encoding="utf-8") as f:
            db = json.load(f)
        db["1234567890"]["balance"] = 100.0
        with open(self.temp_db_path, "w", encoding="utf-8") as f:
            json.dump(db, f)

        resp = self.client.post(
            "/api/transfers", json={"recipient": "Alice", "amount": 200}, headers=headers
        )
        self.assertEqual(resp.status_code, 409)
        with open(self.temp_db_path, encoding="utf-8") as f:
            self.assertEqual(json.load(f)["1234567890"]["balance"], 100.0)

    def test_account_data_isolation(self):
        # User 1 token cannot see User 2's data
        login1 = self._login("1234567890", "0000").get_json()
        login2 = self._login("0987654321", "1111").get_json()

        headers1 = {"Authorization": f"Bearer {login1['token']}"}
        headers2 = {"Authorization": f"Bearer {login2['token']}"}

        bal1 = self.client.get("/api/balance", headers=headers1).get_json()
        bal2 = self.client.get("/api/balance", headers=headers2).get_json()

        self.assertEqual(bal1["account"], "1234567890")
        self.assertEqual(bal1["balance"], 50000.0)

        self.assertEqual(bal2["account"], "0987654321")
        self.assertEqual(bal2["balance"], 120000.0)

    def test_logout_invalidates_session(self):
        login_resp = self._login()
        token = login_resp.get_json()["token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Verify access before logout
        resp1 = self.client.get("/api/balance", headers=headers)
        self.assertEqual(resp1.status_code, 200)

        # Logout
        logout_resp = self.client.post("/api/logout", headers=headers)
        self.assertEqual(logout_resp.status_code, 200)

        # Verify token is now rejected
        resp2 = self.client.get("/api/balance", headers=headers)
        self.assertEqual(resp2.status_code, 401)

    def test_expired_session_requires_a_new_login(self):
        expiring_app = create_app(db_file=self.temp_db_path, session_timeout_minutes=0)
        expiring_app.config["TESTING"] = True
        expiring_client = expiring_app.test_client()
        login = expiring_client.post("/api/login", json={"account": "1234567890", "pin": "0000"})
        token = login.get_json()["token"]
        expired = expiring_client.get("/api/balance", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(expired.status_code, 401)

        normal_login = self._login()
        self.assertEqual(normal_login.status_code, 200)


if __name__ == "__main__":
    unittest.main()
