"""Regression coverage for authoritative deterministic account responses."""

from datetime import date
import unittest

from app.services.account_responses import balance_response, transactions_response


class AccountResponseTests(unittest.TestCase):
    def setUp(self):
        self.user = {
            "balance": 100.0,
            "type": "Savings",
            "credit_score": 720,
            "transactions": [
                {"date": "2024-12-05", "desc": "Card payment", "cat": "Food", "amt": -100.0, "type": "Debit"},
                {"date": "2024-12-03", "desc": "Refund", "cat": "Shopping", "amt": 100.0, "type": "Credit"},
                {"date": "2024-12-01", "desc": "Cash withdrawal", "cat": "Cash", "amt": -100.0, "type": "Debit"},
            ],
        }

    def test_balance_uses_the_supplied_user_including_zero_and_negative_values(self):
        self.assertIn("Rs. 100.00", balance_response(self.user))
        self.assertIn("Rs. 0.00", balance_response({**self.user, "balance": 0.0}))
        self.assertIn("Rs. -12.50", balance_response({**self.user, "balance": -12.5}))

    def test_transaction_limit_and_order_preserve_similar_amount_records(self):
        response = transactions_response(self.user, "show my latest 2 transactions")
        self.assertIn("Card payment", response)
        self.assertIn("Refund", response)
        self.assertNotIn("Cash withdrawal", response)
        self.assertLess(response.index("Card payment"), response.index("Refund"))
        self.assertEqual(response.count("Rs. -100.00"), 1)
        self.assertEqual(response.count("Rs. 100.00"), 1)

    def test_transaction_date_filters_are_inclusive_and_do_not_reorder_records(self):
        response = transactions_response(
            self.user,
            "show transactions from 2024-12-01 to 2024-12-03",
        )
        self.assertIn("Refund", response)
        self.assertIn("Cash withdrawal", response)
        self.assertNotIn("Card payment", response)
        self.assertLess(response.index("Refund"), response.index("Cash withdrawal"))

    def test_relative_date_and_malformed_range_are_explicit(self):
        response = transactions_response(self.user, "show transactions last week", today=date(2024, 12, 10))
        self.assertIn("2024-12-02 to 2024-12-08", response)
        self.assertIn("Card payment", response)
        malformed = transactions_response(self.user, "show transactions from 2024-12-05 to someday")
        self.assertIn("clearer transaction date range", malformed)

    def test_empty_history_does_not_invent_transactions(self):
        response = transactions_response({**self.user, "transactions": []}, "show transactions")
        self.assertIn("last 0", response)
        self.assertIn("No transactions matched", response)


if __name__ == "__main__":
    unittest.main()
