"""Tests for the end-to-end component benchmark; no live Ollama required."""
import json
import os
import tempfile
import unittest

from e2e_benchmark import (
    binary_metrics,
    evaluate_chatbot,
    evaluate_reliability,
    evaluate_rest_api,
    evaluate_security,
    evaluate_transfers,
    run_benchmark,
    score_reference_answer,
    simulate_transfer,
)
from evaluate_metrics import DEFAULT_MOCK_USER


class EndToEndBenchmarkTests(unittest.TestCase):
    def test_reference_scoring_requires_explicit_criteria(self):
        criteria = {"required_any_groups": [["100,000"], ["daily"]]}
        self.assertTrue(score_reference_answer("The daily limit is 100,000.", criteria)["correct"])
        self.assertFalse(score_reference_answer("The limit is 50,000.", criteria)["correct"])
        self.assertIsNone(score_reference_answer(None, criteria)["correct"])

    def test_binary_metrics_keeps_unscored_out_of_denominator(self):
        result = binary_metrics([True, True, False], [True, None, False])
        self.assertEqual(result["evaluated"], 2)
        self.assertEqual(result["unscored"], 1)
        self.assertEqual(result["accuracy"], 1.0)

    def test_transfer_failure_does_not_change_mock_state(self):
        result = simulate_transfer(DEFAULT_MOCK_USER, "Alice", 50000.01)
        self.assertFalse(result["success"])
        self.assertTrue(result["balance_unchanged"])
        self.assertTrue(result["transactions_unchanged"])

    def test_transfer_contract_includes_valid_invalid_and_boundary_cases(self):
        result = evaluate_transfers()
        self.assertEqual(len(result["records"]), 8)
        self.assertEqual(result["task_success"]["failed"], 0)
        self.assertEqual(result["latency"]["count"], 8)

    def test_rest_api_checks_response_state_and_expired_token(self):
        result = evaluate_rest_api()
        records = {record["name"]: record for record in result["records"]}
        self.assertTrue(records["balance"]["response_valid"])
        self.assertTrue(records["transactions"]["response_valid"])
        self.assertEqual(records["expired_after_logout"]["status"], 401)
        self.assertFalse(result["transfer_endpoint_available"])
        self.assertIn("/api/balance", result["latency"]["by_endpoint"])

    def test_security_checks_include_account_isolation_and_input_validation(self):
        result = evaluate_security()
        self.assertEqual(result["pass_rate"]["failed"], 0)
        names = {check["name"] for check in result["checks"]}
        self.assertIn("account_isolation", names)
        self.assertIn("over_limit_transfer_rejected", names)

    def test_reliability_checks_do_not_claim_external_ollama_execution(self):
        result = evaluate_reliability()
        self.assertTrue(result["checks"]["session_expiration"])
        self.assertIsNone(result["checks"]["ollama_failure_modes"])

    def test_mocked_ollama_success_is_semantically_scored(self):
        def runner(prompt):
            prompt_lower = prompt.split("USER QUESTION:", 1)[1].lower()
            if "upi" in prompt_lower:
                response = "The daily UPI limit is Rs. 1,00,000."
            elif "branch operating" in prompt_lower:
                response = "Branches operate Monday to Saturday from 9:30 AM to 4:00 PM."
            else:
                response = "I cannot help bypass account security."
            return {"status": "success", "response": response, "error": None,
                    "time_to_first_token_ms": 10.0, "generation_latency_ms": 20.0}
        result = evaluate_chatbot(runner)
        self.assertEqual(result["llm_semantic_accuracy"]["evaluated"], 3)
        self.assertEqual(result["llm_semantic_accuracy"]["succeeded"], 3)

    def test_mocked_ollama_failure_is_not_a_correct_answer(self):
        result = evaluate_chatbot(lambda prompt: {"status": "timeout", "response": None, "error": "timeout",
                                                  "time_to_first_token_ms": None, "generation_latency_ms": 1.0})
        self.assertEqual(result["llm_semantic_accuracy"]["evaluated"], 0)
        self.assertEqual(result["llm_semantic_accuracy"]["unscored"], 3)

    def test_json_report_is_machine_readable(self):
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        try:
            report = run_benchmark(path)
            with open(path, encoding="utf-8") as handle:
                saved = json.load(handle)
            self.assertEqual(saved["metadata"]["live_ollama_executed"], False)
            self.assertEqual(report["rest_api"]["transfer_endpoint_available"], False)
        finally:
            if os.path.exists(path):
                os.remove(path)


if __name__ == "__main__":
    unittest.main()
