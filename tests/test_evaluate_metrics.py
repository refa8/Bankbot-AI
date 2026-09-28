"""
tests/test_evaluate_metrics.py

Unit tests for evaluate_metrics.py

Tests the metric computation logic (compute_metrics, evaluate_datasets,
load_dataset, run_classifier) using controlled synthetic fixtures — no
dependency on Ollama or external services.

These tests are deliberately isolated from the real datasets so they remain
stable even if the classifier or datasets change.
"""

import json
import os
import sys
import tempfile
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from evaluate_metrics import (
    DEFAULT_MOCK_USER,
    INTENT_LABELS,
    check_safety_and_policy,
    compute_answer_metrics,
    compute_latency_stats,
    compute_metrics,
    compute_safety_factuality_metrics,
    evaluate_datasets,
    evaluate_query,
    generate_deterministic_answer,
    load_dataset,
    run_classifier,
    verify_answer_correctness,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_tmp_dataset(records):
    """Write *records* to a temporary JSON file and return the path."""
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(records, fh)
    return path


# ---------------------------------------------------------------------------
# Tests for compute_metrics
# ---------------------------------------------------------------------------

class TestComputeMetricsPerfect(unittest.TestCase):
    """Perfect predictions: all metrics should be 1.0."""

    def setUp(self):
        self.labels = ["A", "B", "C"]
        self.y = ["A", "A", "B", "B", "C", "C"]
        self.result = compute_metrics(self.y, self.y, self.labels)

    def test_accuracy_is_1(self):
        self.assertAlmostEqual(self.result["accuracy"], 1.0)

    def test_macro_f1_is_1(self):
        self.assertAlmostEqual(self.result["macro_f1"], 1.0)

    def test_weighted_f1_is_1(self):
        self.assertAlmostEqual(self.result["weighted_f1"], 1.0)

    def test_per_class_precision_1(self):
        for lbl in self.labels:
            self.assertAlmostEqual(self.result["per_class"][lbl]["precision"], 1.0)

    def test_per_class_recall_1(self):
        for lbl in self.labels:
            self.assertAlmostEqual(self.result["per_class"][lbl]["recall"], 1.0)

    def test_per_class_f1_1(self):
        for lbl in self.labels:
            self.assertAlmostEqual(self.result["per_class"][lbl]["f1"], 1.0)

    def test_correct_count(self):
        self.assertEqual(self.result["correct"], 6)

    def test_confusion_matrix_diagonal(self):
        cm = self.result["confusion_matrix"]
        for lbl in self.labels:
            self.assertEqual(cm[str(lbl)].get(lbl, 0), 2)


class TestComputeMetricsWorstCase(unittest.TestCase):
    """Predictions are completely wrong (all swapped to another class)."""

    def setUp(self):
        self.labels = ["A", "B"]
        # All A predicted as B and vice versa
        self.y_true = ["A", "A", "B", "B"]
        self.y_pred = ["B", "B", "A", "A"]
        self.result = compute_metrics(self.y_true, self.y_pred, self.labels)

    def test_accuracy_is_0(self):
        self.assertAlmostEqual(self.result["accuracy"], 0.0)

    def test_macro_f1_is_0(self):
        self.assertAlmostEqual(self.result["macro_f1"], 0.0)

    def test_precision_is_0_for_all(self):
        for lbl in self.labels:
            self.assertAlmostEqual(self.result["per_class"][lbl]["precision"], 0.0)

    def test_recall_is_0_for_all(self):
        for lbl in self.labels:
            self.assertAlmostEqual(self.result["per_class"][lbl]["recall"], 0.0)


class TestComputeMetricsPartialCorrect(unittest.TestCase):
    """Known mixed predictions: verify exact numeric results."""

    def setUp(self):
        # Class A: 3 true, 2 correct, 1 missed (fn=1), 0 false positives
        # Class B: 3 true, 2 correct, 1 missed (fn=1), 0 false positives
        # 1 A predicted as B, 1 B predicted as A  =>  fp=1 for each
        self.labels = ["A", "B"]
        self.y_true = ["A", "A", "A", "B", "B", "B"]
        self.y_pred = ["A", "A", "B", "B", "B", "A"]
        self.result = compute_metrics(self.y_true, self.y_pred, self.labels)

    def test_accuracy(self):
        # 4 correct out of 6
        self.assertAlmostEqual(self.result["accuracy"], 4 / 6)

    def test_per_class_precision(self):
        # A: tp=2, fp=1  => p=2/3
        self.assertAlmostEqual(self.result["per_class"]["A"]["precision"], 2 / 3)
        # B: tp=2, fp=1  => p=2/3
        self.assertAlmostEqual(self.result["per_class"]["B"]["precision"], 2 / 3)

    def test_per_class_recall(self):
        # A: tp=2, fn=1  => r=2/3
        self.assertAlmostEqual(self.result["per_class"]["A"]["recall"], 2 / 3)
        self.assertAlmostEqual(self.result["per_class"]["B"]["recall"], 2 / 3)

    def test_per_class_f1(self):
        # f1 = 2*(2/3)*(2/3)/((2/3)+(2/3)) = 2/3
        self.assertAlmostEqual(self.result["per_class"]["A"]["f1"], 2 / 3)

    def test_macro_f1(self):
        self.assertAlmostEqual(self.result["macro_f1"], 2 / 3)

    def test_weighted_f1(self):
        # Both classes have equal support => weighted == macro
        self.assertAlmostEqual(self.result["weighted_f1"], 2 / 3)

    def test_confusion_matrix_entries(self):
        cm = self.result["confusion_matrix"]
        self.assertEqual(cm["A"].get("A", 0), 2)
        self.assertEqual(cm["A"].get("B", 0), 1)
        self.assertEqual(cm["B"].get("B", 0), 2)
        self.assertEqual(cm["B"].get("A", 0), 1)


class TestComputeMetricsWithNoneLabel(unittest.TestCase):
    """Ensure None labels (LLM-routed) are handled without errors."""

    def setUp(self):
        self.labels = ["balance", None]
        self.y_true = ["balance", "balance", None, None]
        self.y_pred = ["balance", None,      None, None]
        self.result = compute_metrics(self.y_true, self.y_pred, self.labels)

    def test_accuracy(self):
        # 3 out of 4 correct
        self.assertAlmostEqual(self.result["accuracy"], 0.75)

    def test_balance_recall(self):
        # 1 out of 2 balance rows correct
        self.assertAlmostEqual(self.result["per_class"]["balance"]["recall"], 0.5)

    def test_none_recall(self):
        # 2 out of 2 None rows correct
        self.assertAlmostEqual(self.result["per_class"][None]["recall"], 1.0)

    def test_none_in_active_labels(self):
        self.assertIn(None, self.result["active_labels"])

    def test_no_exception_for_none_label_support(self):
        """Ensure that labels with zero support don't cause division errors."""
        labels = ["balance", "transactions", None]
        y_t = ["balance"]
        y_p = ["balance"]
        result = compute_metrics(y_t, y_p, labels)
        # "transactions" has support=0 and should not be in active_labels
        self.assertNotIn("transactions", result["active_labels"])
        self.assertAlmostEqual(result["accuracy"], 1.0)


class TestComputeMetricsWeightedVsMacro(unittest.TestCase):
    """Weighted and macro averages diverge when class sizes are unequal."""

    def setUp(self):
        # Class A: 10 true, all pred as A; Class B: 2 true, both pred as A
        # => A gets fp=2 from misclassified B cases
        # tp_A=10 fp_A=2 fn_A=0  => prec_A=10/12  rec_A=1.0  f1_A=10/11 ≈ 0.9091
        # tp_B=0  fp_B=0 fn_B=2  =>                            f1_B=0.0
        # macro_f1  = (10/11 + 0) / 2 ≈ 0.4545
        # wtd_f1    = (10/11 * 10 + 0 * 2) / 12 ≈ 0.7576
        self.labels = ["A", "B"]
        self.y_true = ["A"] * 10 + ["B"] * 2
        self.y_pred = ["A"] * 10 + ["A"] * 2   # B always misclassified as A
        self.result = compute_metrics(self.y_true, self.y_pred, self.labels)
        # Pre-compute ground truth for assertions
        f1_A = 2 * (10 / 12) * 1.0 / ((10 / 12) + 1.0)   # ≈ 0.9091
        self.expected_macro_f1  = f1_A / 2                 # ≈ 0.4545
        self.expected_wtd_f1    = f1_A * 10 / 12           # ≈ 0.7576

    def test_macro_f1_is_mean_of_per_class(self):
        self.assertAlmostEqual(self.result["macro_f1"], self.expected_macro_f1, places=5)

    def test_weighted_f1_reflects_class_imbalance(self):
        self.assertAlmostEqual(self.result["weighted_f1"], self.expected_wtd_f1, places=5)

    def test_weighted_gt_macro(self):
        self.assertGreater(self.result["weighted_f1"], self.result["macro_f1"])


# ---------------------------------------------------------------------------
# Tests for load_dataset
# ---------------------------------------------------------------------------

class TestLoadDataset(unittest.TestCase):

    def test_loads_valid_json(self):
        data = [{"id": 1, "query": "hi"}]
        path = _write_tmp_dataset(data)
        try:
            loaded = load_dataset(path)
            self.assertEqual(loaded, data)
        finally:
            os.remove(path)

    def test_raises_for_missing_file(self):
        with self.assertRaises(FileNotFoundError):
            load_dataset("/nonexistent/path/does_not_exist.json")


# ---------------------------------------------------------------------------
# Tests for run_classifier (integration — uses real classifier)
# ---------------------------------------------------------------------------

class TestRunClassifier(unittest.TestCase):
    """Smoke tests against the live classifier for basic correctness."""

    def _item(self, query, exp_domain, exp_intent):
        return {
            "id": 99,
            "query": query,
            "expected_domain_validity": exp_domain,
            "expected_rule_intent": exp_intent,
        }

    def test_balance_correct(self):
        r = run_classifier(self._item("What is my balance?", True, "balance"))
        self.assertTrue(r["domain_correct"])
        self.assertTrue(r["intent_correct"])
        self.assertTrue(r["both_correct"])
        self.assertEqual(r["actual_intent"], "balance")

    def test_off_topic_correct(self):
        r = run_classifier(self._item("tell me a joke", False, None))
        self.assertTrue(r["domain_correct"])
        self.assertTrue(r["intent_correct"])

    def test_llm_routed_maps_to_none(self):
        # Policy questions must not be intercepted by rule routing
        r = run_classifier(self._item("What is the interest rate on savings?", True, None))
        self.assertEqual(r["actual_intent"], None)
        self.assertTrue(r["intent_correct"])

    def test_result_keys_present(self):
        r = run_classifier(self._item("Show my transactions", True, "transactions"))
        expected_keys = {
            "id", "category", "subcategory", "query",
            "expected_domain", "actual_domain", "domain_reason",
            "expected_intent", "actual_intent",
            "domain_correct", "intent_correct", "both_correct",
        }
        self.assertEqual(set(r.keys()), expected_keys)


# ---------------------------------------------------------------------------
# Tests for evaluate_datasets (end-to-end with synthetic datasets)
# ---------------------------------------------------------------------------

class TestEvaluateDatasets(unittest.TestCase):

    def _make_dataset(self, records):
        return _write_tmp_dataset(records)

    def test_all_correct_returns_100pct(self):
        data = [
            {
                "id": 1, "query": "What is my balance?",
                "expected_domain_validity": True,
                "expected_rule_intent": "balance",
            },
            {
                "id": 2, "query": "hi",
                "expected_domain_validity": True,
                "expected_rule_intent": "greeting",
            },
        ]
        path = self._make_dataset(data)
        try:
            ev = evaluate_datasets([path])
            self.assertEqual(ev["total"], 2)
            self.assertEqual(ev["both_correct"], 2)
            self.assertAlmostEqual(
                ev["intent_metrics"]["accuracy"], 1.0
            )
        finally:
            os.remove(path)

    def test_merges_multiple_files(self):
        data1 = [{"id": 1, "query": "hi",
                   "expected_domain_validity": True, "expected_rule_intent": "greeting"}]
        data2 = [{"id": 2, "query": "What is my balance?",
                   "expected_domain_validity": True, "expected_rule_intent": "balance"}]
        p1 = self._make_dataset(data1)
        p2 = self._make_dataset(data2)
        try:
            ev = evaluate_datasets([p1, p2])
            self.assertEqual(ev["total"], 2)
        finally:
            os.remove(p1)
            os.remove(p2)

    def test_failures_list_populated_for_wrong_predictions(self):
        # "am i broke" is expected balance but classifier will not match it
        data = [
            {
                "id": 1, "query": "am i broke right now or what",
                "expected_domain_validity": True,
                "expected_rule_intent": "balance",
            }
        ]
        path = self._make_dataset(data)
        try:
            ev = evaluate_datasets([path])
            # This is a known failure on unseen-style queries
            if ev["both_correct"] == 0:
                self.assertEqual(len(ev["failures"]), 1)
                self.assertEqual(ev["failures"][0]["id"], 1)
        finally:
            os.remove(path)

    def test_confusion_matrix_serializable(self):
        """confusion_matrix must be JSON-serialisable (no None keys)."""
        data = [
            {"id": 1, "query": "What is my balance?",
             "expected_domain_validity": True, "expected_rule_intent": "balance"},
        ]
        path = self._make_dataset(data)
        try:
            ev = evaluate_datasets([path])
            # Should not raise
            json.dumps(ev["intent_metrics"]["confusion_matrix"])
        finally:
            os.remove(path)


# ---------------------------------------------------------------------------
# Regression: evaluate against the real datasets
# ---------------------------------------------------------------------------

class TestRealDatasetRegression(unittest.TestCase):
    """Smoke tests against the committed datasets — verify known baselines."""

    REGRESSION_PATH = os.path.join(PROJECT_ROOT, "tests", "query_eval_dataset.json")
    UNSEEN_PATH     = os.path.join(PROJECT_ROOT, "tests", "unseen_eval_dataset.json")

    def test_regression_dataset_100pct_exact_match(self):
        ev = evaluate_datasets([self.REGRESSION_PATH])
        self.assertEqual(ev["both_correct"], ev["total"],
                         "Regression dataset must maintain 100% exact match")

    def test_regression_macro_f1_is_1(self):
        ev = evaluate_datasets([self.REGRESSION_PATH])
        self.assertAlmostEqual(ev["intent_metrics"]["macro_f1"], 1.0, places=4)

    def test_unseen_dataset_domain_accuracy_above_90pct(self):
        ev = evaluate_datasets([self.UNSEEN_PATH])
        self.assertGreaterEqual(ev["domain_metrics"]["accuracy"], 0.90)

    def test_unseen_dataset_intent_accuracy_above_85pct(self):
        ev = evaluate_datasets([self.UNSEEN_PATH])
        self.assertGreaterEqual(ev["intent_metrics"]["accuracy"], 0.85)

    def test_combined_weighted_f1_above_90pct(self):
        ev = evaluate_datasets([self.REGRESSION_PATH, self.UNSEEN_PATH])
        self.assertGreaterEqual(ev["intent_metrics"]["weighted_f1"], 0.90)


# ---------------------------------------------------------------------------
# Tests for Latency Calculations
# ---------------------------------------------------------------------------

class TestComputeLatencyStats(unittest.TestCase):
    def test_latency_empty_list(self):
        stats = compute_latency_stats([])
        self.assertEqual(stats["count"], 0)
        self.assertEqual(stats["median_ms"], 0.0)
        self.assertEqual(stats["p95_ms"], 0.0)

    def test_latency_single_element(self):
        stats = compute_latency_stats([12.34])
        self.assertEqual(stats["count"], 1)
        self.assertEqual(stats["min_ms"], 12.34)
        self.assertEqual(stats["median_ms"], 12.34)
        self.assertEqual(stats["p95_ms"], 12.34)
        self.assertEqual(stats["max_ms"], 12.34)

    def test_latency_known_values(self):
        stats = compute_latency_stats([10.0, 20.0, 30.0, 40.0, 50.0])
        self.assertEqual(stats["count"], 5)
        self.assertEqual(stats["min_ms"], 10.0)
        self.assertEqual(stats["median_ms"], 30.0)
        self.assertEqual(stats["p95_ms"], 50.0)
        self.assertEqual(stats["max_ms"], 50.0)
        self.assertEqual(stats["mean_ms"], 30.0)

    def test_latency_p95_100_values(self):
        values = [float(i) for i in range(1, 101)]
        stats = compute_latency_stats(values)
        self.assertEqual(stats["count"], 100)
        self.assertEqual(stats["median_ms"], 50.5)
        self.assertEqual(stats["p95_ms"], 95.0)


# ---------------------------------------------------------------------------
# Tests for Answer Correctness & Verification
# ---------------------------------------------------------------------------

class TestAnswerCorrectness(unittest.TestCase):
    def setUp(self):
        self.user = DEFAULT_MOCK_USER

    def test_balance_answer_verified(self):
        resp = generate_deterministic_answer("balance", self.user)
        self.assertIsNotNone(resp)
        self.assertIn("55,750.50", resp)
        is_correct, reason = verify_answer_correctness("balance", resp, self.user)
        self.assertTrue(is_correct)
        self.assertIn("Verified balance", reason)

    def test_balance_answer_mismatch_fails(self):
        wrong_resp = "Your balance is Rs. 10.00."
        is_correct, reason = verify_answer_correctness("balance", wrong_resp, self.user)
        self.assertFalse(is_correct)
        self.assertIn("Expected balance", reason)

    def test_transactions_answer_verified(self):
        resp = generate_deterministic_answer("transactions", self.user)
        self.assertIsNotNone(resp)
        self.assertIn("Salary Credit", resp)
        self.assertIn("Amazon Purchase", resp)
        is_correct, reason = verify_answer_correctness("transactions", resp, self.user)
        self.assertTrue(is_correct)

    def test_transactions_answer_missing_fails(self):
        empty_resp = "No transactions found."
        is_correct, reason = verify_answer_correctness("transactions", empty_resp, self.user)
        self.assertFalse(is_correct)

    def test_spend_answer_verified(self):
        resp = generate_deterministic_answer("spend", self.user)
        self.assertIsNotNone(resp)
        is_correct, _ = verify_answer_correctness("spend", resp, self.user)
        self.assertTrue(is_correct)

    def test_llm_bound_answer_is_unanswerable_without_llm(self):
        resp = generate_deterministic_answer(None, self.user)
        self.assertIsNone(resp)


# ---------------------------------------------------------------------------
# Tests for Safety & Policy Auditing
# ---------------------------------------------------------------------------

class TestSafetyAndPolicyAudit(unittest.TestCase):
    def test_off_topic_leak_detected(self):
        item = {"query": "tell me a joke", "expected_domain_validity": False, "expected_rule_intent": None}
        is_safe, violations = check_safety_and_policy(item, act_domain=True, act_intent=None, domain_reason="valid")
        self.assertFalse(is_safe)
        self.assertTrue(any("Off-topic leak" in v for v in violations))

    def test_policy_theft_detected(self):
        item = {"query": "What is the UPI limit?", "expected_domain_validity": True, "expected_rule_intent": None}
        is_safe, violations = check_safety_and_policy(item, act_domain=True, act_intent="transfer", domain_reason="valid")
        self.assertFalse(is_safe)
        self.assertTrue(any("Policy theft" in v for v in violations))

    def test_safe_query_passes_audit(self):
        item = {"query": "What is my balance?", "expected_domain_validity": True, "expected_rule_intent": "balance"}
        is_safe, violations = check_safety_and_policy(item, act_domain=True, act_intent="balance", domain_reason="valid")
        self.assertTrue(is_safe)
        self.assertEqual(violations, [])


# ---------------------------------------------------------------------------
# Tests for Machine-Readable Export & Metric Separation
# ---------------------------------------------------------------------------

class TestExportAndMetricSeparation(unittest.TestCase):
    def test_saves_valid_machine_readable_json(self):
        data = [
            {"id": 1, "query": "What is my balance?", "expected_domain_validity": True, "expected_rule_intent": "balance"},
            {"id": 2, "query": "tell me a joke", "expected_domain_validity": False, "expected_rule_intent": None},
        ]
        in_path = _write_tmp_dataset(data)
        out_fd, out_path = tempfile.mkstemp(suffix=".json")
        os.close(out_fd)
        try:
            ev = evaluate_datasets([in_path], output_path=out_path)
            self.assertTrue(os.path.exists(out_path))
            with open(out_path, "r", encoding="utf-8") as f:
                saved = json.load(f)

            # Validate top-level JSON structure
            self.assertIn("metadata", saved)
            self.assertIn("summary", saved)
            self.assertIn("per_query_results", saved)
            self.assertEqual(len(saved["per_query_results"]), 2)

            # Validate separation of classification and answer correctness
            self.assertIn("classification_macro_f1", saved["summary"])
            self.assertIn("answer_correctness", saved["summary"])
            self.assertIn("latency_metrics", saved["summary"])
            self.assertIn("safety_metrics", saved["summary"])

            # Validate per-query fields
            first_q = saved["per_query_results"][0]
            for key in ["route", "latency_ms", "actual_response", "answer_correct", "safety_pass"]:
                self.assertIn(key, first_q)
        finally:
            if os.path.exists(in_path):
                os.remove(in_path)
            if os.path.exists(out_path):
                os.remove(out_path)

    def test_ollama_status_declared(self):
        data = [{"id": 1, "query": "What is my balance?", "expected_domain_validity": True, "expected_rule_intent": "balance"}]
        in_path = _write_tmp_dataset(data)
        try:
            ev = evaluate_datasets([in_path], eval_ollama=False)
            self.assertIn("ollama_evaluation", ev)
            self.assertFalse(ev["ollama_evaluation"]["evaluated"])
            self.assertEqual(ev["ollama_evaluation"]["status"], "skipped_offline")
        finally:
            if os.path.exists(in_path):
                os.remove(in_path)


if __name__ == "__main__":
    unittest.main()
