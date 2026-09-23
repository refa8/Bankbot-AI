"""
evaluate_query_policy.py

Reproducible evaluation benchmark for BankBot's hybrid query classification system.
Evaluates query domain gating (is_banking_query) and rule-intent routing (classify_rule_intent).
Does NOT call Ollama or any external network services.
"""

import json
import os
import sys
from collections import defaultdict
from typing import Any, Dict, List, Optional

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app.services.query_policy import classify_rule_intent, is_banking_query

DATASET_PATH = os.path.join(PROJECT_ROOT, "tests", "query_eval_dataset.json")


def load_dataset(path: str) -> List[Dict[str, Any]]:
    if not os.path.exists(path):
        raise FileNotFoundError(f"Evaluation dataset not found at: {path}")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def evaluate_benchmark(dataset: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    if dataset is None:
        dataset = load_dataset(DATASET_PATH)

    total_cases = len(dataset)
    domain_correct = 0
    intent_correct = 0
    both_correct = 0
    failures = []

    category_stats = defaultdict(lambda: {"total": 0, "domain_correct": 0, "intent_correct": 0, "both_correct": 0})

    for item in dataset:
        case_id = item["id"]
        category = item.get("category", "uncategorized")
        query = item["query"]
        expected_domain = item["expected_domain_validity"]
        expected_intent = item["expected_rule_intent"]

        # 1. Evaluate Domain Gating
        actual_domain, domain_reason = is_banking_query(query)
        domain_match = (actual_domain == expected_domain)

        # 2. Evaluate Rule Intent
        # classify_rule_intent returns 'llm' when no deterministic rule matches.
        # expected_rule_intent is None for LLM-bound queries and off-topic queries.
        raw_intent = classify_rule_intent(query)
        actual_intent = None if raw_intent == "llm" else raw_intent
        intent_match = (actual_intent == expected_intent)

        # Update counters
        category_stats[category]["total"] += 1
        if domain_match:
            domain_correct += 1
            category_stats[category]["domain_correct"] += 1
        if intent_match:
            intent_correct += 1
            category_stats[category]["intent_correct"] += 1
        if domain_match and intent_match:
            both_correct += 1
            category_stats[category]["both_correct"] += 1
        else:
            mismatches = []
            if not domain_match:
                mismatches.append("Domain Gating")
            if not intent_match:
                mismatches.append("Rule Intent")
            failures.append({
                "id": case_id,
                "category": category,
                "subcategory": item.get("subcategory", ""),
                "query": query,
                "expected_domain": expected_domain,
                "actual_domain": actual_domain,
                "domain_reason": domain_reason,
                "expected_intent": expected_intent,
                "actual_intent": actual_intent,
                "raw_intent": raw_intent,
                "mismatches": mismatches
            })

    return {
        "total": total_cases,
        "domain_correct": domain_correct,
        "domain_accuracy": (domain_correct / total_cases) * 100 if total_cases else 0.0,
        "intent_correct": intent_correct,
        "intent_accuracy": (intent_correct / total_cases) * 100 if total_cases else 0.0,
        "both_correct": both_correct,
        "overall_accuracy": (both_correct / total_cases) * 100 if total_cases else 0.0,
        "failures": failures,
        "category_stats": dict(category_stats)
    }


def print_report(results: Dict[str, Any]):
    print("=" * 80)
    print("BANKBOT HYBRID QUERY CLASSIFICATION EVALUATION BENCHMARK")
    print("=" * 80)
    print(f"Total Test Cases: {results['total']}")
    print("-" * 80)

    # Failures detail
    failures = results["failures"]
    if failures:
        print(f"\nDETAILED FAILURES ({len(failures)} cases):\n")
        for idx, f in enumerate(failures, 1):
            mismatch_str = " + ".join(f["mismatches"])
            print(f"[{idx}] Case #{f['id']:03d} | Category: {f['category']} / {f['subcategory']}")
            print(f"    Query:           \"{f['query']}\"")
            print(f"    Mismatch Type:   [{mismatch_str}]")
            if "Domain Gating" in f["mismatches"]:
                print(f"    Domain Validity: Expected={f['expected_domain']} | Actual={f['actual_domain']} (Reason: \"{f['domain_reason']}\")")
            else:
                print(f"    Domain Validity: Correct ({f['actual_domain']})")
            if "Rule Intent" in f["mismatches"]:
                print(f"    Rule Intent:     Expected={f['expected_intent']!r} | Actual={f['actual_intent']!r} (Raw: \"{f['raw_intent']}\")")
            else:
                print(f"    Rule Intent:     Correct ({f['actual_intent']!r})")
            print()
    else:
        print("\nAll test cases passed with 100% accuracy!\n")

    # Category Breakdown
    print("=" * 80)
    print("CATEGORY BREAKDOWN:")
    print(f"{'Category':<32} {'Cases':<8} {'Domain Acc':<14} {'Intent Acc':<14} {'Both Acc':<12}")
    print("-" * 80)
    for cat, stats in sorted(results["category_stats"].items()):
        total = stats["total"]
        dom_pct = (stats["domain_correct"] / total) * 100
        int_pct = (stats["intent_correct"] / total) * 100
        both_pct = (stats["both_correct"] / total) * 100
        print(f"{cat:<32} {total:<8} {dom_pct:>6.1f}% ({stats['domain_correct']}/{total})   {int_pct:>6.1f}% ({stats['intent_correct']}/{total})   {both_pct:>6.1f}%")

    print("=" * 80)
    print("SUMMARY METRICS:")
    print(f"  • Domain-Gating Accuracy: {results['domain_accuracy']:.2f}% ({results['domain_correct']}/{results['total']})")
    print(f"  • Rule-Intent Accuracy:   {results['intent_accuracy']:.2f}% ({results['intent_correct']}/{results['total']})")
    print(f"  • Overall Exact Match:    {results['overall_accuracy']:.2f}% ({results['both_correct']}/{results['total']})")
    print(f"  • Total Failures:         {len(results['failures'])} / {results['total']}")
    print("=" * 80)


if __name__ == "__main__":
    dataset_file = sys.argv[1] if len(sys.argv) > 1 else DATASET_PATH
    dataset = load_dataset(dataset_file)
    benchmark_results = evaluate_benchmark(dataset)
    print_report(benchmark_results)
