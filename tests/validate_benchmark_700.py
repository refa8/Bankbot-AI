"""Validate the static BankBot 700-query benchmark without invoking the evaluator."""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


TESTS_DIR = Path(__file__).resolve().parent
BENCHMARK_PATH = TESTS_DIR / "benchmark_700.json"
EXISTING_DATASETS = [
    TESTS_DIR / "query_eval_dataset.json",
    TESTS_DIR / "unseen_eval_dataset.json",
]
REQUIRED_FIELDS = {
    "id", "category", "subcategory", "query",
    "expected_domain_validity", "expected_rule_intent",
}
SUPPORTED_INTENTS = {
    "balance", "transactions", "spend", "profile",
    "transfer", "greeting", "goodbye", "help", None,
}
EXPECTED_CATEGORY_COUNTS = {
    "deterministic_banking": 250,
    "llm_routed_banking": 200,
    "off_topic_out_of_scope": 150,
    "adversarial_security": 100,
}


def normalized_query(value: str) -> str:
    """Case-and-whitespace normalization only; no classifier normalization is used."""
    return " ".join(value.casefold().split())


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def validate() -> list[str]:
    failures: list[str] = []
    try:
        rows = load_json(BENCHMARK_PATH)
    except (OSError, json.JSONDecodeError) as exc:
        return [f"Cannot load {BENCHMARK_PATH.name}: {exc}"]

    if not isinstance(rows, list):
        return ["Benchmark root must be a JSON list."]
    if len(rows) != 700:
        failures.append(f"Expected 700 records, found {len(rows)}.")

    ids = []
    texts: list[str] = []
    for index, record in enumerate(rows, start=1):
        if not isinstance(record, dict):
            failures.append(f"Record {index} is not an object.")
            continue
        missing = REQUIRED_FIELDS - set(record)
        if missing:
            failures.append(f"Record {index} missing fields: {sorted(missing)}.")
            continue
        if not isinstance(record["id"], int):
            failures.append(f"Record {index} has a non-integer id.")
        else:
            ids.append(record["id"])
        if not isinstance(record["category"], str) or not record["category"]:
            failures.append(f"Record {index} has an invalid category.")
        if not isinstance(record["subcategory"], str) or not record["subcategory"]:
            failures.append(f"Record {index} has an invalid subcategory.")
        if not isinstance(record["query"], str) or not record["query"].strip():
            failures.append(f"Record {index} has an invalid query.")
        else:
            texts.append(normalized_query(record["query"]))
        if type(record["expected_domain_validity"]) is not bool:
            failures.append(f"Record {index} expected_domain_validity must be boolean.")
        if record["expected_rule_intent"] not in SUPPORTED_INTENTS:
            failures.append(f"Record {index} has unsupported intent {record['expected_rule_intent']!r}.")

    duplicate_ids = sorted(key for key, count in Counter(ids).items() if count > 1)
    if duplicate_ids:
        failures.append(f"Duplicate IDs: {duplicate_ids}.")
    duplicate_texts = sorted(key for key, count in Counter(texts).items() if count > 1)
    if duplicate_texts:
        failures.append(f"Duplicate normalized query texts: {duplicate_texts[:10]}.")

    category_counts = Counter(record.get("category") for record in rows if isinstance(record, dict))
    if category_counts != EXPECTED_CATEGORY_COUNTS:
        failures.append(f"Category distribution mismatch: {dict(category_counts)}.")

    existing_texts = set()
    for path in EXISTING_DATASETS:
        try:
            existing_rows = load_json(path)
        except (OSError, json.JSONDecodeError) as exc:
            failures.append(f"Cannot inspect existing dataset {path.name}: {exc}")
            continue
        existing_texts.update(
            normalized_query(record["query"])
            for record in existing_rows
            if isinstance(record, dict) and isinstance(record.get("query"), str)
        )
    overlaps = sorted(set(texts) & existing_texts)
    if overlaps:
        failures.append(f"Exact normalized overlap with existing datasets: {overlaps[:10]}.")

    return failures


def main() -> int:
    failures = validate()
    if failures:
        print("Benchmark validation FAILED:")
        for failure in failures:
            print(f"- {failure}")
        return 1
    print("Benchmark validation passed: 700 records, unique IDs, unique normalized queries, valid schema and category distribution.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
