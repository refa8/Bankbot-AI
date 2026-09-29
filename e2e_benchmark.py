"""End-to-end benchmark harness for the currently exposed BankBot components.

This module intentionally does not start Streamlit or a live Ollama service.  It
exercises deterministic chat, mock-account operations, the Flask API test client,
and security primitives through their public interfaces.  Optional live Ollama
execution is supplied by a caller-provided runner, so failures remain observable
instead of being converted into successful answers.
"""
from __future__ import annotations

import copy
import json
import os
import tempfile
import time
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
from statistics import median
from typing import Any, Callable, Dict, Iterable, List, Optional

from app.api import create_app
from app.services.query_policy import classify_rule_intent, is_banking_query, validate_ollama_response
from evaluate_metrics import (
    DEFAULT_MOCK_USER,
    build_strict_banking_prompt,
    generate_deterministic_answer,
    run_ollama_inference,
    verify_answer_correctness,
)
from security import InputValidator, PasswordHasher, RateLimiter, SessionManager

OllamaRunner = Callable[[str], Dict[str, Any]]


def latency_stats(values: Iterable[Optional[float]]) -> Dict[str, Any]:
    """Return latency statistics in milliseconds, preserving an empty denominator."""
    usable = sorted(float(value) for value in values if value is not None)
    if not usable:
        return {"count": 0, "mean_ms": None, "median_ms": None, "p50_ms": None, "p95_ms": None, "max_ms": None}
    p95_index = min(len(usable) - 1, max(0, int(__import__("math").ceil(len(usable) * .95)) - 1))
    return {
        "count": len(usable),
        "mean_ms": round(sum(usable) / len(usable), 3),
        "median_ms": round(median(usable), 3),
        "p50_ms": round(median(usable), 3),
        "p95_ms": round(usable[p95_index], 3),
        "max_ms": round(usable[-1], 3),
    }


def rate_summary(outcomes: Iterable[Optional[bool]]) -> Dict[str, Any]:
    """Compute a denominator-aware success rate without treating unscored as failures."""
    values = list(outcomes)
    evaluated = [outcome for outcome in values if outcome is not None]
    successes = sum(outcome is True for outcome in evaluated)
    failures = sum(outcome is False for outcome in evaluated)
    return {
        "total": len(values),
        "evaluated": len(evaluated),
        "unscored": len(values) - len(evaluated),
        "succeeded": successes,
        "failed": failures,
        "success_rate": round(successes / len(evaluated), 4) if evaluated else None,
    }


def binary_metrics(expected: Iterable[bool], actual: Iterable[Optional[bool]]) -> Dict[str, Any]:
    """Precision/recall/F1 for independently scored boolean outcomes.

    Pairs with an unscored actual value are excluded and their count is retained.
    """
    expected_values = list(expected)
    pairs = [(bool(exp), got) for exp, got in zip(expected_values, actual) if got is not None]
    tp = sum(exp and got for exp, got in pairs)
    fp = sum(not exp and got for exp, got in pairs)
    fn = sum(exp and not got for exp, got in pairs)
    tn = sum(not exp and not got for exp, got in pairs)
    def score(numerator: int, denominator: int) -> float:
        return round(numerator / denominator, 4) if denominator else 0.0
    positive_precision = score(tp, tp + fp); positive_recall = score(tp, tp + fn)
    positive_f1 = score(2 * tp, 2 * tp + fp + fn)
    negative_precision = score(tn, tn + fn); negative_recall = score(tn, tn + fp)
    negative_f1 = score(2 * tn, 2 * tn + fp + fn)
    total = len(pairs)
    active_f1 = [score_value for score_value, support in ((positive_f1, tp + fn), (negative_f1, tn + fp)) if support]
    return {"evaluated": total, "unscored": len(expected_values) - total,
            "accuracy": score(tp + tn, total), "precision": positive_precision,
            "recall": positive_recall, "f1": positive_f1,
            "macro_f1": round(sum(active_f1) / len(active_f1), 4) if active_f1 else None,
            "weighted_f1": round(((tp + fn) * positive_f1 + (tn + fp) * negative_f1) / total, 4) if total else 0.0,
            "class_support": {"expected_success": tp + fn, "expected_failure": tn + fp},
            "confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn}}


def score_reference_answer(response: Optional[str], criteria: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Score a response against explicit, independently inspectable text criteria.

    Each required group is an OR-set; all groups must have at least one match.
    This deliberately reports unscored for absent responses rather than inferring
    correctness from transport or policy success.
    """
    if not isinstance(response, str) or not response.strip():
        return {"correct": None, "reason": "No response available for semantic scoring.", "matched_groups": []}
    if not isinstance(criteria, dict) or not criteria.get("required_any_groups"):
        return {"correct": None, "reason": "No authoritative reference criteria are available for this response.", "matched_groups": []}
    normalized = response.casefold()
    groups = criteria.get("required_any_groups", [])
    matches = [any(term.casefold() in normalized for term in group) for group in groups]
    forbidden = [term for term in criteria.get("forbidden_terms", []) if term.casefold() in normalized]
    correct = all(matches) and not forbidden
    return {
        "correct": correct,
        "reason": "All reference criteria matched." if correct else "Reference criteria were not fully satisfied.",
        "matched_groups": matches,
        "forbidden_matches": forbidden,
    }


LLM_REFERENCE_CASES = [
    {
        "id": "llm_upi_limit",
        "query": "What is the daily UPI limit?",
        "criteria": {"required_any_groups": [["1,00,000", "100,000", "100000"], ["daily", "per day"]]},
    },
    {
        "id": "llm_branch_hours",
        "query": "What are the branch operating hours?",
        "criteria": {"required_any_groups": [["9:30", "9.30"], ["4:00", "4.00"], ["mon", "monday"]]},
    },
    {
        "id": "llm_security_refusal",
        "query": "What are the bank account security rules for a password reset?",
        "criteria": None,
        "scoring_note": "No password-reset policy is present in BANK_KB, so this case records routing, transport, and response-policy status only. It is not semantically scored.",
    },
]


def evaluate_chatbot(ollama_runner: Optional[OllamaRunner] = None) -> Dict[str, Any]:
    """Evaluate deterministic answers and optional LLM reference-answer cases."""
    deterministic_cases = [
        ("balance", "What is my balance?"),
        ("transactions", "Show my recent transactions"),
        ("spend", "Show my spending analysis"),
        ("profile", "Show my account details"),
    ]
    records: List[Dict[str, Any]] = []
    for expected_intent, query in deterministic_cases:
        start = time.perf_counter()
        domain, _ = is_banking_query(query)
        intent = classify_rule_intent(query) if domain else None
        routing_ms = (time.perf_counter() - start) * 1000.0
        answer = generate_deterministic_answer(intent, DEFAULT_MOCK_USER)
        correct, reason = verify_answer_correctness(intent, answer or "", DEFAULT_MOCK_USER)
        records.append({
            "id": f"deterministic_{expected_intent}", "query": query,
            "expected_intent": expected_intent, "actual_intent": intent,
            "domain_correct": domain is True, "intent_correct": intent == expected_intent,
            "answer_correct": correct and intent == expected_intent,
            "answer_reason": reason, "routing_latency_ms": round(routing_ms, 3),
            "end_to_end_latency_ms": round((time.perf_counter() - start) * 1000.0, 3),
        })

    llm_records: List[Dict[str, Any]] = []
    for case in LLM_REFERENCE_CASES:
        domain, _ = is_banking_query(case["query"])
        intent = classify_rule_intent(case["query"]) if domain else None
        record: Dict[str, Any] = {
            "id": case["id"], "query": case["query"], "actual_domain": domain,
            "actual_intent": intent, "transport_status": "skipped_offline",
            "policy_validation_status": "not_run", "semantic_correct": None,
            "semantic_scoring_status": "not_run", "human_review_required": True,
        }
        if ollama_runner and domain and intent == "llm":
            started = time.perf_counter()
            inference = ollama_runner(build_strict_banking_prompt(DEFAULT_MOCK_USER, case["query"]))
            record.update({
                "transport_status": inference.get("status"),
                "transport_error": inference.get("error"),
                "time_to_first_token_ms": inference.get("time_to_first_token_ms"),
                "generation_latency_ms": inference.get("generation_latency_ms"),
                "end_to_end_latency_ms": round((time.perf_counter() - started) * 1000.0, 3),
                "raw_response": inference.get("response"),
            })
            if inference.get("status") == "success":
                validated = validate_ollama_response(inference.get("response") or "", case["query"])
                record["policy_validation_status"] = "rejected" if validated != inference.get("response") else "passed"
                record["response"] = validated
                semantic = score_reference_answer(validated, case.get("criteria"))
                record["semantic_correct"] = semantic["correct"]
                record["semantic_reason"] = semantic["reason"]
                record["human_review_required"] = semantic["correct"] is None
                record["semantic_scoring_status"] = (
                    "scored" if semantic["correct"] is not None else "unscored_no_authoritative_reference"
                )
            else:
                record["policy_validation_status"] = "not_run"
        llm_records.append(record)

    return {
        "deterministic_records": records,
        "llm_records": llm_records,
        "answer_accuracy": rate_summary(record["answer_correct"] for record in records),
        "answer_quality_metrics": binary_metrics([True] * len(records), (record["answer_correct"] for record in records)),
        "llm_semantic_accuracy": rate_summary(record["semantic_correct"] for record in llm_records),
        "llm_semantic_quality_metrics": binary_metrics([True] * len(llm_records), (record["semantic_correct"] for record in llm_records)),
        "routing_accuracy": rate_summary(
            [record["domain_correct"] and record["intent_correct"] for record in records]
            + [record["actual_domain"] is True and record["actual_intent"] == "llm" for record in llm_records]
        ),
        "latency": {"balance": latency_stats(record["end_to_end_latency_ms"] for record in records if record["expected_intent"] == "balance"),
                    "transactions": latency_stats(record["end_to_end_latency_ms"] for record in records if record["expected_intent"] == "transactions"),
                    "deterministic_end_to_end": latency_stats(record["end_to_end_latency_ms"] for record in records),
                    "llm_end_to_end": latency_stats(record.get("end_to_end_latency_ms") for record in llm_records)},
    }


def simulate_transfer(user: Dict[str, Any], recipient: str, amount: float) -> Dict[str, Any]:
    """Exercise the existing Streamlit transfer validation contract on an isolated copy.

    The Streamlit function is UI-coupled, so this reports logic-level state checks
    rather than claiming browser/UI or persisted-database coverage.
    """
    working = copy.deepcopy(user)
    before_balance = working["balance"]
    before_transactions = copy.deepcopy(working["transactions"])
    started = time.perf_counter()
    error = InputValidator.validate_amount(amount, max_amount=50000.0)
    sanitized_recipient = InputValidator.sanitize_text(recipient)
    if not error and not sanitized_recipient:
        error = "Recipient name is required"
    if not error and amount > working["balance"]:
        error = "Insufficient funds."
    if error:
        return {"success": False, "message": error, "balance_unchanged": working["balance"] == before_balance,
                "transactions_unchanged": working["transactions"] == before_transactions,
                "latency_ms": round((time.perf_counter() - started) * 1000.0, 3)}
    working["balance"] -= amount
    working["transactions"].insert(0, {"date": datetime.now().strftime("%Y-%m-%d"),
        "desc": f"Transfer to {sanitized_recipient}", "cat": "Transfer", "amt": -amount, "type": "Debit"})
    return {"success": True, "message": f"Transfer successful! Rs. {amount:,.2f} sent to {sanitized_recipient}",
            "balance_before": before_balance, "balance_after": working["balance"],
            "transaction_created": working["transactions"][0], "latency_ms": round((time.perf_counter() - started) * 1000.0, 3)}


def evaluate_transfers() -> Dict[str, Any]:
    """Measure the isolated transfer contract without claiming API/UI latency."""
    low_balance_user = copy.deepcopy(DEFAULT_MOCK_USER)
    low_balance_user["balance"] = 100.0
    cases = [
        ("valid_minimum", DEFAULT_MOCK_USER, "Alice", 1.0, True),
        ("valid_limit", DEFAULT_MOCK_USER, "Alice", 50000.0, True),
        ("invalid_zero", DEFAULT_MOCK_USER, "Alice", 0.0, False),
        ("invalid_negative", DEFAULT_MOCK_USER, "Alice", -1.0, False),
        ("over_limit", DEFAULT_MOCK_USER, "Alice", 50000.01, False),
        ("insufficient_funds", low_balance_user, "Alice", 200.0, False),
        ("empty_recipient", DEFAULT_MOCK_USER, "", 100.0, False),
        ("sanitized_recipient", DEFAULT_MOCK_USER, "<Alice>", 100.0, True),
    ]
    records = []
    for name, user, recipient, amount, expected_success in cases:
        result = simulate_transfer(user, recipient, amount)
        state_ok = (result["success"] and result["balance_after"] == user["balance"] - amount
                    and result["transaction_created"]["amt"] == -amount) if result["success"] else (
                    result["balance_unchanged"] and result["transactions_unchanged"])
        records.append({"case": name, "expected_success": expected_success, "state_valid": state_ok,
                        "task_success": result["success"] == expected_success and state_ok, **result})
    return {"records": records, "task_success": rate_summary(record["task_success"] for record in records),
            "task_quality_metrics": binary_metrics((record["expected_success"] for record in records), (record["success"] for record in records)),
            "isolated_logic_latency": latency_stats(record["latency_ms"] for record in records),
            "coverage_note": "Isolated transfer validation/state contract only; see rest_api.transfer_latency for API request timing."}


def _temporary_api_db() -> tuple[str, Dict[str, Any]]:
    hasher = PasswordHasher()
    data = {"1234567890": {"name": "Benchmark User", "hashed_pin": hasher.hash_password("0000"),
            "balance": 50000.0, "type": "Savings", "credit_score": 780,
            "transactions": [{"date": "2026-01-10", "desc": "Salary", "cat": "Income", "amt": 25000, "type": "Credit"}]},
            "0987654321": {"name": "Isolation User", "hashed_pin": hasher.hash_password("1111"),
            "balance": 120000.0, "type": "Current", "credit_score": 810, "transactions": []}}
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    Path(path).write_text(json.dumps(data), encoding="utf-8")
    return path, data


def evaluate_rest_api() -> Dict[str, Any]:
    """Use Flask's in-process client, measuring complete request/response handling."""
    path, expected = _temporary_api_db()
    records = []
    try:
        app = create_app(db_file=path)
        app.config["TESTING"] = True
        client = app.test_client()
        def request_case(name: str, method: str, url: str, expected_status: int, **kwargs: Any) -> Any:
            started = time.perf_counter(); response = getattr(client, method)(url, **kwargs)
            records.append({"name": name, "endpoint": url, "status": response.status_code,
                            "expected_status": expected_status, "success": response.status_code == expected_status,
                            "latency_ms": round((time.perf_counter() - started) * 1000.0, 3), "body": response.get_json()})
            return response
        request_case("health", "get", "/api/health", 200)
        request_case("missing_auth", "get", "/api/balance", 401)
        login = request_case("login", "post", "/api/login", 200, json={"account": "1234567890", "pin": "0000"})
        token = login.get_json()["token"] if login.status_code == 200 else ""
        headers = {"Authorization": f"Bearer {token}"}
        balance = request_case("balance", "get", "/api/balance", 200, headers=headers)
        transactions = request_case("transactions", "get", "/api/transactions", 200, headers=headers)
        transfer = request_case("transfer", "post", "/api/transfers", 201, headers=headers,
                                json={"recipient": "Alice", "amount": 100.0})
        transferred_balance = request_case("balance_after_transfer", "get", "/api/balance", 200, headers=headers)
        request_case("logout", "post", "/api/logout", 200, headers=headers)
        request_case("expired_after_logout", "get", "/api/balance", 401, headers=headers)
        if balance.status_code == 200:
            next(record for record in records if record["name"] == "balance")["response_valid"] = (
                balance.get_json().get("balance") == expected["1234567890"]["balance"]
            )
        if transactions.status_code == 200:
            next(record for record in records if record["name"] == "transactions")["response_valid"] = (
                transactions.get_json().get("transactions") == expected["1234567890"]["transactions"]
            )
        if transfer.status_code == 201:
            transfer_body = transfer.get_json()
            next(record for record in records if record["name"] == "transfer")["response_valid"] = (
                transfer_body.get("balance") == expected["1234567890"]["balance"] - 100.0
                and transfer_body.get("transaction", {}).get("amt") == -100.0
            )
        if transferred_balance.status_code == 200:
            next(record for record in records if record["name"] == "balance_after_transfer")["response_valid"] = (
                transferred_balance.get_json().get("balance") == expected["1234567890"]["balance"] - 100.0
            )
    finally:
        if os.path.exists(path): os.remove(path)
    return {"records": records, "request_success": rate_summary(record["success"] for record in records),
            "latency": {"all_endpoints": latency_stats(record["latency_ms"] for record in records),
                        "by_endpoint": {endpoint: latency_stats(record["latency_ms"] for record in records if record["endpoint"] == endpoint)
                                        for endpoint in sorted({record["endpoint"] for record in records})}},
            "transfer_endpoint_available": True,
            "transfer_endpoint_note": "POST /api/transfers is exercised in-process against an isolated JSON database.",
            "transfer_latency": latency_stats(record["latency_ms"] for record in records if record["name"] == "transfer")}


def evaluate_latency(repetitions: int = 10) -> Dict[str, Any]:
    """Measure repeatable local timings without weakening authentication.

    API measurements use Flask's in-process test client. They are useful for
    comparing code paths, but deliberately exclude network/TLS/proxy latency.
    """
    prompts = ("What is my balance?", "Show my recent transactions", "What is the UPI limit?")
    routing_samples = []
    balance_samples = []
    transaction_samples = []
    for _ in range(repetitions):
        for prompt in prompts:
            started = time.perf_counter()
            domain, _ = is_banking_query(prompt)
            if domain:
                classify_rule_intent(prompt)
            routing_samples.append((time.perf_counter() - started) * 1000.0)

        started = time.perf_counter()
        generate_deterministic_answer("balance", DEFAULT_MOCK_USER, query="What is my balance?")
        balance_samples.append((time.perf_counter() - started) * 1000.0)
        started = time.perf_counter()
        generate_deterministic_answer("transactions", DEFAULT_MOCK_USER, query="Show my latest 2 transactions")
        transaction_samples.append((time.perf_counter() - started) * 1000.0)

    path, _ = _temporary_api_db()
    login_samples = []
    warm_balance_samples = []
    warm_transaction_samples = []
    login_and_balance_samples = []
    try:
        app = create_app(db_file=path)
        app.config["TESTING"] = True
        client = app.test_client()
        for _ in range(repetitions):
            started = time.perf_counter()
            login = client.post("/api/login", json={"account": "1234567890", "pin": "0000"})
            login_samples.append((time.perf_counter() - started) * 1000.0)
            token = login.get_json().get("token") if login.status_code == 200 else ""
            headers = {"Authorization": f"Bearer {token}"}

            started = time.perf_counter()
            client.get("/api/balance", headers=headers)
            warm_balance_samples.append((time.perf_counter() - started) * 1000.0)
            started = time.perf_counter()
            client.get("/api/transactions?limit=2", headers=headers)
            warm_transaction_samples.append((time.perf_counter() - started) * 1000.0)

            started = time.perf_counter()
            pair_login = client.post("/api/login", json={"account": "1234567890", "pin": "0000"})
            pair_token = pair_login.get_json().get("token") if pair_login.status_code == 200 else ""
            client.get("/api/balance", headers={"Authorization": f"Bearer {pair_token}"})
            login_and_balance_samples.append((time.perf_counter() - started) * 1000.0)
    finally:
        if os.path.exists(path):
            os.remove(path)

    return {
        "environment": "single-process Flask test client; local JSON fixture; no network/TLS/proxy load",
        "repetitions": repetitions,
        "routing": latency_stats(routing_samples),
        "deterministic_balance_response": latency_stats(balance_samples),
        "deterministic_transaction_response": latency_stats(transaction_samples),
        "bcrypt_login": latency_stats(login_samples),
        "warm_authenticated_balance_api": latency_stats(warm_balance_samples),
        "warm_authenticated_transactions_api": latency_stats(warm_transaction_samples),
        "login_plus_balance_api": latency_stats(login_and_balance_samples),
    }


def evaluate_security() -> Dict[str, Any]:
    """Execute security checks through validators and two authenticated API sessions."""
    checks: List[Dict[str, Any]] = []
    validator = InputValidator()
    checks.extend([
        {"name": "invalid_account_rejected", "passed": validator.validate_account_number("abc") is not None},
        {"name": "invalid_pin_rejected", "passed": validator.validate_pin("12") is not None},
        {"name": "over_limit_transfer_rejected", "passed": validator.validate_amount(50000.01, max_amount=50000.0) is not None},
        {"name": "html_characters_sanitized", "passed": "<" not in validator.sanitize_text("<Alice>")},
    ])
    path, expected = _temporary_api_db()
    try:
        app = create_app(db_file=path); app.config["TESTING"] = True; client = app.test_client()
        login1 = client.post("/api/login", json={"account": "1234567890", "pin": "0000"})
        login2 = client.post("/api/login", json={"account": "0987654321", "pin": "1111"})
        token1 = login1.get_json().get("token") if login1.status_code == 200 else None
        token2 = login2.get_json().get("token") if login2.status_code == 200 else None
        unauthorized = client.get("/api/balance")
        user1 = client.get("/api/balance", headers={"Authorization": f"Bearer {token1}"}) if token1 else None
        user2 = client.get("/api/balance", headers={"Authorization": f"Bearer {token2}"}) if token2 else None
        checks.extend([
            {"name": "unauthorized_api_rejected", "passed": unauthorized.status_code == 401},
            {"name": "account_isolation", "passed": bool(user1 and user2 and user1.get_json().get("balance") == expected["1234567890"]["balance"] and user2.get_json().get("balance") == expected["0987654321"]["balance"])},
            {"name": "malformed_login_rejected", "passed": client.post("/api/login", json={"account": 1234567890, "pin": 0}).status_code == 400},
            {"name": "unauthorized_transfer_rejected", "passed": client.post("/api/transfers", json={"recipient": "Alice", "amount": 1}).status_code == 401},
        ])
    finally:
        if os.path.exists(path): os.remove(path)
    limiter = RateLimiter(max_attempts=2, lockout_minutes=15)
    limiter.record_attempt("account"); limiter.record_attempt("account")
    checks.append({"name": "rate_limit_lockout", "passed": limiter.is_locked_out("account")[0]})
    return {"checks": checks, "pass_rate": rate_summary(check["passed"] for check in checks),
            "failures": [check for check in checks if not check["passed"]]}


def evaluate_reliability() -> Dict[str, Any]:
    """Test local session/rate-limit recovery; external service faults remain injected-test coverage."""
    manager = SessionManager(timeout_minutes=1)
    session = manager.create_session("1234567890")
    active_valid = manager.is_session_valid(session)
    session["last_activity"] = datetime.now() - timedelta(minutes=2)
    expired_invalid = not manager.is_session_valid(session)
    recovered_valid = manager.is_session_valid(manager.create_session("1234567890"))
    limiter = RateLimiter(max_attempts=2, lockout_minutes=15)
    limiter.record_attempt("1234567890"); limiter.record_attempt("1234567890")
    locked, _ = limiter.is_locked_out("1234567890")
    limiter.reset_attempts("1234567890")
    unlocked, _ = limiter.is_locked_out("1234567890")
    checks = {"session_active": active_valid, "session_expiration": expired_invalid, "session_recovery": recovered_valid,
              "rate_limit_lockout": locked, "rate_limit_recovery": not unlocked,
              "ollama_failure_modes": None, "api_error_modes": None}
    return {"checks": checks, "pass_rate": rate_summary(checks.values()),
            "limitations": ["Ollama unavailable/timeout/malformed-response paths require mocked transport tests or a controlled service.",
                            "API error modes are covered by API tests; this runtime benchmark uses in-process success and authorization probes."]}


def run_benchmark(output_path: Optional[str] = None, ollama_runner: Optional[OllamaRunner] = None) -> Dict[str, Any]:
    """Run the available component benchmark and optionally write a JSON report."""
    started = time.perf_counter()
    report = {"metadata": {"timestamp": datetime.now().isoformat(), "benchmark": "BankBot end-to-end component benchmark",
                             "live_ollama_executed": ollama_runner is not None},
              "chatbot_quality": evaluate_chatbot(ollama_runner), "banking_operations": evaluate_transfers(),
              "rest_api": evaluate_rest_api(), "latency": evaluate_latency(),
              "reliability": evaluate_reliability(), "security": evaluate_security()}
    report["metadata"]["total_runtime_ms"] = round((time.perf_counter() - started) * 1000.0, 3)
    if output_path:
        Path(output_path).write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def print_summary(report: Dict[str, Any]) -> None:
    chat = report["chatbot_quality"]; operations = report["banking_operations"]; api = report["rest_api"]
    print("BankBot End-to-End Component Benchmark")
    print(f"Deterministic answer accuracy: {chat['answer_accuracy']}")
    print(f"Deterministic answer F1: {chat['answer_quality_metrics']}")
    print(f"Routing accuracy: {chat['routing_accuracy']}")
    print(f"LLM semantic accuracy/F1: {chat['llm_semantic_accuracy']} / {chat['llm_semantic_quality_metrics']}")
    print(f"Transfer task success: {operations['task_success']}")
    print(f"Isolated transfer logic latency: {operations['isolated_logic_latency']}")
    print(f"REST transfer latency: {api['transfer_latency']}")
    print(f"API request success: {api['request_success']}")
    print(f"API latency: {api['latency']['all_endpoints']}")
    print(f"Warm authenticated balance API latency: {report['latency']['warm_authenticated_balance_api']}")
    print(f"bcrypt login latency: {report['latency']['bcrypt_login']}")
    print(f"Security pass rate: {report['security']['pass_rate']}")
    print("Note: LLM correctness is unscored unless actual responses satisfy explicit reference criteria;")
    print("transport success and policy acceptance are reported separately in each LLM record.")
    print("Limitation: isolated transfer checks do not cover Streamlit UI; REST transfer timing uses Flask's in-process test client.")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Run BankBot end-to-end component benchmark")
    parser.add_argument("--output", default="e2e_benchmark_results.json")
    parser.add_argument("--eval-ollama", action="store_true", help="Execute configured local Ollama for reference cases")
    args = parser.parse_args()
    result = run_benchmark(args.output, run_ollama_inference if args.eval_ollama else None)
    print_summary(result)
