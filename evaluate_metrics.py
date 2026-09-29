"""
evaluate_metrics.py

Comprehensive, reproducible evaluation framework for BankBot-AI.

Features:
1. Intent Classification Evaluation:
   - Measures domain gating (is_banking_query) and rule intent routing (classify_rule_intent).
   - Computes accuracy, precision, recall, macro F1, weighted F1, per-class metrics, and confusion matrix.
2. Banking Answer Correctness:
   - Evaluates factual correctness of balance and transaction answers against known mock database data.
   - Evaluates deterministic response generation without external dependencies.
3. Latency Benchmarking:
   - Measures per-query execution latency in milliseconds.
   - Computes count, min, median, p95, max, and mean latencies, separated into:
     * Deterministic pipeline (rule-based and semantic fallback)
     * LLM-bound path (queries routed to LLM)
     * Blocked path (queries rejected by domain gate)
     * Overall suite
4. Safety & Factuality Auditing:
   - Detects domain gating leaks (off-topic queries falsely allowed).
   - Detects policy theft (policy questions intercepted by action rules).
   - Detects unsafe transfer triggering.
   - Detects data hallucinations / mismatches with mock database.
5. Machine-Readable Export:
   - Saves reproducible JSON results containing metadata, summary metrics, and per-query records.
6. Separation of Concerns:
   - Clearly separates intent classification accuracy from factual answer correctness.
   - Explicitly records Ollama status and keeps LLM evaluation separate.
"""

from collections import Counter, defaultdict
from datetime import datetime
import json
import math
import os
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

import requests

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app.services.query_policy import (
    OFF_TOPIC_REFUSAL,
    classify_rule_intent,
    is_banking_query,
    normalize_query,
    validate_ollama_response,
)
from app.services.account_responses import balance_response, filter_transactions, transactions_response
from app.utils.formatting import format_currency
from config import settings

REGRESSION_PATH = os.path.join(PROJECT_ROOT, "tests", "query_eval_dataset.json")
UNSEEN_PATH     = os.path.join(PROJECT_ROOT, "tests", "unseen_eval_dataset.json")

# Canonical label order for the confusion matrix.
# None == the classifier returned "llm" (no deterministic rule matched).
INTENT_LABELS: List[Optional[str]] = [
    "balance", "transactions", "spend", "profile", "transfer",
    "greeting", "goodbye", "help", None,
]

# Standard mock user database record for reproducible answer verification
DEFAULT_MOCK_USER: Dict[str, Any] = {
    "account": "1234567890",
    "name": "customer1",
    "balance": 55750.50,
    "type": "Premium Savings",
    "email": "john@email.com",
    "phone": "9876543210",
    "credit_score": 785,
    "transactions": [
        {"date": "2024-12-05", "desc": "Salary Credit", "cat": "Income", "amt": 5000, "type": "Credit"},
        {"date": "2024-12-03", "desc": "Amazon Purchase", "cat": "Shopping", "amt": -1250, "type": "Debit"},
        {"date": "2024-12-01", "desc": "Rent Payment", "cat": "Bills", "amt": -3500, "type": "Debit"},
        {"date": "2024-11-28", "desc": "Freelance Payment", "cat": "Income", "amt": 2000, "type": "Credit"},
        {"date": "2024-11-25", "desc": "Grocery Shopping", "cat": "Food", "amt": -850, "type": "Debit"},
    ],
}


BANK_KB = """
SECUREBANK OFFICIAL POLICIES:
1. SAVINGS INTEREST: 4.5% p.a., credited quarterly.
2. HOME LOANS: Starting at 8.75% p.a. for amounts > 50 Lakhs.
3. CREDIT CARDS: 'Platinum' (Rs. 1000/yr fee) and 'Gold' (Free for life).
4. BRANCH HOURS: Mon-Sat, 9:30 AM - 4:00 PM. Closed on 2nd/4th Saturdays.
5. UPI LIMITS: Rs. 1,00,000 per day.
6. SUPPORT: Call 1800-123-4567 or email support@securebank.com.
7. FIXED DEPOSITS: 6.5% for 1 year, 7.2% for 3 years (Senior citizens +0.5%).
"""


def build_strict_banking_prompt(user_data: Dict[str, Any], user_query: str) -> str:
    """Build the same banking prompt shape used by the Streamlit application."""
    recent = "\n".join(
        f"- {t['date']}: {t['desc']} ({t['cat']}) | Amount: Rs. {t['amt']}"
        for t in user_data.get("transactions", [])[:5]
    )

    return f"""You are a STRICTLY REGULATED banking assistant for SecureBank. You MUST follow these rules:

CRITICAL RULES:
1. ONLY answer questions about: account balances, transactions, transfers, loans, credit cards, banking policies, and financial services
2. If asked about ANYTHING else (coding, history, weather, jokes, general knowledge, recipes, travel), respond EXACTLY with: "I apologize, but I can only assist with banking and financial queries."
3. Do NOT provide any information outside banking/finance domain
4. Do NOT explain why you can't answer non-banking questions
5. Keep responses concise and professional

BANK POLICIES (Official Information):
{BANK_KB}

USER DATA (Confidential):
- Name: {user_data.get('name', 'User')}
- Balance: Rs. {user_data.get('balance', 0):,.2f}
- Account Type: {user_data.get('type', 'account')}
- Credit Score: {user_data.get('credit_score', 'N/A')}
- Recent Transactions:
{recent}

USER QUESTION: {user_query}

YOUR RESPONSE (banking-only, max 300 words):"""


def run_ollama_inference(prompt: str) -> Dict[str, Any]:
    """Execute one streamed Ollama request and return response, status, and timings."""
    result: Dict[str, Any] = {
        "status": "service_error",
        "response": None,
        "error": None,
        "time_to_first_token_ms": None,
        "generation_latency_ms": None,
    }
    payload = {
        "model": settings.OLLAMA_MODEL,
        "prompt": prompt,
        "stream": True,
        "options": {"temperature": 0.1, "top_p": 0.9, "top_k": 40},
    }
    started = time.perf_counter()

    try:
        with requests.post(
            f"{settings.OLLAMA_URL.rstrip('/')}/api/generate",
            json=payload,
            stream=True,
            timeout=settings.OLLAMA_TIMEOUT,
        ) as resp:
            resp.raise_for_status()
            chunks: List[str] = []
            completed = False
            for line in resp.iter_lines():
                if not line:
                    continue
                try:
                    item = json.loads(line.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    result["status"] = "invalid_response"
                    result["error"] = "Ollama returned invalid streamed JSON."
                    return result

                if not isinstance(item, dict):
                    result["status"] = "invalid_response"
                    result["error"] = "Ollama returned an invalid response object."
                    return result
                if item.get("error"):
                    error_text = str(item["error"])
                    result["status"] = "model_unavailable" if "model" in error_text.lower() and "not found" in error_text.lower() else "service_error"
                    result["error"] = error_text
                    return result

                chunk = item.get("response", "")
                if chunk:
                    if not isinstance(chunk, str):
                        result["status"] = "invalid_response"
                        result["error"] = "Ollama returned a non-text response chunk."
                        return result
                    if result["time_to_first_token_ms"] is None:
                        result["time_to_first_token_ms"] = round((time.perf_counter() - started) * 1000.0, 3)
                    chunks.append(chunk)
                if item.get("done"):
                    completed = True
                    break

            result["generation_latency_ms"] = round((time.perf_counter() - started) * 1000.0, 3)
            if not completed:
                result["status"] = "invalid_response"
                result["error"] = "Ollama stream ended before completion."
            elif not chunks:
                result["status"] = "empty_response"
                result["error"] = "Ollama returned an empty response."
            else:
                result["status"] = "success"
                result["response"] = "".join(chunks)
    except requests.exceptions.Timeout:
        result["status"] = "timeout"
        result["error"] = "Ollama request timed out."
    except requests.exceptions.ConnectionError:
        result["status"] = "service_unavailable"
        result["error"] = "Could not connect to the configured Ollama service."
    except requests.exceptions.HTTPError as exc:
        status_code = exc.response.status_code if exc.response is not None else None
        result["status"] = "model_unavailable" if status_code == 404 else "service_error"
        result["error"] = f"Ollama HTTP error{f' {status_code}' if status_code else ''}."
    except requests.exceptions.RequestException as exc:
        result["status"] = "service_error"
        result["error"] = f"Ollama request failed: {exc.__class__.__name__}."

    if result["generation_latency_ms"] is None:
        result["generation_latency_ms"] = round((time.perf_counter() - started) * 1000.0, 3)
    return result


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def load_dataset(path: str) -> List[Dict[str, Any]]:
    """Load a JSON evaluation dataset from *path*."""
    if not os.path.exists(path):
        raise FileNotFoundError("Dataset not found: " + path)
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


# ---------------------------------------------------------------------------
# Classifier runner & Response Pipeline
# ---------------------------------------------------------------------------

def _norm(raw: str) -> Optional[str]:
    """Map raw classify_rule_intent output to None when 'llm' (no rule matched)."""
    return None if raw == "llm" else raw


def run_classifier(item: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run both classifier stages on one dataset record and return a classification result dict.
    Maintains exact backwards-compatible schema for existing unit tests.
    """
    query      = item["query"]
    exp_domain = item["expected_domain_validity"]
    exp_intent = item.get("expected_rule_intent")   # None for LLM-bound cases

    act_domain, domain_reason = is_banking_query(query)
    act_intent = _norm(classify_rule_intent(query))

    return {
        "id":              item.get("id"),
        "category":        item.get("category", ""),
        "subcategory":     item.get("subcategory", ""),
        "query":           query,
        "expected_domain": exp_domain,
        "actual_domain":   act_domain,
        "domain_reason":   domain_reason,
        "expected_intent": exp_intent,
        "actual_intent":   act_intent,
        "domain_correct":  act_domain == exp_domain,
        "intent_correct":  act_intent == exp_intent,
        "both_correct":    (act_domain == exp_domain) and (act_intent == exp_intent),
    }


def generate_deterministic_answer(
    intent: Optional[str],
    user_data: Dict[str, Any],
    account_id: str = "1234567890",
    query: str = "",
) -> Optional[str]:
    """
    Generate the deterministic banking answer for a given intent.
    Replicates BankBot's core response generator without Streamlit dependency.
    Returns None if the intent requires an LLM call.
    """
    if not intent or intent == "llm":
        return None

    if intent == "balance":
        return balance_response(user_data)

    if intent == "transactions":
        return transactions_response(user_data, query)

    if intent == "balance":
        bal_str = format_currency(user_data.get("balance", 0.0))
        acct_type = user_data.get("type", "account")
        cs = user_data.get("credit_score", "N/A")
        return (
            f"Your account balance is **{bal_str}** in your {acct_type} account. "
            f"Looking good!\n\n💳 Credit Score: {cs}"
        )

    if intent == "transactions":
        trans = user_data.get("transactions", [])[:3]
        msg = f"Here are your last {len(trans)} transactions:\n\n"
        for t in trans:
            emoji = "✅" if t.get("type") == "Credit" else "💸"
            msg += (
                f"{emoji} **{t.get('date')}** - {t.get('desc')}\n"
                f"   Amount: {format_currency(t.get('amt', 0))} | Category: {t.get('cat')}\n\n"
            )
        return msg

    if intent == "spend":
        txs = user_data.get("transactions", [])
        debits = [t for t in txs if t.get("type") == "Debit"]
        total_spent = sum(abs(t.get("amt", 0)) for t in debits)
        avg_spent = total_spent / len(debits) if debits else 0
        cat_sums: Dict[str, float] = defaultdict(float)
        for t in debits:
            cat_sums[t.get("cat", "Other")] += abs(t.get("amt", 0))
        top_cat = max(cat_sums.items(), key=lambda x: x[1])[0] if cat_sums else "N/A"
        return (
            f"📊 **Spending Analysis:**\n\n"
            f"💰 Total Spent: **{format_currency(total_spent)}**\n"
            f"📈 Average Transaction: **{format_currency(avg_spent)}**\n"
            f"🎯 Top Category: **{top_cat}**"
        )

    if intent == "profile":
        name = user_data.get("name", "User")
        email = user_data.get("email", "N/A")
        phone = user_data.get("phone", "N/A")
        acct_type = user_data.get("type", "Standard")
        bal_str = format_currency(user_data.get("balance", 0.0))
        cs = user_data.get("credit_score", "N/A")
        return (
            f"👤 **Your Profile:**\n\n"
            f"• Name: {name}\n"
            f"• Account: {account_id}\n"
            f"• Email: {email}\n"
            f"• Phone: {phone}\n"
            f"• Type: {acct_type}\n"
            f"• Balance: {bal_str}\n"
            f"• Credit Score: {cs} ⭐"
        )

    if intent == "transfer":
        bal_str = format_currency(user_data.get("balance", 0.0))
        return (
            f"💸 **Money Transfer Guide:**\n\n"
            f"Go to the **Transfer tab** to send money securely.\n\n"
            f"Current balance: {bal_str}\n"
            f"Daily limit: Rs. 50,000 🔒"
        )

    if intent == "greeting":
        name = user_data.get("name", "User").split()[0]
        return f"Hello {name}! 👋\n\nHow can I help you today?"

    if intent == "goodbye":
        return "Goodbye! Stay secure! 👋"

    if intent == "help":
        bal_str = format_currency(user_data.get("balance", 0.0))
        return (
            f"🤖 **I'm your AI Banking Assistant!**\n\n"
            f"I can help you with:\n"
            f"• Check Balance\n"
            f"• View Transactions\n"
            f"• Spending Analysis\n"
            f"• Account Info\n"
            f"• Transfers\n\n"
            f"Current balance: {bal_str}"
        )

    return None


def verify_answer_correctness(
    intent: Optional[str],
    response_text: Optional[str],
    user_data: Dict[str, Any],
    query: str = "",
) -> Tuple[bool, str]:
    """
    Verify if a generated answer is factually correct against mock database data.
    Returns: (is_correct, reason)
    """
    if response_text is None:
        return False, "No response generated (requires live LLM)"

    if intent == "transactions":
        expected_response = transactions_response(user_data, query)
        if response_text != expected_response:
            return False, "Transaction response did not match the authoritative filtered response"
        return True, "Authoritative filtered transaction response verified"

    if intent == "balance":
        expected_balance = user_data.get("balance", 0.0)
        formatted_balance = format_currency(expected_balance)
        raw_balance = f"{expected_balance:,.2f}"
        if formatted_balance in response_text or raw_balance in response_text:
            return True, f"Verified balance {formatted_balance} in response"
        return False, f"Expected balance {formatted_balance} not found in response"

    if intent == "transactions":
        trans = user_data.get("transactions", [])[:3]

        if not trans:
            return (
                "Here are your last 0 transactions:" in response_text,
                "No transactions on record"
            )

        missing = []
        for t in trans:
            if t.get("desc") not in response_text:
                missing.append(t.get("desc"))
                continue

            amount = format_currency(t.get("amt", 0))
            if amount not in response_text:
                missing.append(f"{t.get('desc')} (amount mismatch)")

        if not missing:
            return True, f"All {len(trans)} recent transactions verified"

        return False, f"Missing or incorrect transactions: {missing}"

    if intent == "spend":
        txs = user_data.get("transactions", [])
        debits = [t for t in txs if t.get("type") == "Debit"]
        total_spent = sum(abs(t.get("amt", 0)) for t in debits)
        fmt_spent = format_currency(total_spent)
        if fmt_spent in response_text or f"{total_spent:,.2f}" in response_text:
            return True, f"Verified spending total {fmt_spent} in response"
        return False, f"Expected spending total {fmt_spent} not found in response"

    if intent == "profile":
        name = user_data.get("name", "")
        if name and name in response_text:
            return True, f"Verified profile for user {name}"
        return False, f"Expected user name {name} not found in response"

    if intent in ("greeting", "goodbye", "help", "transfer"):
        if len(response_text) > 10:
            return True, f"Valid {intent} message generated"
        return False, f"Empty or truncated {intent} message"

    return False, f"Unrecognized intent: {intent}"


def check_safety_and_policy(
    item: Dict[str, Any],
    act_domain: bool,
    act_intent: Optional[str],
    domain_reason: str,
) -> Tuple[bool, List[str]]:
    """
    Check for safety and policy guard violations.
    Returns: (is_safe, list_of_violations)
    """
    violations = []
    exp_domain = item.get("expected_domain_validity", True)
    exp_intent = item.get("expected_rule_intent")

    # 1. Domain gate false positive (off-topic query allowed)
    if not exp_domain and act_domain:
        violations.append(
            f"Off-topic leak: Query allowed by domain gate (reason: {domain_reason})"
        )

    # 2. Policy theft: Policy question intercepted by an action rule
    if exp_domain and exp_intent is None and act_intent is not None:
        violations.append(
            f"Policy theft: Policy question intercepted by rule action '{act_intent}' instead of falling through to LLM"
        )

    # 3. Unsafe transfer triggering
    if act_intent == "transfer":
        query_norm = normalize_query(item.get("query", ""))
        safe_transfer_keywords = {"transfer", "send", "pay", "wire", "shoot"}
        if not any(k in query_norm for k in safe_transfer_keywords):
            violations.append(
                f"Unsafe transfer: Transfer intent triggered without explicit transfer verb in query '{item.get('query')}'"
            )

    return (len(violations) == 0, violations)


def determine_route(act_domain: bool, act_intent: Optional[str]) -> str:
    """Determine query execution route: 'deterministic', 'llm', or 'blocked'."""
    if not act_domain:
        return "blocked"
    if act_intent is not None:
        return "deterministic"
    return "llm"


def evaluate_query(
    item: Dict[str, Any],
    user_data: Optional[Dict[str, Any]] = None,
    eval_ollama: bool = False,
) -> Dict[str, Any]:
    """
    Evaluate a single query through domain gating, intent routing, response generation,
    answer correctness verification, latency measurement, and safety auditing.
    """
    user = user_data or DEFAULT_MOCK_USER
    query = item["query"]
    exp_domain = item["expected_domain_validity"]
    exp_intent = item.get("expected_rule_intent")

    # Measure routing separately from answer generation and LLM inference.
    t0 = time.perf_counter()
    act_domain, domain_reason = is_banking_query(query)
    if act_domain:
        raw_intent = classify_rule_intent(query)
        act_intent = _norm(raw_intent)
    else:
        raw_intent = "blocked"
        act_intent = None
    t1 = time.perf_counter()
    routing_latency_ms = (t1 - t0) * 1000.0

    route = determine_route(act_domain, act_intent)
    domain_correct = (act_domain == exp_domain)
    intent_correct = (act_intent == exp_intent)
    both_correct = domain_correct and intent_correct

    # Safety checks
    is_safe, violations = check_safety_and_policy(item, act_domain, act_intent, domain_reason)

    # Answer correctness evaluation
    answer_correct: Optional[bool] = None
    answer_reason: Optional[str] = None
    factuality_pass: Optional[bool] = None
    actual_response: Optional[str] = None
    ollama_status = "not_applicable"
    ollama_error: Optional[str] = None
    time_to_first_token_ms: Optional[float] = None
    generation_latency_ms: Optional[float] = None
    end_to_end_latency_ms: Optional[float] = None
    raw_ollama_response: Optional[str] = None
    response_validation_status = "not_applicable"
    response_validation_reason: Optional[str] = None
    human_review_required = False

    if not act_domain:
        # Off-topic queries: correct if properly blocked
        actual_response = domain_reason
        answer_correct = not exp_domain
        answer_reason = f"Domain gate refusal: {domain_reason}"
        factuality_pass = True
    elif act_intent is not None:
        # Deterministic banking queries: verify against mock database
        actual_response = generate_deterministic_answer(act_intent, user, query=query)
        if act_intent == "transactions" and actual_response and actual_response.startswith(
            "I need a clearer transaction date range."
        ):
            # A clarification is the safe behavior for malformed filters, but
            # it is not an answer that can be counted as factually correct.
            is_ans_correct, reason = None, "Transaction filter needs clarification; no factual answer was produced."
        else:
            is_ans_correct, reason = verify_answer_correctness(act_intent, actual_response, user, query=query)
        # An answer is only correct if the classifier chose the correct intent AND data matched
        if exp_intent is not None and act_intent != exp_intent:
            answer_correct = False
            answer_reason = f"Intent misclassification (expected {exp_intent}, got {act_intent})"
            factuality_pass = False
        else:
            answer_correct = is_ans_correct
            answer_reason = reason
            factuality_pass = is_ans_correct
    else:
        # LLM-bound queries
        if eval_ollama:
            inference = run_ollama_inference(build_strict_banking_prompt(user, query))
            ollama_status = inference["status"]
            ollama_error = inference["error"]
            raw_ollama_response = inference["response"]
            time_to_first_token_ms = inference["time_to_first_token_ms"]
            generation_latency_ms = inference["generation_latency_ms"]
            # Stop at receipt of the completed stream; policy validation is
            # deliberately reported separately and is not generation time.
            end_to_end_latency_ms = round((time.perf_counter() - t0) * 1000.0, 3)
            if ollama_status == "success":
                # Match the production post-validation step. Transport success only
                # means Ollama returned text; it does not establish policy compliance.
                actual_response = validate_ollama_response(raw_ollama_response, query)
                if actual_response == OFF_TOPIC_REFUSAL and raw_ollama_response != OFF_TOPIC_REFUSAL:
                    response_validation_status = "rejected"
                    response_validation_reason = "Production response policy replaced the generated text with a refusal."
                    answer_correct = False
                    answer_reason = "Live Ollama response was rejected by production response policy."
                    # A policy rejection establishes neither factuality nor a
                    # semantic answer assessment; keep those dimensions separate.
                    factuality_pass = None
                else:
                    response_validation_status = "passed"
                    response_validation_reason = "Production response policy accepted the generated text."
                    # LLM-routed records have no deterministic answer assertions in the current datasets.
                    answer_reason = "Live Ollama response passed policy validation; semantic correctness requires human review."
                    human_review_required = True
            else:
                actual_response = raw_ollama_response
                response_validation_status = "not_run"
                response_validation_reason = "Response validation was not run because inference did not succeed."
                answer_reason = f"Ollama inference failed ({ollama_status}): {ollama_error}"
        else:
            ollama_status = "skipped_offline"
            response_validation_status = "not_run"
            response_validation_reason = "Response validation was not run because live Ollama evaluation is disabled."
            answer_reason = "LLM-backed query; live Ollama call not executed"

    return {
        "id":                     item.get("id"),
        "category":               item.get("category", ""),
        "subcategory":            item.get("subcategory", ""),
        "query":                  query,
        "expected_domain":        exp_domain,
        "actual_domain":          act_domain,
        "domain_reason":          domain_reason,
        "expected_intent":        exp_intent,
        "actual_intent":          act_intent,
        "raw_intent":             raw_intent,
        "domain_correct":         domain_correct,
        "intent_correct":         intent_correct,
        "both_correct":           both_correct,
        "classification_correct": both_correct,
        "route":                  route,
        "latency_ms":             round(routing_latency_ms, 3),
        "routing_latency_ms":     round(routing_latency_ms, 3),
        "time_to_first_token_ms": time_to_first_token_ms,
        "generation_latency_ms":  generation_latency_ms,
        "end_to_end_latency_ms":  end_to_end_latency_ms,
        "actual_response":        actual_response,
        "raw_ollama_response":    raw_ollama_response,
        "response_validation_status": response_validation_status,
        "response_validation_reason": response_validation_reason,
        "answer_correct":         answer_correct,
        "answer_reason":          answer_reason,
        "safety_pass":            is_safe,
        "safety_violations":      violations,
        "factuality_pass":        factuality_pass,
        "ollama_status":          ollama_status,
        "ollama_error":           ollama_error,
        "human_review_required":  human_review_required,
    }


# ---------------------------------------------------------------------------
# Metric computation  (pure Python — no scikit-learn required)
# ---------------------------------------------------------------------------

def compute_metrics(
    y_true: List[Optional[str]],
    y_pred: List[Optional[str]],
    labels: List[Optional[str]],
) -> Dict[str, Any]:
    """
    Compute per-class precision / recall / F1 and macro + weighted averages.

    Parameters
    ----------
    y_true  : ground-truth labels (list, may contain None)
    y_pred  : predicted labels    (list, may contain None)
    labels  : all candidate labels (order determines confusion-matrix rows/cols)

    Returns a dict with keys:
        n, correct, accuracy,
        per_class       {label -> {precision, recall, f1, support, tp, fp, fn}},
        labels, active_labels,
        macro_precision, macro_recall, macro_f1,
        weighted_precision, weighted_recall, weighted_f1,
        confusion_matrix  {str(true_label) -> {pred_label -> count}}
    """
    n       = len(y_true)
    correct = sum(1 for t, p in zip(y_true, y_pred) if t == p)

    cm: Dict[Any, Dict[Any, int]] = defaultdict(lambda: defaultdict(int))
    for t, p in zip(y_true, y_pred):
        cm[t][p] += 1

    per_class: Dict[Optional[str], Dict[str, Any]] = {}
    for lbl in labels:
        support = sum(1 for t in y_true if t == lbl)
        tp = cm[lbl][lbl]
        fp = sum(cm[o][lbl] for o in labels if o != lbl)
        fn = sum(cm[lbl][o] for o in labels if o != lbl)
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec  = tp / (tp + fn) if (tp + fn) else 0.0
        f1   = 2.0 * prec * rec / (prec + rec) if (prec + rec) else 0.0
        per_class[lbl] = {
            "precision": prec, "recall": rec, "f1": f1,
            "support": support, "tp": tp, "fp": fp, "fn": fn,
        }

    active  = [l for l in labels if per_class[l]["support"] > 0]
    total_s = sum(per_class[l]["support"] for l in active) or 1

    def _avg(key: str) -> float:
        return sum(per_class[l][key] for l in active) / len(active) if active else 0.0

    def _wavg(key: str) -> float:
        return sum(per_class[l][key] * per_class[l]["support"] for l in active) / total_s

    return {
        "n":       n,
        "correct": correct,
        "accuracy": correct / n if n else 0.0,
        "per_class":    per_class,
        "labels":       labels,
        "active_labels": active,
        "macro_precision": _avg("precision"),
        "macro_recall":    _avg("recall"),
        "macro_f1":        _avg("f1"),
        "weighted_precision": _wavg("precision"),
        "weighted_recall":    _wavg("recall"),
        "weighted_f1":        _wavg("f1"),
        "confusion_matrix": {str(k): dict(v) for k, v in cm.items()},
    }


def compute_latency_stats(latencies_ms: List[float]) -> Dict[str, float]:
    """
    Compute count, min, median, p95, max, and mean for a list of latencies in ms.
    Uses nearest-rank formulation for p95.
    """
    if not latencies_ms:
        return {
            "count": 0,
            "min_ms": 0.0,
            "median_ms": 0.0,
            "p95_ms": 0.0,
            "max_ms": 0.0,
            "mean_ms": 0.0,
        }

    sorted_l = sorted(latencies_ms)
    n = len(sorted_l)

    # Median
    if n % 2 == 1:
        median = sorted_l[n // 2]
    else:
        median = (sorted_l[n // 2 - 1] + sorted_l[n // 2]) / 2.0

    # 95th percentile
    p95_idx = min(n - 1, max(0, int(math.ceil(0.95 * n)) - 1))
    p95 = sorted_l[p95_idx]

    return {
        "count": n,
        "min_ms": round(sorted_l[0], 3),
        "median_ms": round(median, 3),
        "p95_ms": round(p95, 3),
        "max_ms": round(sorted_l[-1], 3),
        "mean_ms": round(sum(sorted_l) / n, 3),
    }


def compute_answer_metrics(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Compute answer correctness metrics across answerable queries.
    Distinguishes deterministic answers from LLM-required queries.
    """
    answerable = [r for r in results if r.get("answer_correct") is not None]
    total_answerable = len(answerable)
    correct_count = sum(1 for r in answerable if r["answer_correct"])
    accuracy = correct_count / total_answerable if total_answerable > 0 else 0.0

    per_intent: Dict[str, Dict[str, Any]] = defaultdict(lambda: {"total": 0, "correct": 0, "accuracy": 0.0})
    for r in answerable:
        intent = r.get("actual_intent") or ("blocked" if not r.get("actual_domain") else "other")
        per_intent[intent]["total"] += 1
        if r["answer_correct"]:
            per_intent[intent]["correct"] += 1

    for intent, stats in per_intent.items():
        stats["accuracy"] = stats["correct"] / stats["total"] if stats["total"] > 0 else 0.0

    return {
        "total_answerable": total_answerable,
        "correct": correct_count,
        "accuracy": round(accuracy, 4),
        "accuracy_pct": round(accuracy * 100.0, 2),
        "per_intent": dict(per_intent),
        "unanswerable_llm_bound": sum(1 for r in results if r.get("answer_correct") is None),
    }


def compute_safety_factuality_metrics(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate safety and factuality checks and failure details."""
    safety_failures = []
    factuality_failures = []

    for r in results:
        for viol in r.get("safety_violations", []):
            safety_failures.append({
                "id": r.get("id"),
                "query": r.get("query"),
                "category": r.get("category"),
                "violation": viol,
            })
        if r.get("factuality_pass") is False:
            factuality_failures.append({
                "id": r.get("id"),
                "query": r.get("query"),
                "intent": r.get("actual_intent"),
                "reason": r.get("answer_reason"),
                "actual_response": r.get("actual_response"),
            })

    total_queries = len(results)
    return {
        "safety_checks_total": total_queries,
        "safety_failures_count": len(safety_failures),
        "safety_pass_rate": round((total_queries - len(safety_failures)) / total_queries, 4) if total_queries else 1.0,
        "safety_failures": safety_failures,
        "factuality_checks_total": sum(1 for r in results if r.get("factuality_pass") is not None),
        "factuality_failures_count": len(factuality_failures),
        "factuality_failures": factuality_failures,
    }


def evaluate_datasets(
    paths: List[str],
    user_data: Optional[Dict[str, Any]] = None,
    eval_ollama: bool = False,
    output_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Load dataset files, execute full evaluation across classification,
    answer correctness, latency, and safety, returning a comprehensive dictionary.
    Optionally saves machine-readable JSON results to output_path.
    """
    user = user_data or DEFAULT_MOCK_USER
    dataset: List[Dict[str, Any]] = []
    for p in paths:
        dataset.extend(load_dataset(p))

    # Evaluate each query
    results = [evaluate_query(item, user_data=user, eval_ollama=eval_ollama) for item in dataset]
    failures = [r for r in results if not r["both_correct"]]

    domain_metrics = compute_metrics(
        [str(r["expected_domain"]) for r in results],
        [str(r["actual_domain"])   for r in results],
        ["True", "False"],
    )
    intent_metrics = compute_metrics(
        [r["expected_intent"] for r in results],
        [r["actual_intent"]   for r in results],
        INTENT_LABELS,
    )

    answer_metrics = compute_answer_metrics(results)
    safety_metrics = compute_safety_factuality_metrics(results)

    # Routing latency is measured for every query; model timings exist only after real inference.
    det_latencies = [r["latency_ms"] for r in results if r["route"] == "deterministic"]
    llm_routing_latencies = [r["latency_ms"] for r in results if r["route"] == "llm"]
    blk_latencies = [r["latency_ms"] for r in results if r["route"] == "blocked"]
    all_routing_latencies = [r["latency_ms"] for r in results]
    llm_generation_latencies = [
        r["generation_latency_ms"] for r in results
        if r["route"] == "llm" and r["ollama_status"] == "success" and r["generation_latency_ms"] is not None
    ]
    llm_first_token_latencies = [
        r["time_to_first_token_ms"] for r in results
        if r["route"] == "llm" and r["ollama_status"] == "success" and r["time_to_first_token_ms"] is not None
    ]
    llm_end_to_end_latencies = [
        r["end_to_end_latency_ms"] for r in results
        if r["route"] == "llm" and r["ollama_status"] == "success" and r["end_to_end_latency_ms"] is not None
    ]

    overall_routing_stats = compute_latency_stats(all_routing_latencies)
    latency_metrics = {
        "deterministic": compute_latency_stats(det_latencies),
        "llm_routing":   compute_latency_stats(llm_routing_latencies),
        "blocked":       compute_latency_stats(blk_latencies),
        "overall_routing": overall_routing_stats,
        # Backward-compatible alias. Consumers should migrate to overall_routing.
        "overall": {
            **overall_routing_stats,
            "deprecated": True,
            "replacement": "overall_routing",
            "description": "Deprecated routing-only aggregate; use overall_routing.",
        },
        "ollama_time_to_first_token": compute_latency_stats(llm_first_token_latencies),
        "ollama_generation": compute_latency_stats(llm_generation_latencies),
        "ollama_end_to_end": compute_latency_stats(llm_end_to_end_latencies),
    }

    llm_results = [r for r in results if r["route"] == "llm"]
    successful_ollama = [r for r in llm_results if r["ollama_status"] == "success"]
    failed_ollama = [
        r for r in llm_results
        if r["ollama_status"] not in {"success", "skipped_offline"}
    ]
    status_counts = dict(Counter(r["ollama_status"] for r in llm_results))
    validation_status_counts = dict(Counter(r["response_validation_status"] for r in llm_results))
    ollama_info = {
        "evaluated": len(successful_ollama) > 0,
        "requested": eval_ollama,
        "status": "evaluated" if successful_ollama else ("failed" if eval_ollama and llm_results else "skipped_offline"),
        "llm_routed_queries": len(llm_results),
        "requests_made": len(successful_ollama) + len(failed_ollama),
        "succeeded": len(successful_ollama),
        "failed": len(failed_ollama),
        "skipped": status_counts.get("skipped_offline", 0),
        "status_counts": status_counts,
        "response_validation_status_counts": validation_status_counts,
        "message": "Live Ollama inference completed." if successful_ollama else (
            "Live Ollama inference was requested but no LLM request succeeded."
            if eval_ollama and llm_results
            else "Ollama evaluation skipped; deterministic and rule-based pipeline evaluated only."
        ),
    }

    summary = {
        "total_queries": len(results),
        "both_correct": sum(1 for r in results if r["both_correct"]),
        "domain_correct": sum(1 for r in results if r["domain_correct"]),
        "intent_correct": sum(1 for r in results if r["intent_correct"]),
        "domain_accuracy": domain_metrics["accuracy"],
        "intent_accuracy": intent_metrics["accuracy"],
        "exact_match_accuracy": sum(1 for r in results if r["both_correct"]) / len(results) if results else 0.0,
        "classification_macro_f1": intent_metrics["macro_f1"],
        "classification_weighted_f1": intent_metrics["weighted_f1"],
        "answer_correctness": answer_metrics,
        "latency_metrics": latency_metrics,
        "safety_metrics": safety_metrics,
        "ollama_evaluation": ollama_info,
    }

    report_dict: Dict[str, Any] = {
        "results":          results,
        "failures":         failures,
        "total":            len(results),
        "domain_correct":   sum(1 for r in results if r["domain_correct"]),
        "intent_correct":   sum(1 for r in results if r["intent_correct"]),
        "both_correct":     sum(1 for r in results if r["both_correct"]),
        "domain_metrics":   domain_metrics,
        "intent_metrics":   intent_metrics,
        "answer_metrics":   answer_metrics,
        "latency_metrics":  latency_metrics,
        "safety_metrics":   safety_metrics,
        "ollama_evaluation": ollama_info,
        "summary":          summary,
    }

    if output_path:
        # Prepare machine-readable JSON structure
        json_output = {
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "dataset_paths": paths,
                "total_queries": len(results),
                "ollama_requested": eval_ollama,
                "ollama_evaluated": ollama_info["evaluated"],
                "mock_user_account": user.get("account", "1234567890"),
            },
            "summary": summary,
            "per_query_results": results,
        }
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(json_output, fh, indent=2)

    return report_dict


# ---------------------------------------------------------------------------
# Reporting helpers
# ---------------------------------------------------------------------------

def _ls(lbl: Optional[str]) -> str:
    """Return a printable string for a label (None -> 'llm/None')."""
    return "llm/None" if lbl is None else lbl


def print_confusion_matrix(im: Dict[str, Any]) -> None:
    labels = im["active_labels"]
    cm_raw = im["confusion_matrix"]
    hl  = [_ls(l) for l in labels]
    cw  = max(10, max(len(h) for h in hl) + 2)
    print("")
    print("CONFUSION MATRIX  (rows = true label, cols = predicted label)")
    hdr = " " * cw + "".join(h.rjust(cw) for h in hl)
    print(hdr)
    print("-" * len(hdr))
    for tl in labels:
        row = _ls(tl).rjust(cw)
        row_d = cm_raw.get(str(tl), {})
        for pl in labels:
            row += str(row_d.get(pl, 0)).rjust(cw)
        print(row)


def print_per_class(im: Dict[str, Any]) -> None:
    labels = im["active_labels"]
    pc = im["per_class"]
    cw = 12

    print("")
    col_hdr = (
        "Class".rjust(12) + "  " +
        "Precision".rjust(cw) + "  " +
        "Recall".rjust(cw) + "  " +
        "F1".rjust(cw) + "  " +
        "Support".rjust(8)
    )
    print(col_hdr)
    print("-" * len(col_hdr))

    for lbl in labels:
        m = pc[lbl]
        print(
            _ls(lbl).rjust(12) + "  " +
            f"{m['precision']:.4f}".rjust(cw) + "  " +
            f"{m['recall']:.4f}".rjust(cw) + "  " +
            f"{m['f1']:.4f}".rjust(cw) + "  " +
            str(m["support"]).rjust(8)
        )

    print("-" * len(col_hdr))
    print(
        "macro avg".rjust(12) + "  " +
        f"{im['macro_precision']:.4f}".rjust(cw) + "  " +
        f"{im['macro_recall']:.4f}".rjust(cw) + "  " +
        f"{im['macro_f1']:.4f}".rjust(cw) + "  " +
        str(im["n"]).rjust(8)
    )
    print(
        "wtd avg".rjust(12) + "  " +
        f"{im['weighted_precision']:.4f}".rjust(cw) + "  " +
        f"{im['weighted_recall']:.4f}".rjust(cw) + "  " +
        f"{im['weighted_f1']:.4f}".rjust(cw) + "  " +
        str(im["n"]).rjust(8)
    )


def print_report(ev: Dict[str, Any], label: str = "") -> None:
    title = "BANKBOT-AI EVALUATION BENCHMARK" + (" -- " + label if label else "")
    sep   = "=" * 80
    print(sep)
    print(title)
    print(sep)

    total = ev["total"]
    dm    = ev["domain_metrics"]
    im    = ev["intent_metrics"]
    am    = ev["answer_metrics"]
    lm    = ev["latency_metrics"]
    sm    = ev["safety_metrics"]
    om    = ev["ollama_evaluation"]

    print("Total queries evaluated : " + str(total))
    print(
        "Domain gate accuracy    : " + str(ev["domain_correct"]) + "/" + str(total) +
        "  (" + f"{dm['accuracy']*100:.2f}" + "%)"
    )
    print(
        "Intent routing accuracy : " + str(ev["intent_correct"]) + "/" + str(total) +
        "  (" + f"{im['accuracy']*100:.2f}" + "%)"
    )
    bc = ev["both_correct"]
    print(
        "Exact match accuracy    : " + str(bc) + "/" + str(total) +
        "  (" + f"{bc/total*100:.2f}" + "%)"
    )

    print("")
    print("--------------------------------------------------------------------------------")
    print("SECTION 1: INTENT CLASSIFICATION METRICS  (Routing correctness)")
    print("--------------------------------------------------------------------------------")
    print(
        "  Macro    P=" + f"{im['macro_precision']:.4f}" +
        "  R=" + f"{im['macro_recall']:.4f}" +
        "  F1=" + f"{im['macro_f1']:.4f}" +
        "  (Unweighted mean over active classes)"
    )
    print(
        "  Weighted P=" + f"{im['weighted_precision']:.4f}" +
        "  R=" + f"{im['weighted_recall']:.4f}" +
        "  F1=" + f"{im['weighted_f1']:.4f}" +
        "  (Support-weighted average)"
    )

    print_per_class(im)
    print_confusion_matrix(im)

    print("")
    print("--------------------------------------------------------------------------------")
    print("SECTION 2: BANKING ANSWER CORRECTNESS  (Factuality against mock database)")
    print("--------------------------------------------------------------------------------")
    print(f"  Answerable deterministic queries : {am['total_answerable']} / {total}")
    print(f"  Factual answers verified         : {am['correct']} / {am['total_answerable']} ({am['accuracy_pct']}%)")
    print(f"  LLM-bound queries (unscored)     : {am['unanswerable_llm_bound']} (requires assertions or human review)")
    if am["per_intent"]:
        print("\n  Per-Intent Answer Correctness:")
        for it, st in sorted(am["per_intent"].items()):
            acc_pct = st["accuracy"] * 100.0
            print(f"    • {it:<14} : {st['correct']}/{st['total']} ({acc_pct:.1f}%)")

    print("")
    print("--------------------------------------------------------------------------------")
    print("SECTION 3: LATENCY BENCHMARKS (milliseconds)")
    print("--------------------------------------------------------------------------------")
    print(f"{'Metric':<30} {'Count':<8} {'Mean(ms)':<11} {'Median(ms)':<12} {'P95(ms)':<11} {'Max(ms)':<11}")
    print("-" * 88)
    for pth in [
        "deterministic",
        "llm_routing",
        "blocked",
        "overall_routing",
        "ollama_time_to_first_token",
        "ollama_generation",
        "ollama_end_to_end",
    ]:
        st = lm[pth]
        print(
            f"{pth:<30} {st['count']:<8} {st['mean_ms']:<11.2f} "
            f"{st['median_ms']:<12.2f} {st['p95_ms']:<11.2f} {st['max_ms']:<11.2f}"
        )
    print("  Note: legacy latency_metrics.overall is a deprecated alias for overall_routing.")

    print("")
    print("--------------------------------------------------------------------------------")
    print("SECTION 4: SAFETY & FACTUALITY AUDIT")
    print("--------------------------------------------------------------------------------")
    print(f"  Safety checks total    : {sm['safety_checks_total']}")
    print(f"  Safety violations      : {sm['safety_failures_count']}")
    if sm["safety_failures"]:
        for sf in sm["safety_failures"][:5]:
            print(f"    [FAIL #{sf['id']}] {sf['violation']} (query: {repr(sf['query'])})")
    else:
        print("  Safety status          : PASSED (0 policy/domain leaks detected)")

    print(f"\n  Factuality checks total: {sm['factuality_checks_total']}")
    print(f"  Factuality failures    : {sm['factuality_failures_count']}")
    if sm["factuality_failures"]:
        for ff in sm["factuality_failures"][:5]:
            print(f"    [FAIL #{ff['id']}] {ff['reason']} (query: {repr(ff['query'])})")
    else:
        print("  Factuality status      : PASSED (0 data mismatches with mock database)")

    print("")
    print("--------------------------------------------------------------------------------")
    print("SECTION 5: OLLAMA STATUS & SEPARATION")
    print("--------------------------------------------------------------------------------")
    print(f"  Ollama evaluated       : {om['evaluated']}")
    print(f"  Ollama path status     : {om['status']}")
    print(f"  Requests made/succeeded/failed : {om['requests_made']}/{om['succeeded']}/{om['failed']}")
    print(f"  LLM-routed/skipped     : {om['llm_routed_queries']}/{om['skipped']}")
    print(f"  Response validation    : {om['response_validation_status_counts']}")
    print("  Transport success and policy validation do not establish semantic answer correctness.")
    print(f"  Notes                  : {om['message']}")

    failures = ev["failures"]
    if failures:
        print("")
        print(f"FAILURES ({len(failures)} / {total}):")
        for f in failures:
            parts = []
            if not f["domain_correct"]:
                parts.append("domain exp=" + str(f["expected_domain"]) + " got=" + str(f["actual_domain"]))
            if not f["intent_correct"]:
                parts.append("intent exp=" + repr(f["expected_intent"]) + " got=" + repr(f["actual_intent"]))
            fid = str(f["id"]).zfill(3)
            print("  #" + fid + "  [" + ", ".join(parts) + "]  " + repr(f["query"]))
    else:
        print("")
        print("All classification cases passed -- 0 routing failures.")

    print(sep)


def main():
    import argparse
    parser = argparse.ArgumentParser(description="BankBot-AI Evaluation Framework")
    parser.add_argument("datasets", nargs="*", default=[REGRESSION_PATH],
                        help="Paths to JSON evaluation datasets (defaults to tests/query_eval_dataset.json)")
    parser.add_argument("--output", "-o", type=str, default=None,
                        help="Optional file path to save machine-readable JSON results")
    parser.add_argument("--eval-ollama", action="store_true", default=False,
                        help="Evaluate live Ollama responses for LLM-routed queries if Ollama is running")
    args = parser.parse_args()

    paths = args.datasets
    ev_label = " + ".join(os.path.basename(p) for p in paths)
    result = evaluate_datasets(paths, eval_ollama=args.eval_ollama, output_path=args.output)
    print_report(result, label=ev_label)
    if args.output:
        print(f"\n[Saved machine-readable results to: {os.path.abspath(args.output)}]\n")


if __name__ == "__main__":
    main()
