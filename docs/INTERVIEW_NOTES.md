# BankBot-AI interview notes

## One-minute walkthrough

BankBot uses a hybrid route: `is_banking_query` gates strong off-topic prompts,
`classify_rule_intent` handles unambiguous account actions, and only remaining
banking-policy questions call local Ollama. This gives fast, data-grounded answers
for balance, transactions, spending, profile, and transfer guidance, while still
supporting open-ended banking questions. The streamed LLM output is passed through
the same response-policy validator before display.

## Design choices to explain

- The deterministic path reads the current signed-in account's JSON data rather
  than asking the model to invent balance or transaction values.
- Ollama is called once per LLM-routed user message; transport failures, malformed
  chunks, empty streams, and missing models become user-facing errors.
- bcrypt stores PIN hashes, not plaintext PINs. API tokens are server-side session
  records with inactivity expiry; failed logins are rate-limited per account.
- The REST API mirrors the demo store. Transfers validate a finite numeric amount,
  recipient text, maximum amount, and available balance, then use atomic file
  replacement to persist the debit and transaction together.
- Streamlit analytics uses Pandas and Plotly. It is presentation/analysis over
  demo transaction history, not an accounting ledger.

## Evaluation story

- `evaluate_metrics.py` runs the 700-record routing benchmark and reports domain
  accuracy, intent metrics, verified deterministic-answer accuracy, safety checks,
  and separately defined latency.
- `e2e_benchmark.py` exercises deterministic chat, isolated transfer state,
  Flask requests, security helpers, optional live Ollama reference cases, and
  repeated local timing workloads. It reports routing, deterministic-response,
  bcrypt-login, warm authenticated API, and login-plus-balance latency separately.
- A nonempty or policy-accepted LLM answer is never counted as semantically
  correct. It needs an explicit reference criterion; unsupported policy questions
  remain unscored and require review.
- The 700 records are policy-derived, not an independent holdout. State the sample
  size and denominator whenever quoting a metric.
- `tests/account_accuracy_cases.json` is hand-authored development regression
  coverage. It found and now protects the third-party account-data refusal; it
  must not be presented as independent validation.

## Honest limitations

This is a single-process demo: JSON persistence, tokens, and the limiter do not
scale across workers. The API benchmark uses Flask's in-process test client, so it
is not a network-load benchmark. Local model latency varies significantly by
hardware and model warm-up. Security tests demonstrate specific regressions, not a
security certification.

## Current measured figures

The documented 45 ms routing and 120 ms API targets have no implementation note
or measurement boundary in the repository. The reproducible local workload on
2026-09-29 measured routing p95 1.36 ms (30 samples), warm authenticated balance
API p95 1.47 ms (10 samples), and login-plus-balance p95 463.63 ms (10 samples).
The latter includes bcrypt and intentionally does not meet 120 ms. Explain that
the difference is authentication cost, not a reason to lower bcrypt rounds.
