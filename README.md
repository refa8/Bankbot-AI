# BankBot-AI

BankBot-AI is a local demo banking assistant built with Streamlit, a rule-first
query-policy layer, optional local Ollama generation, a JSON demo store, and a
small Flask API. It is an interview project, not a production banking system.

## What is implemented

- Hybrid chatbot routing: domain gating, deterministic account intents, and an
  Ollama fallback for banking-policy questions.
- Deterministic balance, transactions, spending, profile, transfer guidance,
  greeting, goodbye, and help responses using the signed-in demo account data.
- Streamed Ollama responses with timeout, unavailable-service, malformed-stream,
  empty-response, and unavailable-model handling.
- Plotly/Pandas Streamlit dashboard and persisted chat history in the demo JSON
  database.
- Flask endpoints for health, login, balance, transactions, transfer, and logout.
- bcrypt PIN verification, token sessions with inactivity expiry, login rate
  limiting, input validation, and JSON API error responses.
- Offline routing/factuality evaluation, a 700-record policy-derived benchmark,
  and a component end-to-end benchmark.

## Architecture

```text
Streamlit UI (bankbot.py)
  -> query policy (app/services/query_policy.py)
       -> deterministic response from current demo account data
       -> or one streamed Ollama request, then response-policy validation
  -> JSON demo store (bank_db.json)

Flask API (app/api.py)
  -> shared security helpers (security.py)
  -> JSON demo store (isolated temporary stores in tests/benchmarks)
```

The classifier is rule-first, not a separate ML classifier. It normalizes common
phrasings and typos, blocks strong off-topic signals, reserves banking policy
questions for the LLM, and selects a single deterministic action only when safe.

## Setup

Python 3.10+ is recommended. Create an environment, then install the one
canonical dependency file:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Configuration is read from environment variables (and `.env` when present):

```text
DATABASE_FILE=bank_db.json
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=llama3.2
OLLAMA_TIMEOUT=120
SESSION_TIMEOUT_MINUTES=15
MAX_LOGIN_ATTEMPTS=5
LOCKOUT_MINUTES=15
```

Use a non-default `SECRET_KEY` outside local development. Do not commit `.env`
or a database containing real credentials or customer data.

For local LLM features, install Ollama separately and make the configured model
available, for example:

```powershell
ollama pull llama3.2
ollama serve
```

## Run

Start the Streamlit application:

```powershell
streamlit run bankbot.py
```

Start the API in another terminal:

```powershell
python -m flask --app app.api run --host 127.0.0.1 --port 5000
```

API endpoints:

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/api/health` | Health response |
| `POST` | `/api/login` | Issue a Bearer token from a 10-digit account and 4-digit PIN |
| `GET` | `/api/balance` | Authenticated account balance |
| `GET` | `/api/transactions?limit=N` | Authenticated transaction list; `N` must be positive |
| `POST` | `/api/transfers` | Authenticated JSON transfer with `recipient` and numeric `amount` |
| `POST` | `/api/logout` | Invalidate the supplied Bearer token |

Transfers are constrained to ₹1–₹50,000 and persist an atomic JSON-file update.
They are demo operations only; recipients are not real bank accounts.

## Evaluation and tests

Validate the static benchmark schema and uniqueness:

```powershell
python tests/validate_benchmark_700.py
```

Run the reproducible offline benchmark. It measures domain gating, intent routing,
deterministic/mock-data answer checks, safety checks, and routing latency. It does
not call Ollama:

```powershell
python evaluate_metrics.py tests/benchmark_700.json --output benchmark_700_results.json
```

Run the small, hand-authored account-response regression set. It covers date and
limit phrasing, malformed ranges, ambiguous requests, and a third-party account
request. It is a development regression set, not an independent held-out result:

```powershell
python evaluate_metrics.py tests/account_accuracy_cases.json --output account_accuracy_results.json
```

Run the component benchmark (deterministic chatbot, isolated transfer contract,
in-process Flask API, security, and reliability checks):

```powershell
python e2e_benchmark.py --output e2e_benchmark_results.json
```

Run the small live reference evaluation only when Ollama is running:

```powershell
python e2e_benchmark.py --eval-ollama --output e2e_live_results.json
```

Run the selected 30- or 100-query live-routing subsets when a larger local-model
sample is appropriate:

```powershell
python evaluate_metrics.py tests/benchmark_ollama_smoke.json --eval-ollama --output ollama_smoke_results.json
python evaluate_metrics.py tests/benchmark_ollama_100.json --eval-ollama --output ollama_100_results.json
```

Run all automated tests:

```powershell
python -m unittest discover -s tests -v
```

## How to read the metrics

The reports keep these dimensions separate:

- **Routing accuracy/F1:** expected domain and rule intent versus the current
  query-policy result.
- **Deterministic answer correctness:** only answers verified against the mock
  account data. LLM-bound records are excluded from this denominator.
- **LLM transport and policy validation:** successful streaming and a policy-
  accepted response are not semantic correctness.
- **LLM semantic correctness:** scored only where an explicit authoritative
  reference criterion exists; otherwise it remains unscored/human-review.
- **Latency:** routing latency is not model generation time. Live reports expose
  time-to-first-token, completed generation, and LLM end-to-end timing separately.
  The component benchmark separately reports isolated transfer logic and
  in-process API request timing. Its `latency` section reports p50, p95, mean,
  and sample count for routing, deterministic balance/transaction responses,
  bcrypt login, warm authenticated API reads, and login-plus-balance requests.

The 700-query dataset is versioned in `tests/benchmark_700.json`; its manifest
states clearly that it is newly authored but policy-derived, not an independent
held-out benchmark. Do not cite its score as general real-world accuracy.

### Recorded local measurements (2026-09-29)

On the local single-process fixture described in the report, the offline
700-record run produced 99.00% intent-routing accuracy and 98.99% weighted F1.
Its data-grounded answer denominator was 465 records: balance was 40/40 and
transactions 31/31. These figures meet the stated balance/transaction targets
for this policy-derived mock-data workload; they are not independent production
accuracy estimates.

The repeated latency workload recorded routing p50/p95 of 0.95/1.36 ms (n=30),
deterministic balance response p95 of 0.02 ms (n=10), deterministic transaction
response p95 of 0.10 ms (n=10), and warm authenticated balance API p95 of 1.47
ms (n=10). Bcrypt login p95 was 472.15 ms and login-plus-balance API p95 was
463.63 ms (n=10); bcrypt's work factor was not reduced. No source or timing
boundary for the historical 45 ms/120 ms figures exists in this repository.
Treat the warm routing/API results as comparable local targets, not network-load
or LLM latency claims.

## Current limitations

- JSON storage, in-memory sessions, and in-memory rate limiting are suitable only
  for a single-process demo; use a transactional database and shared session/rate
  limit store for deployment.
- Flask test-client timings exclude network, TLS, reverse proxy, and concurrent
  load effects.
- The application is not a real payments system and has no recipient verification,
  idempotency key, audit service, or external banking integration.
- The LLM can still produce unsupported banking statements; response policy checks
  are guardrails, not a factuality guarantee.
- The benchmark does not prove security. It provides regression checks for the
  specific controls implemented here.
