"""
app/api.py

Lightweight, authenticated REST API for BankBot-AI.
Provides authenticated access to account balance and transaction history.
Reuses existing security components (SessionManager, PasswordHasher, RateLimiter, InputValidator).
"""

import json
import os
import tempfile
from datetime import date, datetime
from typing import Dict, Optional, Tuple

from flask import Flask, jsonify, request
from werkzeug.exceptions import HTTPException

from config import settings
from app.services.account_responses import filter_transactions
from security import InputValidator, PasswordHasher, RateLimiter, SessionManager


def create_app(
    db_file: Optional[str] = None,
    session_timeout_minutes: Optional[int] = None,
    max_login_attempts: Optional[int] = None,
    lockout_minutes: Optional[int] = None,
) -> Flask:
    """Create the demo API application.

    Optional security settings are primarily useful for isolated tests; omitted
    values always use the configured production defaults.
    """
    app = Flask(__name__)

    db_path = db_file or os.getenv("DATABASE_FILE", settings.DATABASE_FILE)
    password_hasher = PasswordHasher()
    session_timeout = session_timeout_minutes if session_timeout_minutes is not None else settings.SESSION_TIMEOUT_MINUTES
    max_attempts = max_login_attempts if max_login_attempts is not None else settings.MAX_LOGIN_ATTEMPTS
    lockout_duration = lockout_minutes if lockout_minutes is not None else settings.LOCKOUT_MINUTES
    session_manager = SessionManager(timeout_minutes=session_timeout)
    rate_limiter = RateLimiter(
        max_attempts=max_attempts,
        lockout_minutes=lockout_duration,
    )
    input_validator = InputValidator()

    # In-memory active session registry: {token: session_dict}
    active_sessions: Dict[str, dict] = {}

    @app.errorhandler(HTTPException)
    def handle_http_error(error: HTTPException):
        """Keep API errors machine-readable, including routing errors."""
        return jsonify({"error": error.description}), error.code

    def _load_db() -> dict:
        if os.path.exists(db_path):
            try:
                with open(db_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    return data if isinstance(data, dict) else {}
            except (OSError, json.JSONDecodeError):
                return {}
        return {}

    def _save_db(data: dict) -> bool:
        """Atomically persist a completed transfer to the demo JSON database."""
        directory = os.path.dirname(os.path.abspath(db_path))
        temp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                "w", encoding="utf-8", dir=directory, delete=False
            ) as temp_file:
                temp_path = temp_file.name
                json.dump(data, temp_file, ensure_ascii=False, indent=2)
                temp_file.flush()
                os.fsync(temp_file.fileno())
            os.replace(temp_path, db_path)
            return True
        except (OSError, TypeError, ValueError):
            if temp_path:
                try:
                    os.unlink(temp_path)
                except OSError:
                    pass
            return False

    def _get_authenticated_user() -> Tuple[Optional[str], Optional[dict], Optional[Tuple[dict, int]]]:
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return None, None, ({"error": "Missing or malformed Authorization header. Expected 'Bearer <token>'."}, 401)

        token = auth_header.split(" ", 1)[1].strip()
        session = active_sessions.get(token)

        if not session or not session_manager.is_session_valid(session):
            if token in active_sessions:
                del active_sessions[token]
            return None, None, ({"error": "Invalid or expired session token. Please log in again."}, 401)

        session_manager.update_activity(session)
        user_id = session.get("user_id")

        db = _load_db()
        user = db.get(user_id)
        if not user:
            return None, None, ({"error": "Account not found."}, 404)

        return user_id, user, None

    @app.route("/api/health", methods=["GET"])
    def health():
        return jsonify({
            "status": "healthy",
            "service": "BankBot REST API",
            "version": "1.0.0"
        }), 200

    @app.route("/api/login", methods=["POST"])
    def login():
        data = request.get_json(silent=True)
        if not data or not isinstance(data, dict):
            return jsonify({"error": "Invalid JSON body. Expected 'account' and 'pin'."}), 400

        account = data.get("account", "")
        pin = data.get("pin", "")

        # 1. Format validation
        account_err = input_validator.validate_account_number(account)
        if account_err:
            return jsonify({"error": account_err}), 400

        pin_err = input_validator.validate_pin(pin)
        if pin_err:
            return jsonify({"error": pin_err}), 400

        account = account.strip()
        pin = pin.strip()

        # 2. Rate limiting check
        is_locked, lock_msg = rate_limiter.is_locked_out(account)
        if is_locked:
            return jsonify({"error": lock_msg}), 429

        # 3. Credential verification
        db = _load_db()
        user = db.get(account)
        if not user:
            rate_limiter.record_attempt(account)
            return jsonify({"error": "Invalid account number or PIN."}), 401

        hashed_pin = user.get("hashed_pin", "")
        if not hashed_pin or not password_hasher.verify_password(pin, hashed_pin):
            rate_limiter.record_attempt(account)
            return jsonify({"error": "Invalid account number or PIN."}), 401

        # 4. Successful authentication -> issue session token
        rate_limiter.reset_attempts(account)
        session = session_manager.create_session(account)
        token = session["token"]
        active_sessions[token] = session

        return jsonify({
            "message": "Login successful",
            "token": token,
            "account": account,
            "name": user.get("name", "Customer"),
            "token_type": "Bearer",
            "expires_in_minutes": session_timeout
        }), 200

    @app.route("/api/balance", methods=["GET"])
    def get_balance():
        user_id, user, err = _get_authenticated_user()
        if err:
            return jsonify(err[0]), err[1]

        return jsonify({
            "account": user_id,
            "balance": user.get("balance", 0.0),
            "currency": "INR",
            "account_type": user.get("type", "Standard"),
            "credit_score": user.get("credit_score", "N/A")
        }), 200

    @app.route("/api/transactions", methods=["GET"])
    def get_transactions():
        user_id, user, err = _get_authenticated_user()
        if err:
            return jsonify(err[0]), err[1]

        raw_limit = request.args.get("limit")
        limit = None
        if raw_limit is not None:
            try:
                limit = int(raw_limit)
            except (TypeError, ValueError):
                return jsonify({"error": "limit must be a positive integer."}), 400
            if limit <= 0:
                return jsonify({"error": "limit must be a positive integer."}), 400

        def parse_date_parameter(name: str) -> Optional[date]:
            value = request.args.get(name)
            if value is None:
                return None
            try:
                return date.fromisoformat(value)
            except ValueError:
                raise ValueError(f"{name} must use YYYY-MM-DD format.")

        try:
            start_date = parse_date_parameter("start_date")
            end_date = parse_date_parameter("end_date")
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        if start_date and end_date and start_date > end_date:
            return jsonify({"error": "start_date must be on or before end_date."}), 400

        all_transactions = user.get("transactions", [])
        txs = filter_transactions(all_transactions, limit=limit, start_date=start_date, end_date=end_date)

        return jsonify({
            "account": user_id,
            "total_transactions": len(all_transactions) if isinstance(all_transactions, list) else 0,
            "filtered_transactions": len(txs),
            "transactions": txs
        }), 200

    @app.route("/api/transfers", methods=["POST"])
    def create_transfer():
        """Create and persist a debit transfer for the authenticated account."""
        user_id, user, err = _get_authenticated_user()
        if err:
            return jsonify(err[0]), err[1]

        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({"error": "Invalid JSON body. Expected 'recipient' and 'amount'."}), 400

        amount = data.get("amount")
        amount_err = input_validator.validate_amount(amount, max_amount=50000.0)
        if amount_err:
            return jsonify({"error": amount_err}), 400
        amount = float(amount)

        recipient = input_validator.sanitize_text(data.get("recipient"))
        if not recipient:
            return jsonify({"error": "Recipient is required and must be text."}), 400
        if len(recipient) > 100:
            return jsonify({"error": "Recipient must be 100 characters or fewer."}), 400

        balance = user.get("balance")
        if isinstance(balance, bool) or not isinstance(balance, (int, float)):
            return jsonify({"error": "Account balance is unavailable."}), 503
        balance = float(balance)
        if balance < amount:
            return jsonify({"error": "Insufficient balance for this transfer."}), 409

        transaction = {
            "date": datetime.now().strftime("%Y-%m-%d"),
            "desc": f"Transfer to {recipient}",
            "cat": "Transfer",
            "amt": -amount,
            "type": "Debit",
        }
        db = _load_db()
        persisted_user = db.get(user_id)
        if not isinstance(persisted_user, dict):
            return jsonify({"error": "Account not found."}), 404

        persisted_user["balance"] = balance - amount
        transactions = persisted_user.setdefault("transactions", [])
        if not isinstance(transactions, list):
            return jsonify({"error": "Account transaction data is unavailable."}), 503
        transactions.insert(0, transaction)

        if not _save_db(db):
            return jsonify({"error": "Unable to persist transfer. No transfer was completed."}), 503

        return jsonify({
            "message": "Transfer completed successfully.",
            "account": user_id,
            "recipient": recipient,
            "amount": amount,
            "balance": persisted_user["balance"],
            "transaction": transaction,
        }), 201

    @app.route("/api/logout", methods=["POST"])
    def logout():
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1].strip()
            active_sessions.pop(token, None)

        return jsonify({"message": "Successfully logged out."}), 200

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
