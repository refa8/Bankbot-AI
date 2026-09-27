"""
app/api.py

Lightweight, authenticated REST API for BankBot-AI.
Provides authenticated access to account balance and transaction history.
Reuses existing security components (SessionManager, PasswordHasher, RateLimiter, InputValidator).
"""

import json
import os
from typing import Dict, Optional, Tuple

from flask import Flask, jsonify, request

from config import settings
from security import InputValidator, PasswordHasher, RateLimiter, SessionManager


def create_app(db_file: Optional[str] = None) -> Flask:
    app = Flask(__name__)

    db_path = db_file or os.getenv("DATABASE_FILE", settings.DATABASE_FILE)
    password_hasher = PasswordHasher()
    session_manager = SessionManager(timeout_minutes=settings.SESSION_TIMEOUT_MINUTES)
    rate_limiter = RateLimiter(
        max_attempts=settings.MAX_LOGIN_ATTEMPTS,
        lockout_minutes=settings.LOCKOUT_MINUTES,
    )
    input_validator = InputValidator()

    # In-memory active session registry: {token: session_dict}
    active_sessions: Dict[str, dict] = {}

    def _load_db() -> dict:
        if os.path.exists(db_path):
            try:
                with open(db_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

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
            "expires_in_minutes": settings.SESSION_TIMEOUT_MINUTES
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

        limit = request.args.get("limit", default=None, type=int)
        txs = user.get("transactions", [])
        if limit is not None and limit > 0:
            txs = txs[:limit]

        return jsonify({
            "account": user_id,
            "total_transactions": len(user.get("transactions", [])),
            "transactions": txs
        }), 200

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
