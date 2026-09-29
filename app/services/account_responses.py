"""Authoritative deterministic account-response helpers.

These helpers deliberately operate on the caller-provided account record.  They
do not load a database or infer an account identifier, preventing a chat or API
caller from accidentally receiving another user's data.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta
import math
import re
from typing import Any, Dict, List, Optional, Tuple

from app.utils.formatting import format_currency


class TransactionFilterError(ValueError):
    """The query requested a transaction filter that cannot be interpreted."""


def _valid_amount(value: Any) -> Optional[float]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    amount = float(value)
    return amount if math.isfinite(amount) else None


def balance_response(user_data: Dict[str, Any]) -> str:
    """Return the supplied user's current balance, never a model-generated value."""
    balance = _valid_amount(user_data.get("balance"))
    if balance is None:
        return "I cannot retrieve a valid balance for this account right now."
    account_type = user_data.get("type", "account")
    credit_score = user_data.get("credit_score", "N/A")
    return (
        f"Your account balance is **{format_currency(balance)}** in your {account_type} account. "
        f"Looking good!\n\n💳 Credit Score: {credit_score}"
    )


def _parse_iso_date(value: str, label: str) -> date:
    try:
        return date.fromisoformat(value)
    except (TypeError, ValueError) as exc:
        raise TransactionFilterError(f"{label} must use YYYY-MM-DD format.") from exc


def transaction_filters(
    query: str,
    *,
    today: Optional[date] = None,
    default_limit: int = 3,
) -> Tuple[Optional[int], Optional[date], Optional[date]]:
    """Extract explicit, conservative count and ISO/relative-date filters.

    Unrecognised prose is not treated as a date filter.  A malformed explicit
    ISO range raises so the UI can ask for clarification instead of showing an
    unrelated set of transactions.
    """
    text = (query or "").casefold()
    current_day = today or date.today()
    limit = default_limit

    count_match = re.search(r"\b(?:last|latest|recent)\s+(\d{1,2})\s+(?:transactions?|payments?|entries)\b", text)
    if count_match:
        limit = int(count_match.group(1))
        if limit < 1 or limit > 50:
            raise TransactionFilterError("Please request between 1 and 50 transactions.")

    iso_values = re.findall(r"\b\d{4}-\d{2}-\d{2}\b", text)
    if "from" in text or "between" in text:
        if len(iso_values) != 2:
            raise TransactionFilterError("Please provide both dates as YYYY-MM-DD.")
        start, end = _parse_iso_date(iso_values[0], "Start date"), _parse_iso_date(iso_values[1], "End date")
        if start > end:
            raise TransactionFilterError("Start date must be on or before end date.")
        return limit, start, end
    if "on" in text and iso_values:
        selected = _parse_iso_date(iso_values[0], "Date")
        return limit, selected, selected
    if iso_values:
        raise TransactionFilterError("Use 'on', 'from', or 'between' with YYYY-MM-DD dates.")

    if "yesterday" in text:
        selected = current_day - timedelta(days=1)
        return limit, selected, selected
    if "today" in text:
        return limit, current_day, current_day
    if "last week" in text:
        this_monday = current_day - timedelta(days=current_day.weekday())
        return limit, this_monday - timedelta(days=7), this_monday - timedelta(days=1)
    if "this week" in text:
        return limit, current_day - timedelta(days=current_day.weekday()), current_day
    return limit, None, None


def filter_transactions(
    transactions: Any,
    *,
    limit: Optional[int] = None,
    start_date: Optional[date] = None,
    end_date: Optional[date] = None,
) -> List[Dict[str, Any]]:
    """Filter stored transactions without changing their authoritative order."""
    if not isinstance(transactions, list):
        return []
    selected: List[Dict[str, Any]] = []
    for transaction in transactions:
        if not isinstance(transaction, dict):
            continue
        if start_date is not None or end_date is not None:
            try:
                transaction_date = date.fromisoformat(str(transaction.get("date", "")))
            except ValueError:
                continue
            if start_date is not None and transaction_date < start_date:
                continue
            if end_date is not None and transaction_date > end_date:
                continue
        selected.append(transaction)
        if limit is not None and len(selected) >= limit:
            break
    return selected


def transactions_response(
    user_data: Dict[str, Any],
    query: str = "",
    *,
    today: Optional[date] = None,
) -> str:
    """Build an ordered, data-grounded transaction response for one account."""
    try:
        limit, start_date, end_date = transaction_filters(query, today=today)
    except TransactionFilterError as exc:
        return f"I need a clearer transaction date range. {exc}"

    transactions = filter_transactions(
        user_data.get("transactions", []), limit=limit, start_date=start_date, end_date=end_date
    )
    if start_date and end_date:
        heading = f"transactions from {start_date.isoformat()} to {end_date.isoformat()}"
    else:
        heading = "recent transactions"
    message = f"Here are your last {len(transactions)} {heading}:\n\n"
    if not transactions:
        return message + "No transactions matched that request."

    for transaction in transactions:
        transaction_type = transaction.get("type", "Debit")
        emoji = "✅" if transaction_type == "Credit" else "💸"
        amount = _valid_amount(transaction.get("amt"))
        formatted_amount = format_currency(amount) if amount is not None else "Unavailable"
        message += (
            f"{emoji} **{transaction.get('date', 'Unknown date')}** - {transaction.get('desc', 'Unknown transaction')}\n"
            f"   Amount: {formatted_amount} | Category: {transaction.get('cat', 'Uncategorised')}\n\n"
        )
    return message
