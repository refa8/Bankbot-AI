from datetime import datetime

import pandas as pd

TRANSACTION_COLUMNS = ["date", "desc", "cat", "amt", "type"]


def format_currency(amount):
    return f"Rs. {amount:,.2f}"


def generate_fast_title(first_prompt):
    return (first_prompt[:30] + "...") if len(first_prompt) > 30 else first_prompt


def safe_transactions_frame(transactions):
    """Build a transactions DataFrame that always has the expected columns."""
    if not isinstance(transactions, list) or len(transactions) == 0:
        return pd.DataFrame(columns=TRANSACTION_COLUMNS)

    df = pd.DataFrame(transactions)
    for col in TRANSACTION_COLUMNS:
        if col not in df.columns:
            df[col] = 0.0 if col == "amt" else ""
    return df


def history_trend_xy(history, end=None):
    """Return matching x/y arrays for a balance history series."""
    if not isinstance(history, list) or len(history) == 0:
        return [], []

    end_time = end if end is not None else datetime.now()
    dates = pd.date_range(end=end_time, periods=len(history)).strftime("%b %d")
    return list(dates), list(history)
