import json
import os
import unittest

import pandas as pd
import plotly.graph_objects as go

from app.utils.formatting import history_trend_xy, safe_transactions_frame


def _metric_values(df):
    total_income = df[df['type'] == 'Credit']['amt'].sum() if not df.empty else 0
    total_expense = abs(df[df['type'] == 'Debit']['amt'].sum()) if not df.empty else 0
    avg_transaction = df['amt'].abs().mean() if not df.empty else 0
    if pd.isna(avg_transaction):
        avg_transaction = 0
    spending = df[df['type'] == 'Debit'].copy() if not df.empty else pd.DataFrame(columns=df.columns)
    if not spending.empty:
        spending['amt'] = spending['amt'].abs()
        category_totals = spending.groupby('cat')['amt'].sum().reset_index()
    else:
        category_totals = pd.DataFrame(columns=['cat', 'amt'])
    return total_income, total_expense, avg_transaction, category_totals


def _build_trend_figure(history):
    dates, history_values = history_trend_xy(history)
    if not history_values:
        return dates, history_values, None
    fig = go.Figure(go.Scatter(x=dates, y=history_values, fill='tozeroy'))
    return dates, history_values, fig


class DashboardDataTests(unittest.TestCase):
    def test_empty_history(self):
        dates, values, fig = _build_trend_figure([])
        self.assertEqual(dates, [])
        self.assertEqual(values, [])
        self.assertEqual(len(dates), len(values))
        self.assertIsNone(fig)

    def test_empty_transactions(self):
        df = safe_transactions_frame([])
        total_income, total_expense, avg_transaction, category_totals = _metric_values(df)
        self.assertEqual(total_income, 0)
        self.assertEqual(total_expense, 0)
        self.assertEqual(avg_transaction, 0)
        self.assertTrue(category_totals.empty)
        self.assertListEqual(list(df.columns), ['date', 'desc', 'cat', 'amt', 'type'])
        _ = df[['date', 'desc', 'cat', 'amt', 'type']]

    def test_one_history_record(self):
        dates, values, fig = _build_trend_figure([25348.5])
        self.assertEqual(len(dates), 1)
        self.assertEqual(len(values), 1)
        self.assertEqual(dates, list(fig.data[0].x))
        self.assertEqual(list(fig.data[0].y), values)

    def test_more_than_six_history_records(self):
        history = [42000, 43500, 45000, 44800, 44200, 45750, 45449.5, 40449.5, 35449.5, 35448.5, 30448.5, 30348.5, 25348.5]
        dates, values, fig = _build_trend_figure(history)
        self.assertEqual(len(history), 13)
        self.assertEqual(len(dates), 13)
        self.assertEqual(len(values), 13)
        self.assertEqual(len(dates), len(values))
        self.assertNotEqual(len(dates), 6)
        self.assertEqual(list(fig.data[0].x), dates)
        self.assertEqual(list(fig.data[0].y), values)

    def test_demo_database_if_present(self):
        db_path = os.path.join(os.path.dirname(__file__), '..', 'bank_db.json')
        db_path = os.path.abspath(db_path)
        if not os.path.exists(db_path):
            self.skipTest('bank_db.json is not present')

        with open(db_path, 'r', encoding='utf-8') as handle:
            data = json.load(handle)

        user = data['1234567890']
        df = safe_transactions_frame(user.get('transactions', []))
        _metric_values(df)
        dates, values, fig = _build_trend_figure(user.get('history', []))
        self.assertEqual(len(dates), len(values))
        self.assertGreater(len(values), 6)
        self.assertIsNotNone(fig)
        self.assertFalse(df.empty)


if __name__ == '__main__':
    unittest.main()
