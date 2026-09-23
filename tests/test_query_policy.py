import unittest

from app.services.query_policy import classify_rule_intent, is_banking_query


class QueryPolicyTests(unittest.TestCase):
    def test_allows_core_banking_queries(self):
        allowed = [
            "What is my balance?",
            "Show my recent transactions",
            "Show my transaction history",
            "How much did I spend?",
            "Transfer money",
            "Show profile",
            "What is the savings account interest?",
            "What is this interest rate?",
            "home loan interest",
            "UPI limit",
            "branch hours",
        ]
        for query in allowed:
            allowed_flag, _ = is_banking_query(query)
            self.assertTrue(allowed_flag, f"should allow banking query: {query}")

    def test_rejects_off_topic_queries(self):
        blocked = [
            "python coding",
            "tell me a joke",
            "what is the weather",
            "write a poem",
            "world history",
        ]
        for query in blocked:
            allowed_flag, _ = is_banking_query(query)
            self.assertFalse(allowed_flag, f"should reject off-topic query: {query}")

    def test_allows_small_talk(self):
        for query in ["hi", "hello", "hey there", "how are you", "thanks"]:
            allowed_flag, reason = is_banking_query(query)
            self.assertTrue(allowed_flag, query)
            self.assertEqual(reason, "conversation")

    def test_rule_intents_for_demo_queries(self):
        self.assertEqual(classify_rule_intent("What is my balance?"), "balance")
        self.assertEqual(classify_rule_intent("Show my recent transactions"), "transactions")
        self.assertEqual(classify_rule_intent("Show my transaction history"), "transactions")
        self.assertEqual(classify_rule_intent("How much did I spend?"), "spend")
        self.assertEqual(classify_rule_intent("Show profile"), "profile")
        self.assertEqual(classify_rule_intent("Transfer money"), "transfer")
        self.assertEqual(classify_rule_intent("hi"), "greeting")
        self.assertEqual(classify_rule_intent("help"), "help")

    def test_does_not_steal_policy_questions(self):
        self.assertEqual(classify_rule_intent("What is the savings account interest?"), "llm")
        self.assertEqual(classify_rule_intent("What is this interest rate?"), "llm")
        self.assertEqual(classify_rule_intent("home loan policy"), "llm")
        self.assertEqual(classify_rule_intent("UPI limit"), "llm")

    def test_allows_expanded_banking_vocabulary(self):
        """Regression test: natural phrasing like spending, expenses, funds, pay, details, mutual fund."""
        expanded_queries = [
            "What are my available funds?",
            "Show my spending analysis",
            "What are my total expenses this month?",
            "Show my spending breakdown",
            "Show my details",
            "How do I pay someone?",
            "can you explain what a mutual fund is",
        ]
        for query in expanded_queries:
            allowed_flag, _ = is_banking_query(query)
            self.assertTrue(allowed_flag, f"should allow expanded query: {query}")

    def test_allows_farewells_as_conversation(self):
        """Regression test: goodbye/bye queries should be accepted as conversation."""
        farewells = ["bye", "goodbye", "bye bankbot", "goodbye see you later"]
        for query in farewells:
            allowed_flag, reason = is_banking_query(query)
            self.assertTrue(allowed_flag, f"should allow farewell: {query}")
            self.assertEqual(reason, "conversation")
            self.assertEqual(classify_rule_intent(query), "goodbye")

    def test_distinguishes_personal_history_from_general_history(self):
        """Regression test: personal history is allowed while general history is blocked."""
        personal_history = [
            "show my history",
            "Show my transaction history",
            "Show my account history",
            "my history",
        ]
        for query in personal_history:
            allowed_flag, _ = is_banking_query(query)
            self.assertTrue(allowed_flag, f"should allow personal history: {query}")
            self.assertEqual(classify_rule_intent(query), "transactions")

        general_history = [
            "history of banking",
            "world history",
            "explain the history of ancient Rome",
        ]
        for query in general_history:
            allowed_flag, _ = is_banking_query(query)
            self.assertFalse(allowed_flag, f"should reject general history: {query}")

    def test_rejects_off_topic_even_with_banking_words(self):
        """Regression test: off-topic requests containing banking keywords must still be blocked."""
        adversarial_queries = [
            "tell me a joke about money",
            "write python code to calculate bank interest",
            "what is the weather near the bank branch",
            "recipe for bank holiday chocolate cake",
            "science behind banking algorithms",
            "how much money does Bill Gates make",
        ]
        for query in adversarial_queries:
            allowed_flag, _ = is_banking_query(query)
            self.assertFalse(allowed_flag, f"should reject off-topic query with banking words: {query}")

    def test_does_not_steal_fee_limit_policy_questions(self):
        """Regression test: policy, fee, limit, and card settings questions must fall through to LLM."""
        policy_queries = [
            "What is the daily UPI transfer limit?",
            "What is the RTGS transfer fee?",
            "Are there any charges for ATM withdrawals after 5 free transactions?",
            "Is there a penalty fee for minimum balance violation?",
            "How can I enable international transactions on my card?",
            "what is my rate",
            "how much cash can I withdraw at the ATM",
        ]
        for query in policy_queries:
            self.assertEqual(classify_rule_intent(query), "llm", f"query should fall through to llm: {query}")

    def test_classifies_expanded_deterministic_intents(self):
        """Regression test: newly supported deterministic queries map to expected rule intents."""
        test_cases = [
            ("what happened recently", "transactions"),
            ("tell me about my account", "profile"),
            ("how much did I pay", "spend"),
            ("where did all my money go", "spend"),
            ("can I get a bank statement for last month", "transactions"),
            ("what is my account number", "profile"),
            ("can I send money", "transfer"),
            ("how to send funds to John", "transfer"),
        ]
        for query, expected_intent in test_cases:
            self.assertEqual(classify_rule_intent(query), expected_intent, f"intent mismatch for: {query}")


if __name__ == "__main__":
    unittest.main()
