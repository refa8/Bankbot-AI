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


if __name__ == "__main__":
    unittest.main()
