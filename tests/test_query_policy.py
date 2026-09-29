import unittest

from app.services.query_policy import (
    OFF_TOPIC_REFUSAL,
    classify_rule_intent,
    is_banking_query,
    match_semantic_intent,
    normalize_query,
    validate_ollama_response,
)


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

    def test_normalization_contractions_and_repeated_chars(self):
        """Test that query normalization expands contractions, strips excess punctuation, and compresses repeats."""
        self.assertEqual(normalize_query("what's my balance???"), "what is my balance")
        self.assertEqual(normalize_query("heyyy bot"), "hey bot")
        self.assertEqual(normalize_query("can u shoot some funds!"), "can you shoot some funds")
        self.assertEqual(normalize_query("where's my salary???"), "where is my salary")
        self.assertEqual(normalize_query("pleaaase help me"), "please help me")

    def test_semantic_fallback_natural_language_variations(self):
        """Test that semantic fallback correctly routes natural phrasing without exact keyword matches."""
        variations = [
            ("how much moolah is sittin in my account", "balance"),
            ("where did all my salary disappear to", "spend"),
            ("cya later", "goodbye"),
            ("peace out", "goodbye"),
            ("yo bankbot", "greeting"),
            ("good day assistant", "greeting"),
            ("check my past payment records", "transactions"),
            ("give me my account ledger for this week", "transactions"),
        ]
        for query, expected in variations:
            allowed, _ = is_banking_query(query)
            self.assertTrue(allowed, f"Query should be allowed by domain gating: {query}")
            self.assertEqual(classify_rule_intent(query), expected, f"Semantic mismatch for: {query}")

    def test_ambiguous_and_uncertain_queries_route_to_llm(self):
        """Test that queries with weak similarity or close runner-up scores fall back safely to LLM."""
        ambiguous_queries = [
            "tell me about financial aspects",
            "what about my money situation",
            "banking options overview",
        ]
        for query in ambiguous_queries:
            self.assertEqual(classify_rule_intent(query), "llm", f"Ambiguous query must fall through to llm: {query}")

    def test_off_topic_queries_never_reach_semantic_action(self):
        """Test that off-topic queries are strictly rejected and never trigger semantic action routing."""
        off_topic_queries = [
            "what is Mark Zuckerberg's salary",
            "tell me a joke about money",
            "python coding for banking balance",
            "weather forecast near my bank",
            "how to bake a cake with bank butter",
        ]
        for query in off_topic_queries:
            allowed, _ = is_banking_query(query)
            self.assertFalse(allowed, f"Off-topic query should be rejected by domain gate: {query}")
            self.assertEqual(classify_rule_intent(query), "llm", f"Off-topic query must fall through to llm: {query}")

    def test_profile_phone_policy_guard_fix(self):
        """Regression: 'phone' in a profile query must not be intercepted by the LLM policy guard.

        Root cause: bare 'phone' in the policy guard pattern fired before _PROFILE_PATTERN.
        Fix: removed 'phone' from the guard — policy queries match via 'support'/'contact'.
        """
        # Profile queries with 'phone' must reach the profile intent
        self.assertEqual(
            classify_rule_intent("display my user profile and registered phone number"),
            "profile",
        )
        # Policy queries about phone numbers must still route to LLM (via 'support'/'contact')
        self.assertEqual(
            classify_rule_intent("What is the customer support phone number?"),
            "llm",
        )

    def test_balance_cash_coverage(self):
        """Regression: 'how much cash is left' must resolve to balance."""
        q = "how much cash is left in my savings"
        allowed, _ = is_banking_query(q)
        self.assertTrue(allowed)
        self.assertEqual(classify_rule_intent(q), "balance")

    def test_transactions_buy_coverage(self):
        """Regression: 'what did i buy yesterday' must resolve to transactions."""
        q = "what did i buy yesterday"
        allowed, _ = is_banking_query(q)
        self.assertTrue(allowed, "domain gate should pass for purchase-history query")
        self.assertEqual(classify_rule_intent(q), "transactions")

    def test_transactions_debits_credits_coverage(self):
        """Regression: 'pull up my latest debits and credits' must resolve to transactions."""
        q = "pull up my latest debits and credits"
        allowed, _ = is_banking_query(q)
        self.assertTrue(allowed)
        self.assertEqual(classify_rule_intent(q), "transactions")

    def test_transactions_swiped_coverage(self):
        """Regression: 'show me where my card was swiped recently' must resolve to transactions."""
        q = "show me where my card was swiped recently"
        allowed, _ = is_banking_query(q)
        self.assertTrue(allowed)
        self.assertEqual(classify_rule_intent(q), "transactions")

    def test_spend_expenditure_coverage(self):
        """Regression: 'break down my expenditure for me' must resolve to spend."""
        q = "break down my expenditure for me"
        allowed, _ = is_banking_query(q)
        self.assertTrue(allowed)
        self.assertEqual(classify_rule_intent(q), "spend")

    def test_profile_registered_to_coverage(self):
        """Regression: 'who is this account registered to' must resolve to profile."""
        q = "who is this account registered to"
        allowed, _ = is_banking_query(q)
        self.assertTrue(allowed)
        self.assertEqual(classify_rule_intent(q), "profile")

    def test_broke_slang_routes_to_llm(self):
        """'am i broke right now or what' is colloquial and ambiguous for a rule-based classifier.

        Decision: domain gate must pass as a valid banking inquiry, and router
        must send to LLM rather than risk misclassifying with deterministic rules.
        """
        q = "am i broke right now or what"
        allowed, _ = is_banking_query(q)
        self.assertTrue(allowed, "domain gate should allow 'am i broke' as banking inquiry")
        self.assertEqual(classify_rule_intent(q), "llm")

    def test_wire_transfer_with_recipient_resolves_safely(self):
        """Regression: 'wire ... to ...' resolves to transfer intent.

        Safety rationale: routing to transfer intent only displays a guide message
        directing the user to the Transfer tab. No funds move without a separate
        form submission. The pattern requires both 'wire' and 'to' (recipient context).
        """
        q = "wire 500 bucks to my brother"
        allowed, _ = is_banking_query(q)
        self.assertTrue(allowed)
        self.assertEqual(classify_rule_intent(q), "transfer")

    def test_wire_without_recipient_does_not_resolve_to_transfer(self):
        """Bare 'wire' without 'to' (recipient) must NOT resolve to transfer."""
        self.assertNotEqual(
            classify_rule_intent("tell me about wire transfers"),
            "transfer",
        )

    def test_banking_action_beats_greeting_or_farewell_prefix(self):
        """Conversation markers must not hide a requested account operation."""
        cases = [
            ("hi show me balance", "balance"),
            ("bye what is my balance", "balance"),
            ("hello, show my recent transactions", "transactions"),
        ]
        for query, expected in cases:
            allowed, _ = is_banking_query(query)
            self.assertTrue(allowed)
            self.assertEqual(classify_rule_intent(query), expected)

    def test_greeting_prefix_does_not_bypass_off_topic_gate(self):
        for query in [
            "hi, write Python code to read my balance",
            "hello, tell me a joke about money",
            "hey, what is the weather near my bank",
        ]:
            allowed, _ = is_banking_query(query)
            self.assertFalse(allowed, query)
            self.assertEqual(classify_rule_intent(query), "llm")

    def test_common_banking_typoes_normalize_to_existing_intents(self):
        cases = [
            ("what is my balence", "balance"),
            ("show my transactons", "transactions"),
            ("show my acount details", "profile"),
            ("trasnfer money to Alice", "transfer"),
        ]
        for query, expected in cases:
            allowed, _ = is_banking_query(query)
            self.assertTrue(allowed)
            self.assertEqual(classify_rule_intent(query), expected)

    def test_personal_history_profile_and_spending_paraphrases_use_data_routes(self):
        cases = [
            ("show latest activity", "transactions"),
            ("show my last payment", "transactions"),
            ("my recent purchases", "transactions"),
            ("where has my cash gone", "spend"),
            ("what email is linked to my account", "profile"),
            ("send 1000 to Alice", "transfer"),
        ]
        for query, expected in cases:
            allowed, _ = is_banking_query(query)
            self.assertTrue(allowed)
            self.assertEqual(classify_rule_intent(query), expected)

    def test_transfer_status_remains_an_llm_information_request(self):
        self.assertEqual(classify_rule_intent("What is my transfer status?"), "llm")

    def test_third_party_account_requests_are_refused_before_action_routing(self):
        allowed, reason = is_banking_query("Show my colleague's transaction history")
        self.assertFalse(allowed)
        self.assertIn("signed-in account", reason)
        allowed, _ = is_banking_query("Send money to my friend")
        self.assertTrue(allowed)

    def test_response_validation_rejects_malformed_and_fenced_code(self):
        self.assertEqual(validate_ollama_response("", "UPI limit"), OFF_TOPIC_REFUSAL)
        self.assertEqual(validate_ollama_response(None, "UPI limit"), OFF_TOPIC_REFUSAL)
        self.assertEqual(
            validate_ollama_response("```python\nprint('hello')\n```", "UPI limit"),
            OFF_TOPIC_REFUSAL,
        )
        self.assertEqual(
            validate_ollama_response("The daily UPI limit is Rs. 1,00,000.", "UPI limit"),
            "The daily UPI limit is Rs. 1,00,000.",
        )


if __name__ == "__main__":
    unittest.main()
