import re

RESTRICTED_TOPICS = {
    'technology': [
        'coding', 'programming', 'python', 'javascript', 'html', 'css',
        'software', 'computer', 'algorithm', 'algorithms', 'debug',
        'postgresql', 'mysql', 'mongodb', 'django', 'flask'
    ],
    'general_knowledge': [
        'politics', 'geography', 'science', 'physics', 'chemistry', 'biology',
        'math', 'capital city', 'capital of'
    ],
    'entertainment': [
        'joke', 'jokes', 'riddle', 'story', 'movie', 'movies', 'film',
        'music', 'song', 'game', 'meme', 'oscars', 'actor', 'actors', 'actress'
    ],
    'lifestyle': [
        'cooking', 'recipe', 'fashion', 'sport', 'fitness', 'exercise', 'workout'
    ],
    'other': [
        'weather', 'news', 'celebrity', 'astrology', 'horoscope', 'poem',
        'essay', 'bill gates', 'elon musk',
        'rain', 'raining', 'temperature', 'forecast', 'snow'
    ]
}

BANKING_KEYWORDS = {
    'account': [
        'balance', 'account', 'statement', 'profile', 'summary', 'details',
        'number', 'kyc', 'score'
    ],
    'transactions': [
        'transaction', 'transactions', 'payment', 'payments', 'transfer',
        'transfers', 'upi', 'pay', 'paying', 'paid'
    ],
    'services': [
        'loan', 'loans', 'credit', 'debit', 'card', 'cards', 'interest',
        'savings', 'deposit', 'deposits', 'fixed', 'fd', 'emi', 'atm',
        'ifsc', 'neft', 'rtgs', 'cheque', 'cheques', 'fund', 'funds',
        'mutual', 'insurance'
    ],
    'operations': [
        'send', 'sending', 'withdraw', 'withdrawing', 'withdrawal',
        'withdrawals', 'deposit', 'depositing', 'money'
    ],
    'queries': [
        'branch', 'branches', 'hours', 'timing', 'timings', 'contact',
        'support', 'limit', 'limits', 'policy', 'policies', 'rate',
        'rates', 'fee', 'fees', 'charges', 'charge', 'penalty', 'penalties'
    ],
    'financial': [
        'spend', 'spent', 'spending', 'expense', 'expenses', 'income',
        'budget', 'budgeting', 'investment', 'investments', 'portfolio',
        'finances', 'financial'
    ]
}

BANKING_PHRASES = (
    'transaction history',
    'account history',
    'credit history',
    'payment history',
    'recent transactions',
    'recent activity',
    'last transaction',
    'last transactions',
    'account details',
    'account info',
    'account information',
    'account number',
    'account summary',
    'available funds',
    'show my history',
    'my history',
    'what happened recently',
    'how much did i pay',
    'mutual fund',
    'mutual funds',
    'where did my money go',
    'where did all my money go',
    'bank statement',
)

SMALL_TALK = (
    'hi', 'hello', 'hey', 'how are you', 'how do you do',
    'who are you', 'what can you do', 'thanks', 'thank you',
    'good morning', 'good evening', 'good afternoon', 'nice to meet you'
)

OFF_TOPIC_REFUSAL = "I apologize, but I can only assist with banking and financial queries."
BANKING_ONLY_REFUSAL = (
    "I can only assist with banking-related questions about your account, "
    "transactions, transfers, loans, and other financial services."
)

PERSONAL_HISTORY_PATTERN = re.compile(
    r'\b(?:show|view|check|see|get|display|my)\s+(?:recent\s+)?(?:account\s+|transaction\s+|credit\s+|payment\s+)?history\b|'
    r'\b(?:transaction|account|credit|payment)\s+history\b'
)

# High-confidence programming patterns
STRONG_PROGRAMMING_PATTERN = re.compile(
    r'\b(?:c\+\+|postgresql|django|mongodb|mysql|database)\b|'
    r'\b(?:fix\s+this|debug)\s+(?:python\s+)?bug\b|'
    r'\bwrite\s+(?:a\s+|an\s+)?(?:c\+\+\s+|python\s+)?(?:class|function|script|algorithm|program)\b',
    re.IGNORECASE
)

# High-confidence weather patterns
STRONG_WEATHER_PATTERN = re.compile(
    r'\b(?:will\s+it\s+rain|is\s+it\s+raining|temperature\s+outside|weather\s+forecast)\b|'
    r'\b(?:rain|weather|temperature|forecast|snow|humidity)\b',
    re.IGNORECASE
)

# High-confidence third-party wealth pattern
THIRD_PARTY_WEALTH_PATTERN = re.compile(
    r'\bhow much (?:money\s+)?(?:do|does)\s+(?!my|the\s+bank|this|i\b)[a-z\s]+(?:make|earn|possess|have)\b|'
    r'\bnet\s+worth\s+of\b|\b(?:richest\s+man|billionaires?|millionaires?)\b',
    re.IGNORECASE
)


def _word_pattern(word: str) -> str:
    return rf'(?<![a-z0-9]){re.escape(word)}(?![a-z0-9])'


def _has_word(text: str, word: str) -> bool:
    return re.search(_word_pattern(word), text) is not None


def _has_any_word(text: str, words) -> bool:
    return any(_has_word(text, word) for word in words)


def _collect_keywords(groups: dict) -> list[str]:
    words = []
    for keywords in groups.values():
        words.extend(keywords)
    return words


_BANKING_WORDS = _collect_keywords(BANKING_KEYWORDS)
_RESTRICTED_WORDS = _collect_keywords(RESTRICTED_TOPICS)


def is_small_talk(prompt: str) -> bool:
    prompt_lower = prompt.lower().strip()
    if not prompt_lower:
        return False
    if re.search(r'\b(bye|goodbye)\b', prompt_lower):
        return True
    if re.fullmatch(r'(please\s+)?help(\s+please)?\??', prompt_lower):
        return True
    if any(phrase in prompt_lower for phrase in SMALL_TALK if ' ' in phrase):
        return True
    return bool(re.match(r'^(hi|hello|hey|thanks|thank you)\b', prompt_lower))


def has_strong_off_topic_signals(prompt_lower: str) -> bool:
    """Detect high-confidence non-banking queries (coding, weather, trivia)."""
    if _has_any_word(prompt_lower, _RESTRICTED_WORDS):
        return True
    if STRONG_PROGRAMMING_PATTERN.search(prompt_lower):
        return True
    if STRONG_WEATHER_PATTERN.search(prompt_lower):
        return True
    if THIRD_PARTY_WEALTH_PATTERN.search(prompt_lower):
        return True
    if _has_word(prompt_lower, 'history') and not PERSONAL_HISTORY_PATTERN.search(prompt_lower):
        return True
    return False


def is_banking_query(prompt: str) -> tuple[bool, str]:
    """
    Validates if a query is banking-related.
    Returns: (is_valid, reason/message)
    """
    prompt_lower = prompt.lower().strip()

    if is_small_talk(prompt):
        return True, "conversation"

    # Precedence: check strong off-topic signals BEFORE general banking keyword match
    # to prevent off-topic queries (e.g. "joke about money", "python banking script",
    # "weather near bank branch", "django database transactions") from leaking through.
    if has_strong_off_topic_signals(prompt_lower):
        return False, OFF_TOPIC_REFUSAL

    if any(phrase in prompt_lower for phrase in BANKING_PHRASES):
        return True, "valid banking query"

    banking_match = _has_any_word(prompt_lower, _BANKING_WORDS)
    if banking_match:
        return True, "valid banking query"

    return False, BANKING_ONLY_REFUSAL


# Pre-compiled action intent patterns
_BALANCE_PATTERN = re.compile(
    r'\bbalance\b|how much money(?:\s+do\s+i|\s+is\s+in\s+my)|how much do i have|\bavailable funds\b',
    re.IGNORECASE
)
_TRANSACTIONS_PATTERN = re.compile(
    r'\btransactions?\b|(?:transaction|account|payment)\s+history|recent (transactions?|activity)|last transactions?|'
    r'show (?:my\s+)?(?:account\s+)?history|\bmy\s+(?:account\s+)?history\b|what happened recently|\bstatements?\b',
    re.IGNORECASE
)
_SPEND_PATTERN = re.compile(
    r'\bspend|\bspent\b|\bexpenses?\b|\bspending\b|\banalytics\b|'
    r'how much did i (?:spend|pay)|where did (?:all\s+)?my money go',
    re.IGNORECASE
)
_PROFILE_PATTERN = re.compile(
    r'\bprofile\b|account (?:details|info|information|number|summary)|'
    r'my (?:details|account details|credit score|account number)|'
    r'tell me about my account|\bcredit score\b',
    re.IGNORECASE
)
_TRANSFER_PATTERN = re.compile(
    r'\btransfer\b|send money|how (?:do i|to|can i) (?:send|pay|transfer)|'
    r'want to transfer|pay someone|send funds',
    re.IGNORECASE
)


def classify_rule_intent(prompt: str) -> str:
    """Classify queries that can be answered without calling the LLM."""
    prompt_lower = prompt.lower().strip()

    # 1. Conversational exits
    if re.search(r'\b(bye|goodbye)\b', prompt_lower):
        return "goodbye"

    # 2. Conversational help / identity
    if re.search(r'^(please\s+)?(help|what can you|what do you do|who are you)\b', prompt_lower):
        return "help"

    # 3. Conversational greeting
    if is_small_talk(prompt):
        return "greeting"

    # 4. Off-topic guard: if query contains strong off-topic signals, it must never trigger an action
    if has_strong_off_topic_signals(prompt_lower):
        return "llm"

    # 5. Informational / Policy Guard: inquiries must fall through to the LLM
    llm_policy_patterns = [
        # Duration / timing / clearing / processing inquiries
        r'\bhow\s+long\b',
        r'\bhow\s+much\s+time\b',
        r'\b(?:clearing\s+time|processing\s+time|turnaround\s+time)\b',
        r'\b(?:to\s+clear|clearance\s+time)\b',
        # Process / procedure / explanation inquiries
        r'\bwhat\s+is\s+the\s+(?:process|procedure|steps?|mechanism|way\s+to\s+apply)\b',
        r'\b(?:process|procedure)\s+(?:for|to|of)\b',
        r'\bhow\s+does\s+(?:it|a|an|the)\s+.*\s+work\b',
        # Policies, limits, fees, rules
        r'\b(?:limit|limits|maximum|cap|ceiling)\b',
        r'\b(?:fee|fees|charges?|penalty|penalties|cost|costs|fine|fines)\b',
        r'\bminimum\s+balance\b',
        r'\b(?:interest\s+rate|rate\s+of\s+interest|rates?|policy|policies)\b',
        r'\b(?:rules?|regulations?|eligibility|requirements?|terms)\b',
        r'\b(?:loan|loans|emi|mortgage)\b',
        r'\b(?:enable|disable|activate|block|lost|reward|rewards|points)\b',
        r'\bcredit\s+card\b|\bdebit\s+card\b',
        r'\b(?:branch\s+hours|open\s+on|opening\s+hours|hours|closed|contact|support|phone|email|ifsc|cheque\s+book)\b',
        r'\bfixed\s+deposit|\brecurring\s+deposit|\bfd\b|\brd\b|\bdeposit\s+rate',
        r'\bmutual\s+funds?|\bfinancial\s+advice|\badvice\b|\bguidance\b|\binvestment\s+advice\b',
        r'\batm\b',
        r'\bkyc\b',
        r'\bhow\s+often\b|\bwhen\s+is\b|\bcan\s+you\s+explain\b',
    ]
    if any(re.search(pat, prompt_lower) for pat in llm_policy_patterns):
        return "llm"

    # 6. Compound / Multi-Intent Detection across deterministic actions
    # Instead of letting the first matching regex silently win, identify all candidate actions.
    matched_actions = []

    if _BALANCE_PATTERN.search(prompt_lower):
        matched_actions.append("balance")

    if _TRANSACTIONS_PATTERN.search(prompt_lower):
        matched_actions.append("transactions")

    if _SPEND_PATTERN.search(prompt_lower):
        matched_actions.append("spend")

    if _PROFILE_PATTERN.search(prompt_lower):
        matched_actions.append("profile")

    if _TRANSFER_PATTERN.search(prompt_lower):
        matched_actions.append("transfer")

    # Clear deterministic policy for compound/conflicting requests:
    # If multiple distinct actions are requested, route safely to conversational LLM.
    if len(matched_actions) > 1:
        return "llm"

    if len(matched_actions) == 1:
        return matched_actions[0]

    return "llm"


def validate_ollama_response(response: str, original_query: str) -> str:
    """
    Post-validation: Check if Ollama's response stayed on-topic.
    Returns: cleaned response or refusal message
    """
    response_lower = response.lower()

    off_topic_indicators = [
        'here is a python script',
        'here\'s some code',
        'def ', 'function(',
        'import ',
        'recipe for',
        'ingredients:',
        'world war',
        'the capital of',
        'once upon a time'
    ]

    if any(indicator in response_lower for indicator in off_topic_indicators):
        return OFF_TOPIC_REFUSAL

    banking_terms = ['account', 'balance', 'transaction', 'transfer', 'bank', 'credit', 'debit', 'loan', 'deposit']
    has_banking_term = any(term in response_lower for term in banking_terms)

    if len(response) > 800 and not has_banking_term:
        return OFF_TOPIC_REFUSAL

    return response
