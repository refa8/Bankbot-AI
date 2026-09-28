import math
import re
from collections import Counter, defaultdict
from typing import Optional


def normalize_query(prompt: str) -> str:
    """Lightweight query normalization handling contractions, repeated chars, and punctuation."""
    if not prompt:
        return ""
    text = prompt.lower().strip()
    text = text.replace("’", "'").replace("‘", "'")

    contractions = {
        r"\bwhat's\b": "what is",
        r"\bwhats\b": "what is",
        r"\bhow's\b": "how is",
        r"\bhows\b": "how is",
        r"\bwhere's\b": "where is",
        r"\bwheres\b": "where is",
        r"\bthere's\b": "there is",
        r"\bcan't\b": "cannot",
        r"\bcant\b": "cannot",
        r"\bdon't\b": "do not",
        r"\bdont\b": "do not",
        r"\bwon't\b": "will not",
        r"\bi'm\b": "i am",
        r"\bim\b": "i am",
        r"\bi've\b": "i have",
        r"\bi'd\b": "i would",
        r"\bi'll\b": "i will",
        r"\bu\b": "you",
        r"\bur\b": "your",
        r"\bpls\b": "please",
        r"\bplz\b": "please",
    }
    for pat, repl in contractions.items():
        text = re.sub(pat, repl, text)

    # Compress 3+ repeated characters down to 1 (e.g. heyyy -> hey, pleaaase -> please)
    text = re.sub(r'([a-zA-Z])\1{2,}', r'\1', text)

    # Replace punctuation with spaces to preserve clean word boundaries
    text = re.sub(r'[^\w\s]', ' ', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text

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
        'transfers', 'upi', 'pay', 'paying', 'paid',
        'debits', 'credits', 'swiped'
    ],
    'services': [
        'loan', 'loans', 'credit', 'debit', 'card', 'cards', 'interest',
        'savings', 'deposit', 'deposits', 'fixed', 'fd', 'emi', 'atm',
        'ifsc', 'neft', 'rtgs', 'cheque', 'cheques', 'fund', 'funds',
        'mutual', 'insurance'
    ],
    'operations': [
        'send', 'sending', 'withdraw', 'withdrawing', 'withdrawal',
        'withdrawals', 'deposit', 'depositing', 'money', 'cash', 'wire'
    ],
    'queries': [
        'branch', 'branches', 'hours', 'timing', 'timings', 'contact',
        'support', 'limit', 'limits', 'policy', 'policies', 'rate',
        'rates', 'fee', 'fees', 'charges', 'charge', 'penalty', 'penalties'
    ],
    'financial': [
        'spend', 'spent', 'spending', 'expense', 'expenses', 'expenditure',
        'income', 'budget', 'budgeting', 'investment', 'investments',
        'portfolio', 'finances', 'financial'
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
    'what did i buy',
    'what i bought',
    'am i broke',
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
    r'\bnet\s+worth\s+of\b|\b(?:richest\s+man|billionaires?|millionaires?)\b|'
    r'\b(?:salary|net\s*worth|wealth)\s+of\b|'
    r'\bwhat\s+is\s+(?!my\b)[a-z\s]+\b(?:salary|net\s*worth|wealth)\b',
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
    prompt_norm = normalize_query(prompt)
    if not prompt_norm:
        return False
    if re.search(r'\b(bye|goodbye|cya|peace\s+out)\b', prompt_norm):
        return True
    if re.search(r'\b(yo|whats\s+up|what\s+is\s+up|heyy?)\b', prompt_norm):
        return True
    if re.search(r'\b(good\s+day|good\s+morning|good\s+afternoon|good\s+evening)\b', prompt_norm):
        return True
    if re.search(r'\bhelp\b', prompt_norm) and not _has_any_word(prompt_norm, ['transfer', 'balance', 'statement', 'account']):
        return True
    if any(phrase in prompt_norm for phrase in SMALL_TALK if ' ' in phrase):
        return True
    return bool(re.match(r'^(hi|hello|hey|thanks|thank you)\b', prompt_norm))


def has_strong_off_topic_signals(prompt_lower: str) -> bool:
    """Detect high-confidence non-banking queries (coding, weather, trivia)."""
    prompt_norm = normalize_query(prompt_lower)
    if _has_any_word(prompt_norm, _RESTRICTED_WORDS):
        return True
    if STRONG_PROGRAMMING_PATTERN.search(prompt_norm):
        return True
    if STRONG_WEATHER_PATTERN.search(prompt_norm):
        return True
    if THIRD_PARTY_WEALTH_PATTERN.search(prompt_norm):
        return True
    if _has_word(prompt_norm, 'history') and not PERSONAL_HISTORY_PATTERN.search(prompt_norm):
        return True
    return False


# ============================================================================
# LIGHTWEIGHT SEMANTIC MATCHER (Character N-gram + TF-IDF Cosine Similarity)
# ============================================================================

def _get_char_ngrams(text: str, n_range=(3, 4)) -> list[str]:
    text = f" {text} "
    ngrams = []
    for n in range(n_range[0], n_range[1] + 1):
        if len(text) >= n:
            for i in range(len(text) - n + 1):
                ngrams.append(text[i:i+n])
    return ngrams


INTENT_EXEMPLARS = {
    'balance': [
        "what is my account balance",
        "how much money do i have in my account",
        "check my current available balance",
        "how much balance is remaining",
        "tell me my available funds",
        "how much moolah is in my account",
    ],
    'transactions': [
        "show my recent transactions",
        "display my transaction history",
        "show me my account statement",
        "check past transactions and payments",
        "give me my account ledger",
        "check my past payment records",
        "show me my statements",
    ],
    'spend': [
        "how much did i spend",
        "show my spending analysis",
        "what are my total expenses",
        "where did my money go",
        "where did all my salary disappear to",
        "track my spending breakdown",
    ],
    'profile': [
        "show my profile details",
        "what is my account number",
        "view my registered account information",
        "check my credit score and summary",
        "display user profile and account details",
    ],
    'transfer': [
        "transfer money to someone",
        "send funds to another account",
        "i want to transfer cash",
        "send money to my friend",
        "pay my landlord how do i do that",
        "need to send cash to mom",
        "send twenty grand to someone",
        "shoot some funds over to someone",
    ],
    'greeting': [
        "hello bankbot",
        "hi good morning",
        "hey there assistant",
        "good day assistant",
        "yo bankbot what is up",
        "heyyy greetings",
    ],
    'goodbye': [
        "goodbye see you later",
        "bye bankbot",
        "cya later",
        "peace out",
        "exit session bye",
    ],
    'help': [
        "help me navigate this banking app",
        "what can you do for me",
        "what features do you offer here",
        "how can you assist me",
    ]
}

_CORPUS = []
_DOC_TO_INTENT = []
for intent, phrases in INTENT_EXEMPLARS.items():
    for p in phrases:
        _CORPUS.append(normalize_query(p))
        _DOC_TO_INTENT.append(intent)

_N_DOCS = len(_CORPUS)
_DOC_FREQ = Counter()
_CORPUS_TF = []
for doc in _CORPUS:
    ng = _get_char_ngrams(doc)
    counts = Counter(ng)
    _CORPUS_TF.append(counts)
    for term in counts:
        _DOC_FREQ[term] += 1

_IDF = {term: math.log((1 + _N_DOCS) / (1 + freq)) + 1.0 for term, freq in _DOC_FREQ.items()}

_CORPUS_VECTORS = []
for counts in _CORPUS_TF:
    vec = {}
    norm_sq = 0.0
    for term, count in counts.items():
        weight = count * _IDF[term]
        vec[term] = weight
        norm_sq += weight * weight
    norm = math.sqrt(norm_sq) if norm_sq > 0 else 1.0
    _CORPUS_VECTORS.append({t: w / norm for t, w in vec.items()})


def match_semantic_intent(prompt_norm: str, threshold: float = 0.55, margin: float = 0.08) -> tuple[Optional[str], float, float]:
    """
    Computes character n-gram TF-IDF cosine similarity against intent exemplars.
    Returns: (matched_intent, top_score, second_score)
    """
    ng = _get_char_ngrams(prompt_norm)
    if not ng:
        return None, 0.0, 0.0
    counts = Counter(ng)
    vec = {}
    norm_sq = 0.0
    for term, count in counts.items():
        if term in _IDF:
            weight = count * _IDF[term]
            vec[term] = weight
            norm_sq += weight * weight
    norm = math.sqrt(norm_sq) if norm_sq > 0 else 1.0
    q_vec = {t: w / norm for t, w in vec.items()}

    intent_scores = defaultdict(float)
    for (c_vec, intent) in zip(_CORPUS_VECTORS, _DOC_TO_INTENT):
        sim = sum(w * c_vec.get(t, 0.0) for t, w in q_vec.items())
        if sim > intent_scores[intent]:
            intent_scores[intent] = sim

    sorted_scores = sorted(intent_scores.items(), key=lambda x: x[1], reverse=True)
    if not sorted_scores:
        return None, 0.0, 0.0

    best_intent, best_score = sorted_scores[0]
    second_score = sorted_scores[1][1] if len(sorted_scores) > 1 else 0.0

    # Mandatory Transfer Safety:
    # Semantic similarity alone must never trigger transfer intent.
    # Require explicit action verbs (send, transfer, pay, wire, shoot) AND higher confidence threshold (0.60).
    if best_intent == "transfer":
        transfer_keywords = {'transfer', 'send', 'pay', 'wire', 'shoot'}
        if not any(k in prompt_norm for k in transfer_keywords):
            return None, best_score, second_score
        if best_score < 0.60:
            return None, best_score, second_score

    if best_score >= threshold and (best_score - second_score) >= margin:
        return best_intent, best_score, second_score

    return None, best_score, second_score


def is_banking_query(prompt: str) -> tuple[bool, str]:
    """
    Validates if a query is banking-related.
    Returns: (is_valid, reason/message)
    """
    prompt_norm = normalize_query(prompt)

    if is_small_talk(prompt_norm):
        return True, "conversation"

    # Precedence: check strong off-topic signals BEFORE general banking keyword match
    # to prevent off-topic queries (e.g. "joke about money", "python banking script",
    # "weather near bank branch", "django database transactions") from leaking through.
    if has_strong_off_topic_signals(prompt_norm):
        return False, OFF_TOPIC_REFUSAL

    if any(phrase in prompt_norm for phrase in BANKING_PHRASES):
        return True, "valid banking query"

    if _has_any_word(prompt_norm, _BANKING_WORDS):
        return True, "valid banking query"

    # Semantic domain gate check: if legitimate banking phrasing without off-topic signals
    sem_intent, score, _ = match_semantic_intent(prompt_norm, threshold=0.45, margin=0.04)
    if sem_intent:
        if sem_intent in ("greeting", "goodbye", "help"):
            return True, "conversation"
        return True, "valid banking query"

    # Extended terms check: complaints, grievance, statements
    if _has_any_word(prompt_norm, ['grievance', 'complaint', 'complaints', 'redressal', 'statements']):
        return True, "valid banking query"

    return False, BANKING_ONLY_REFUSAL


# Pre-compiled action intent patterns
_BALANCE_PATTERN = re.compile(
    r'\bbalance\b|how much (?:money|cash)(?:\s+do\s+i|\s+is\s+(?:in\s+my|left))|how much do i have|\bavailable funds\b',
    re.IGNORECASE
)
_TRANSACTIONS_PATTERN = re.compile(
    r'\btransactions?\b|(?:transaction|account|payment)\s+history|recent(?:ly)?\s+(?:transactions?|activity)|last transactions?|'
    r'show (?:my\s+)?(?:account\s+)?history|\bmy\s+(?:account\s+)?history\b|what happened recently|\bstatements?\b|'
    r'\b(?:buy|bought)\b.*\b(?:yesterday|today|last|recent|this)\b|'
    r'\bswiped\b|\bdebits?\s+and\s+credits?\b',
    re.IGNORECASE
)
_SPEND_PATTERN = re.compile(
    r'\bspend|\bspent\b|\bexpenses?\b|\bexpenditure\b|\bspending\b|\banalytics\b|'
    r'how much did i (?:spend|pay)|where did (?:all\s+)?my money go',
    re.IGNORECASE
)
_PROFILE_PATTERN = re.compile(
    r'\bprofile\b|account (?:details|info|information|number|summary)|'
    r'my (?:details|account details|credit score|account number)|'
    r'tell me about my account|\bcredit score\b|'
    r'\baccount\s+registered\s+to\b|\bregistered\s+to\b',
    re.IGNORECASE
)
_TRANSFER_PATTERN = re.compile(
    r'\btransfer\b|send money|how (?:do i|to|can i) (?:send|pay|transfer)|'
    r'want to transfer|pay someone|send funds|'
    r'\bwire\b.+\bto\b',
    re.IGNORECASE
)


def classify_rule_intent(prompt: str) -> str:
    """Classify queries that can be answered without calling the LLM."""
    prompt_norm = normalize_query(prompt)

    # 1. Conversational exits
    if re.search(r'\b(bye|goodbye|cya|peace\s+out)\b', prompt_norm):
        return "goodbye"

    # 2. Conversational help / identity
    if re.search(r'^(please\s+)?(help|what can you|what do you do|who are you)\b', prompt_norm):
        return "help"
    if "help" in prompt_norm and not _has_any_word(prompt_norm, ['transfer', 'balance', 'statement', 'account', 'pay']):
        return "help"

    # 3. Conversational greeting
    if is_small_talk(prompt):
        return "greeting"

    # 4. Off-topic guard: if query contains strong off-topic signals, it must never trigger an action
    if has_strong_off_topic_signals(prompt_norm):
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
        r'\b(?:branch\s+hours|open\s+on|opening\s+hours|hours|closed|contact|support|email|ifsc|cheque\s+book)\b',
        r'\bfixed\s+deposit|\brecurring\s+deposit|\bfd\b|\brd\b|\bdeposit\s+rate',
        r'\bmutual\s+funds?|\bfinancial\s+advice|\badvice\b|\bguidance\b|\binvestment\s+advice\b',
        r'\batm\b',
        r'\bkyc\b',
        r'\bhow\s+often\b|\bwhen\s+is\b|\bcan\s+you\s+explain\b',
        r'\b(?:grievance|complaint|complaints|redressal|escalation)\b',
    ]
    if any(re.search(pat, prompt_norm) for pat in llm_policy_patterns):
        return "llm"

    # 6. Compound / Multi-Intent Detection across deterministic actions
    # Instead of letting the first matching regex silently win, identify all candidate actions.
    matched_actions = []

    if _BALANCE_PATTERN.search(prompt_norm):
        matched_actions.append("balance")

    if _TRANSACTIONS_PATTERN.search(prompt_norm):
        matched_actions.append("transactions")

    if _SPEND_PATTERN.search(prompt_norm):
        matched_actions.append("spend")

    if _PROFILE_PATTERN.search(prompt_norm):
        matched_actions.append("profile")

    if _TRANSFER_PATTERN.search(prompt_norm):
        matched_actions.append("transfer")

    # Clear deterministic policy for compound/conflicting requests:
    # If multiple distinct actions are requested, route safely to conversational LLM.
    if len(matched_actions) > 1:
        return "llm"

    if len(matched_actions) == 1:
        return matched_actions[0]

    # 7. Semantic Fallback: run only when rules cannot confidently identify a single intent
    sem_intent, score, margin = match_semantic_intent(prompt_norm, threshold=0.55, margin=0.08)
    if sem_intent:
        return sem_intent

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
