import re

RESTRICTED_TOPICS = {
    'technology': ['coding', 'programming', 'python', 'javascript', 'html', 'css', 'software', 'computer', 'algorithm', 'debug'],
    'general_knowledge': ['politics', 'geography', 'science', 'physics', 'chemistry', 'biology', 'math', 'capital'],
    'entertainment': ['joke', 'riddle', 'story', 'movie', 'film', 'music', 'song', 'game', 'meme'],
    'lifestyle': ['cooking', 'recipe', 'fashion', 'travel', 'sport', 'fitness', 'exercise', 'workout'],
    'other': ['weather', 'news', 'celebrity', 'astrology', 'horoscope', 'poem', 'essay']
}

BANKING_KEYWORDS = {
    'account': ['balance', 'account', 'statement', 'profile', 'summary'],
    'transactions': ['transaction', 'transactions', 'payment', 'transfer', 'upi'],
    'services': ['loan', 'credit', 'debit', 'card', 'interest', 'savings', 'deposit', 'fixed', 'fd', 'emi', 'atm', 'ifsc', 'kyc', 'neft', 'rtgs', 'cheque'],
    'operations': ['send', 'withdraw', 'deposit', 'money'],
    'queries': ['branch', 'hours', 'contact', 'support', 'limit', 'policy', 'rate', 'fee'],
    'financial': ['spend', 'spent', 'expense', 'income', 'budget', 'investment', 'portfolio']
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
    if re.fullmatch(r'(please\s+)?help(\s+please)?\??', prompt_lower):
        return True
    if any(phrase in prompt_lower for phrase in SMALL_TALK if ' ' in phrase):
        return True
    return bool(re.match(r'^(hi|hello|hey|thanks|thank you)\b', prompt_lower))


def is_banking_query(prompt: str) -> tuple[bool, str]:
    """
    Validates if a query is banking-related.
    Returns: (is_valid, reason/message)
    """
    prompt_lower = prompt.lower()

    if is_small_talk(prompt):
        return True, "conversation"

    if any(phrase in prompt_lower for phrase in BANKING_PHRASES):
        return True, "valid banking query"

    banking_match = _has_any_word(prompt_lower, _BANKING_WORDS)
    if banking_match:
        return True, "valid banking query"

    if _has_any_word(prompt_lower, _RESTRICTED_WORDS):
        return False, OFF_TOPIC_REFUSAL

    if _has_word(prompt_lower, 'history'):
        return False, OFF_TOPIC_REFUSAL

    return False, BANKING_ONLY_REFUSAL


def classify_rule_intent(prompt: str) -> str:
    """Classify queries that can be answered without calling the LLM."""
    prompt_lower = prompt.lower()

    if re.search(r'\bbalance\b|how much money|how much do i have|\bavailable funds\b', prompt_lower):
        return "balance"

    if re.search(
        r'\btransactions?\b|transaction history|recent (transactions?|activity)|last transactions?',
        prompt_lower,
    ):
        return "transactions"

    if re.search(r'\bspend|\bspent\b|\bexpenses?\b|\bspending\b|\banalytics\b', prompt_lower):
        return "spend"

    if re.search(
        r'\bprofile\b|my account details|account (details|info|information)|\bcredit score\b|\bmy details\b',
        prompt_lower,
    ):
        return "profile"

    if re.search(r'\btransfer\b|send money|how (do i|to) (send|pay|transfer)', prompt_lower):
        return "transfer"

    if re.search(r'\b(bye|goodbye)\b', prompt_lower):
        return "goodbye"

    if re.search(r'^(please\s+)?(help|what can you|what do you do|who are you)\b', prompt_lower.strip()):
        return "help"

    if is_small_talk(prompt):
        return "greeting"

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
