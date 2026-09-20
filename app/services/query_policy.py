RESTRICTED_TOPICS = {
    'technology': ['coding', 'programming', 'python', 'javascript', 'html', 'css', 'software', 'computer', 'algorithm', 'debug'],
    'general_knowledge': ['history', 'politics', 'geography', 'science', 'physics', 'chemistry', 'biology', 'math', 'capital'],
    'entertainment': ['joke', 'riddle', 'story', 'movie', 'film', 'music', 'song', 'game', 'meme'],
    'lifestyle': ['cooking', 'recipe', 'fashion', 'travel', 'sport', 'fitness', 'exercise', 'workout'],
    'other': ['weather', 'news', 'celebrity', 'astrology', 'horoscope', 'poem', 'essay']
}

BANKING_KEYWORDS = {
    'account': ['balance', 'account', 'statement', 'profile', 'details', 'info', 'summary'],
    'transactions': ['transaction', 'history', 'payment', 'transfer', 'sent', 'received', 'recent', 'last'],
    'services': ['loan', 'credit', 'debit', 'card', 'interest', 'savings', 'deposit', 'fixed', 'fd'],
    'operations': ['send', 'pay', 'withdraw', 'deposit', 'transfer', 'upi', 'money'],
    'queries': ['branch', 'hours', 'contact', 'support', 'help', 'limit', 'policy', 'rate', 'fee'],
    'financial': ['spend', 'expense', 'income', 'budget', 'investment', 'portfolio']
}


def is_banking_query(prompt: str) -> tuple[bool, str]:
    """
    Validates if a query is banking-related.
    Returns: (is_valid, reason/message)
    """
    prompt_lower = prompt.lower()
    
    # 1. Check for restricted topics (DENY LIST)
    small_talk = ['hi', 'hello', 'hey', 'how are you', 'how do you do', 
    'who are you', 'what can you do', 'thanks', 'thank you',
    'good morning', 'good evening', 'nice to meet you']
    if any(phrase in prompt_lower for phrase in small_talk):
        return True, "conversation"
    
    for category, keywords in RESTRICTED_TOPICS.items():
        for keyword in keywords:
            if keyword in prompt_lower:
                return False, "I apologize, but I can only assist with banking and financial queries."
    
    # 2. Check for banking keywords (ALLOW LIST)
    banking_match = False
    for category, keywords in BANKING_KEYWORDS.items():
        if any(word in prompt_lower for word in keywords):
            banking_match = True
            break
    
    # 3. Allow greetings and farewells
    
    # 4. If no banking keywords found, reject
    if not banking_match:
        return False, "I can only assist with banking-related questions about your account, transactions, transfers, loans, and other financial services."
    
    return True, "valid banking query"


def validate_ollama_response(response: str, original_query: str) -> str:
    """
    Post-validation: Check if Ollama's response stayed on-topic.
    Returns: cleaned response or refusal message
    """
    response_lower = response.lower()
    
    # Check if response contains non-banking content indicators
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
        return "I apologize, but I can only assist with banking and financial queries."
    
    # If response is suspiciously generic/long and doesn't mention banking terms
    banking_terms = ['account', 'balance', 'transaction', 'transfer', 'bank', 'credit', 'debit', 'loan', 'deposit']
    has_banking_term = any(term in response_lower for term in banking_terms)
    
    if len(response) > 800 and not has_banking_term:
        return "I apologize, but I can only assist with banking and financial queries."
    
    return response
