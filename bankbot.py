import os
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import time
import uuid
import requests
import json
from typing import Generator, Optional

# ============================================================================
# BANKING KNOWLEDGE BASE & RESTRICTIONS
# ============================================================================

BANK_KB = """
SECUREBANK OFFICIAL POLICIES:
1. SAVINGS INTEREST: 4.5% p.a., credited quarterly.
2. HOME LOANS: Starting at 8.75% p.a. for amounts > 50 Lakhs.
3. CREDIT CARDS: 'Platinum' (Rs. 1000/yr fee) and 'Gold' (Free for life).
4. BRANCH HOURS: Mon-Sat, 9:30 AM - 4:00 PM. Closed on 2nd/4th Saturdays.
5. UPI LIMITS: Rs. 1,00,000 per day.
6. SUPPORT: Call 1800-123-4567 or email support@securebank.com.
7. FIXED DEPOSITS: 6.5% for 1 year, 7.2% for 3 years (Senior citizens +0.5%).
"""

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

# # ============================================================================
# # CONFIG
# # ============================================================================
from config import settings
from security import (
    PasswordHasher, 
    SessionManager, 
    RateLimiter, 
    InputValidator
)

# Initialize security components
password_hasher = PasswordHasher()
session_manager = SessionManager(timeout_minutes=settings.SESSION_TIMEOUT_MINUTES)
rate_limiter = RateLimiter(
    max_attempts=settings.MAX_LOGIN_ATTEMPTS,
    lockout_minutes=settings.LOCKOUT_MINUTES
)
input_validator = InputValidator()

# Config
OLLAMA_URL = settings.OLLAMA_URL
OLLAMA_MODEL = settings.OLLAMA_MODEL
OLLAMA_TIMEOUT = settings.OLLAMA_TIMEOUT
USE_OLLAMA = True
DB_FILE = settings.DATABASE_FILE

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def safe_rerun():
    try:
        st.experimental_rerun()
    except Exception:
        try:
            st.rerun()
        except Exception:
            st.stop()

def load_data():
    """Load database and ensure passwords are hashed"""
    if os.path.exists(DB_FILE):
        try:
            with open(DB_FILE, 'r') as f:
                data = json.load(f)
                # Migrate plaintext PINs to hashed versions
                for user_id, user_data in data.items():
                    if 'pin' in user_data:
                        # Check if PIN is plaintext (not hashed)
                        pin = user_data['pin']
                        if not pin.startswith('$2b$'):  # bcrypt hash starts with $2b$
                            # Hash the plaintext PIN
                            user_data['hashed_pin'] = password_hasher.hash_password(pin)
                            del user_data['pin']  # Remove plaintext
                    
                    # Initialize security fields if missing
                    if 'failed_login_attempts' not in user_data:
                        user_data['failed_login_attempts'] = 0
                    if 'last_login' not in user_data:
                        user_data['last_login'] = None
                    if 'account_locked_until' not in user_data:
                        user_data['account_locked_until'] = None
                
                # Save migrated data
                with open(DB_FILE, 'w') as f:
                    json.dump(data, f, indent=4)
                
                return data
        except Exception as e:
            print(f"Error loading data: {e}")
    
    # Default data with hashed PINs
    return {
        "1234567890": {
            "name": "customer1",
            "hashed_pin": password_hasher.hash_password("0000"),  # Hashed version of 0000
            "balance": 45750.50,
            "type": "Premium Savings",
            "email": "john@email.com",
            "phone": "9876543210",
            "credit_score": 785,
            "failed_login_attempts": 0,
            "last_login": None,
            "account_locked_until": None,
            "history": [42000, 43500, 45000, 44800, 44200, 45750],
            "chats": [],
            "transactions": [
                {"date": "2024-12-05", "desc": "Salary Credit", "cat": "Income", "amt": 5000, "type": "Credit"},
                {"date": "2024-12-03", "desc": "Amazon Purchase", "cat": "Shopping", "amt": -1250, "type": "Debit"},
                {"date": "2024-12-01", "desc": "Rent Payment", "cat": "Bills", "amt": -3500, "type": "Debit"},
                {"date": "2024-11-28", "desc": "Freelance Payment", "cat": "Income", "amt": 2000, "type": "Credit"},
                {"date": "2024-11-25", "desc": "Grocery Shopping", "cat": "Food", "amt": -850, "type": "Debit"},
            ]
        },
        "0987654321": {
            "name": "Customer2",
            "hashed_pin": password_hasher.hash_password("1111"),  # Hashed version of 1111
            "balance": 128300.75,
            "type": "Business Current",
            "email": "jane@email.com",
            "phone": "9123456789",
            "credit_score": 820,
            "failed_login_attempts": 0,
            "last_login": None,
            "account_locked_until": None,
            "history": [110000, 115000, 120000, 125000, 127000, 128300],
            "chats": [],
            "transactions": [
                {"date": "2024-12-04", "desc": "Client Payment", "cat": "Business", "amt": 25000, "type": "Credit"},
                {"date": "2024-12-02", "desc": "Office Supplies", "cat": "Business", "amt": -8500, "type": "Debit"},
                {"date": "2024-11-29", "desc": "Project Payment", "cat": "Business", "amt": 40000, "type": "Credit"},
            ]
        }
    }

def save_data():
    with open(DB_FILE, 'w') as f:
        json.dump(st.session_state.db, f, indent=4)

# ============================================================================
# VALIDATION FUNCTIONS
# ============================================================================

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

# ============================================================================
# OLLAMA FUNCTIONS
# ============================================================================

def get_strict_banking_prompt(user_id, user_query):
    """Generate strict banking-only prompt for Ollama"""
    user = st.session_state.db[user_id]
    recent = "\n".join([f"- {t['date']}: {t['desc']} ({t['cat']}) | Amount: Rs. {t['amt']}" 
                       for t in user['transactions'][:5]])
    
    return f"""You are a STRICTLY REGULATED banking assistant for SecureBank. You MUST follow these rules:

CRITICAL RULES:
1. ONLY answer questions about: account balances, transactions, transfers, loans, credit cards, banking policies, and financial services
2. If asked about ANYTHING else (coding, history, weather, jokes, general knowledge, recipes, travel), respond EXACTLY with: "I apologize, but I can only assist with banking and financial queries."
3. Do NOT provide any information outside banking/finance domain
4. Do NOT explain why you can't answer non-banking questions
5. Keep responses concise and professional

BANK POLICIES (Official Information):
{BANK_KB}

USER DATA (Confidential):
- Name: {user['name']}
- Balance: Rs. {user['balance']:,.2f}
- Account Type: {user['type']}
- Credit Score: {user['credit_score']}
- Recent Transactions:
{recent}

USER QUESTION: {user_query}

YOUR RESPONSE (banking-only, max 300 words):"""

def call_ollama_stream(prompt):
    """Stream response from Ollama"""
    try:
        payload = {
            "model": OLLAMA_MODEL, 
            "prompt": prompt, 
            "stream": True,
            "options": {
                "temperature": 0.1,
                "top_p": 0.9,
                "top_k": 40
            }
        }
        with requests.post(
            f"{OLLAMA_URL.rstrip('/')}/api/generate", 
            json=payload, 
            stream=True, 
            timeout=OLLAMA_TIMEOUT
        ) as resp:
            resp.raise_for_status()
            for line in resp.iter_lines():
                if line:
                    obj = json.loads(line.decode("utf-8"))
                    if obj.get("done"): 
                        break
                    if obj.get("response"): 
                        yield obj.get("response")
    except Exception as e: 
        yield f"[System Error: Unable to connect to AI service]"

# ============================================================================
# RULE-BASED RESPONSES
# ============================================================================

def get_bot_response(prompt: str) -> str:
    """Fast rule-based responses for common queries"""
    prompt_lower = prompt.lower()
    user = st.session_state.db.get(st.session_state.user_id, {})
    
    if any(w in prompt_lower for w in ["balance", "how much money", "fund"]):
        import random
        responses = [
            f"Right now, you have **{format_currency(user.get('balance',0))}** in your {user.get('type','account')} account.",
            f"Your account balance is **{format_currency(user.get('balance',0))}**. Looking good!",
            f"Let me check... You currently have **{format_currency(user.get('balance',0))}** available.",
        ]
        return random.choice(responses) + f"\n\n💳 Credit Score: {user.get('credit_score','N/A')}"
    
    elif any(w in prompt_lower for w in ["transaction", "history", "recent", "last"]):
        trans = user.get('transactions', [])[:3]
        msg = f"Here are your last {len(trans)} transactions:\n\n"
        for t in trans:
            emoji = "✅" if t['type'] == 'Credit' else "💸"
            msg += f"{emoji} **{t['date']}** - {t['desc']}\n   Amount: {format_currency(t['amt'])} | Category: {t['cat']}\n\n"
        return msg
    
    elif any(w in prompt_lower for w in ["spend", "expense", "analytics"]):
        df = pd.DataFrame(user.get('transactions', []))
        debits = df[df['type'] == 'Debit'].copy() if not df.empty else pd.DataFrame()
        total_spent = abs(debits['amt'].sum()) if not debits.empty else 0
        avg_transaction = abs(debits['amt'].mean()) if not debits.empty else 0
        most_spent_cat = debits.groupby('cat')['amt'].sum().abs().idxmax() if (not debits.empty and len(debits)>0) else "N/A"
        return f"📊 **Spending Analysis:**\n\n💰 Total Spent: **{format_currency(total_spent)}**\n📈 Average Transaction: **{format_currency(avg_transaction)}**\n🎯 Top Category: **{most_spent_cat}**"
    
    elif any(w in prompt_lower for w in ["profile", "account", "details", "info"]):
        return f"👤 **Your Profile:**\n\n• Name: {user.get('name')}\n• Account: {st.session_state.user_id}\n• Email: {user.get('email')}\n• Phone: {user.get('phone')}\n• Type: {user.get('type')}\n• Balance: {format_currency(user.get('balance',0))}\n• Credit Score: {user.get('credit_score')} ⭐"
    
    elif any(w in prompt_lower for w in ["transfer", "send", "pay"]):
        return f"💸 **Money Transfer Guide:**\n\nGo to the **Transfer tab** to send money securely.\n\nCurrent balance: {format_currency(user.get('balance',0))}\nDaily limit: Rs. 50,000 🔒"
    
    elif any(w in prompt_lower for w in ["hi", "hello", "hey"]):
        hour = datetime.now().hour
        greeting = "Good morning" if hour < 12 else "Good afternoon" if hour < 18 else "Good evening"
        return f"{greeting} {user.get('name','User').split()[0]}! 👋\n\nHow can I help you today?"
    
    elif any(w in prompt_lower for w in ["bye", "goodbye"]):
        return "Goodbye! Stay secure! 👋"
    
    elif any(w in prompt_lower for w in ["help", "what can you", "what do you do ","who are you"]):
        return f"🤖 **I'm your AI Banking Assistant!**\n\nI can help you with:\n• Check Balance\n• View Transactions\n• Spending Analysis\n• Account Info\n• Transfers\n\nCurrent balance: {format_currency(user.get('balance',0))}"
    
    else:
        return "NEED_OLLAMA"  # Signal that Ollama is needed

# ============================================================================
# CHAT FUNCTIONS
# ============================================================================

def format_currency(amount):
    return f"Rs. {amount:,.2f}"

def add_chat_message(role, content):
    st.session_state.chat_history.append({
        "role": role, 
        "content": content,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })

def generate_fast_title(first_prompt):
    return (first_prompt[:30] + "...") if len(first_prompt) > 30 else first_prompt
def generate_smart_title(first_prompt):
    """Slow but smart title generation"""
    try:
        if not USE_OLLAMA: return (first_prompt[:25] + "..")
        prompt = f"Summarize this into a 3-4 word title (no quotes): '{first_prompt}'"
        payload = {"model": OLLAMA_MODEL, "prompt": prompt, "stream": False}
        resp = requests.post(f"{OLLAMA_URL.rstrip('/')}/api/generate", json=payload, timeout=5)
        if resp.status_code == 200:
            return resp.json().get("response", "").strip().strip('"')
    except: pass
    return (first_prompt[:25] + "..")

def save_current_chat(title_update=None):
    if not st.session_state.chat_history: return
    
    # Generate ID if new
    if st.session_state.current_chat_id is None:
        st.session_state.current_chat_id = str(uuid.uuid4())
        first_msg = st.session_state.chat_history[0]['content']
        # USE FAST TITLE INITIALLY (ZERO DELAY)
        title = title_update if title_update else generate_fast_title(first_msg)
        
        st.session_state.all_chats.insert(0, {
            'id': st.session_state.current_chat_id, 'title': title,
            'messages': list(st.session_state.chat_history),
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
    else:
        # Update existing
        for chat in st.session_state.all_chats:
            if chat['id'] == st.session_state.current_chat_id:
                chat['messages'] = list(st.session_state.chat_history)
                chat['timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                if title_update: chat['title'] = title_update # Update title if requested
                break
    
    if st.session_state.user_id:
        st.session_state.db[st.session_state.user_id]['chats'] = st.session_state.all_chats
        save_data()   

def load_chat(chat_id):
    for chat in st.session_state.all_chats:
        if chat['id'] == chat_id:
            st.session_state.chat_history = list(chat['messages'])
            st.session_state.current_chat_id = chat_id
            return

def start_new_chat():
    st.session_state.chat_history = []
    st.session_state.current_chat_id = None

def delete_chat(chat_id):
    st.session_state.all_chats = [c for c in st.session_state.all_chats if c['id'] != chat_id]
    if st.session_state.current_chat_id == chat_id:
        start_new_chat()
    if st.session_state.user_id:
        st.session_state.db[st.session_state.user_id]['chats'] = st.session_state.all_chats
        save_data()

def process_transfer(recipient, amount):
    """Process transfer with validation"""
    
    # Validate amount
    amount_error = input_validator.validate_amount(amount, max_amount=50000.0)
    if amount_error:
        return False, amount_error
    
    # Sanitize recipient name
    recipient = input_validator.sanitize_text(recipient)
    if not recipient:
        return False, "Recipient name is required"
    
    user = st.session_state.db[st.session_state.user_id]
    
    if amount > user['balance']:
        return False, "Insufficient funds."
    
    # Process transfer
    user['balance'] -= amount
    new_txn = {
        "date": datetime.now().strftime("%Y-%m-%d"),
        "desc": f"Transfer to {recipient}",
        "cat": "Transfer",
        "amt": -amount,
        "type": "Debit"
    }
    user['transactions'].insert(0, new_txn)
    user['history'].append(user['balance'])
    
    save_data()
    return True, f"Transfer successful! Rs. {amount:,.2f} sent to {recipient}"
    

# ============================================================================
# STREAMLIT CONFIG
# ============================================================================

st.set_page_config(
    page_title="SecureBank",
    page_icon="💳",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
    * {
        margin: 0;
        padding:  0;
        box-sizing: border-box;
    }
    
    .stApp {
        background: linear-gradient(135deg, #0f172a 0%, #1a2e4a 50%, #0d1b2a 100%);
        font-family: 'Segoe UI', 'Roboto', sans-serif;
        color: #e0e0e0;
    }
    
    /* HEADERS */
    h1, h2, h3, h4, h5, h6 {
        color: #ffffff;
        font-weight: 700;
        letter-spacing: 0.5px;
    }
    
    h1 {
        font-size: 2.5em;
        background: linear-gradient(120deg, #00d9ff, #0099ff);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
    }
    
    /* BANK CARD */
    .bank-card {
        background: linear-gradient(135deg, rgba(0, 217, 255, 0.1), rgba(0, 153, 255, 0.05));
        backdrop-filter: blur(20px);
        border-radius:  24px;
        padding: 32px;
        border: 1px solid rgba(0, 217, 255, 0.2);
        color: #e0e0e0;
        box-shadow: 0 20px 60px rgba(0, 0, 0, 0.4), inset 0 1px 0 rgba(255, 255, 255, 0.1);
        margin-bottom: 24px;
        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        position: relative;
        overflow: hidden;
    }
    
    .bank-card::before {
        content:  '';
        position: absolute;
        top: -50%;
        right: -50%;
        width:  100%;
        height: 100%;
        background: radial-gradient(circle, rgba(0, 217, 255, 0.1) 0%, transparent 70%);
        pointer-events: none;
    }
    
    .bank-card: hover {
        transform: translateY(-8px);
        border-color: rgba(0, 217, 255, 0.4);
        box-shadow: 0 30px 80px rgba(0, 217, 255, 0.2), inset 0 1px 0 rgba(255, 255, 255, 0.2);
    }
    
    /* STAT CARDS */
    .stat-card {
        background: linear-gradient(135deg, rgba(65, 90, 119, 0.3), rgba(30, 41, 59, 0.3));
        border:  1.5px solid rgba(100, 150, 200, 0.3);
        border-radius: 20px;
        padding: 24px;
        color: white;
        height: 100%;
        transition: all 0.3s ease;
        backdrop-filter: blur(10px);
    }
    
    . stat-card:hover {
        border-color: rgba(0, 217, 255, 0.5);
        box-shadow: 0 15px 40px rgba(0, 217, 255, 0.1);
    }
    
    /* CHAT BUBBLES */
    .chat-bubble-user {
        background: linear-gradient(135deg, #0066ff, #00d4ff);
        padding: 12px 16px;
        border-radius: 12px 12px 0px 12px;
        border: none;
        box-shadow: 0 2px 8px rgba(0, 92, 75, 0.3);
        color: white;
        font-weight: 400;
        display: inline-block;
        max-width: 70%;
        word-wrap: break-word;
        margin: 8px 0;
        margin-left: auto;
        text-align: left;
        animation: slideInRight 0.3s ease;
    }

    .chat-bubble-assistant {
        background: linear-gradient(135deg, #1a2847, #0f1929);
        padding: 12px 16px;
        border-radius: 12px 12px 12px 0px;
        border: none;
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.2);
        display: inline-block;
        max-width: 70%;
        word-wrap: break-word;
        color: #e9edef;
        font-weight: 400;
        margin: 8px 0;
        margin-right: auto;
        text-align: left;
        animation: slideInLeft 0.3s ease;
    }

    /* Container for chat messages */
    .chat-message-container {
        display: flex;
        width: 100%;
        margin: 4px 0;
    }

    .chat-message-user {
        display: flex;
        justify-content: flex-end;
        width: 100%;
    }

    .chat-message-assistant {
        display: flex;
        justify-content: flex-start;
        width: 100%;
    }

    @keyframes slideInRight {
        from { opacity: 0; transform: translateX(20px); }
        to { opacity: 1; transform:  translateX(0); }
    }

    @keyframes slideInLeft {
        from { opacity: 0; transform: translateX(-20px); }
        to { opacity:  1; transform: translateX(0); }
    }

    .chat-timestamp {
        font-size: 0.75em;
        color: rgba(255, 255, 255, 0.6);
        margin-top: 4px;
        font-weight: 500;
    }
    
    /* BUTTONS */
    .stButton button {
        background: linear-gradient(135deg, #0066ff, #00d4ff) ;
        border: 1px solid rgba(0, 212, 255, 0.5) ;
        color:  white ;
        border-radius: 12px ;
        font-weight: 600 ;
        padding:  10px 20px ;
        box-shadow: 0 8px 25px rgba(0, 102, 255, 0.25) ;
        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1) ;
    }

    .stButton button:hover {
        background: linear-gradient(135deg, #00d4ff, #0066ff) ;
        box-shadow: 0 12px 35px rgba(0, 180, 255, 0.4) ;
        transform: translateY(-3px) ;
    }

    .stButton button:active {
        transform:  translateY(-1px) ;
        box-shadow: 0 6px 20px rgba(0, 150, 255, 0.3) ;
    }
    /* INPUT FIELDS */
    .stTextInput input, .stNumberInput input, .stTextArea textarea {
        background-color: rgba(15, 23, 42, 0.8) ;
        border: 1.5px solid rgba(100, 150, 200, 0.3) ;
        border-radius: 12px ;
        color: #e0e0e0  ;
        padding: 12px 16px ;
        transition: all 0.2s ease ;
    }
    
    .stTextInput input:focus, .stNumberInput input:focus, .stTextArea textarea:focus {
        border-color: rgba(0, 217, 255, 0.8) ;
        box-shadow: 0 0 0 3px rgba(0, 217, 255, 0.1) ;
    }
    
    /* TABS */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        background-color: transparent;
    }
    
    .stTabs [data-baseweb="tab"] {
        height: 50px;
        padding: 8px 24px;
        background-color:  rgba(30, 41, 59, 0.5);
        border-radius: 12px 12px 0 0;
        border:  1px solid rgba(100, 150, 200, 0.2);
        color: #a0aec0;
        font-weight: 600;
        transition: all 0.3s ease;
    }
    
    .stTabs [aria-selected="true"] {
        background:  linear-gradient(135deg, rgba(0, 153, 255, 0.2), rgba(0, 217, 255, 0.1));
        border-color: rgba(0, 217, 255, 0.4);
        color: #00d9ff;
        box-shadow: 0 4px 15px rgba(0, 217, 255, 0.2);
    }
    
    /* SIDEBAR */
    [data-testid="stSidebar"] {
        background:  linear-gradient(180deg, #0f172a 0%, #1a2e4a 100%);
        border-right: 1px solid rgba(0, 217, 255, 0.2);
    }
    
    [data-testid="stSidebar"] [data-testid="stBaseButton"] {
        border-radius: 12px;
    }
    
    /* METRICS */
    .stMetric {
        background: linear-gradient(135deg, rgba(65, 90, 119, 0.2), rgba(30, 41, 59, 0.2));
        padding: 20px;
        border-radius: 16px;
        border: 1px solid rgba(100, 150, 200, 0.2);
        transition: all 0.3s ease;
    }
    
    .stMetric:hover {
        border-color: rgba(0, 217, 255, 0.4);
        box-shadow: 0 10px 30px rgba(0, 217, 255, 0.1);
    }
    
    /* DATAFRAME */
    .stDataFrame {
        background-color: transparent ! important;
    }
    
    [data-testid="stDataFrameContainer"] {
        background:  linear-gradient(135deg, rgba(30, 41, 59, 0.3), rgba(15, 23, 42, 0.3));
        border-radius: 16px;
        padding: 16px;
        border: 1px solid rgba(100, 150, 200, 0.2);
    }
    
    /* ALERTS */
    .stAlert {
        border-radius: 12px;
        backdrop-filter: blur(10px);
    }
    
    .stSuccess {
        background-color: rgba(0, 200, 100, 0.2) !important;
        border:  1px solid rgba(0, 200, 100, 0.5) !important;
    }
    
    .stError {
        background-color: rgba(255, 100, 100, 0.2) !important;
        border:  1px solid rgba(255, 100, 100, 0.5) !important;
    }
    
    .stWarning {
        background-color:  rgba(255, 200, 0, 0.2) !important;
        border: 1px solid rgba(255, 200, 0, 0.5) !important;
    }
    
    . stInfo {
        background-color: rgba(0, 150, 255, 0.2) !important;
        border: 1px solid rgba(0, 150, 255, 0.5) !important;
    }
    
    /* HIDE FOOTER */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    
    /* EXPANDER */
    .stExpander {
        background-color: rgba(30, 41, 59, 0.3);
        border: 1px solid rgba(100, 150, 200, 0.2);
        border-radius: 12px;
    }
    
    .stExpander [data-testid="stExpanderDetails"] {
        background-color: rgba(15, 23, 42, 0.5);
    }
</style>
""", unsafe_allow_html=True)
# ----------------------------------------------------------------------------- 
# 2. STATE MANAGEMENT
# ----------------------------------------------------------------------------- 

if "db" not in st.session_state:
    st.session_state.db = load_data()
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "user_id" not in st.session_state:
    st.session_state.user_id = None
if "session_data" not in st.session_state:
    st.session_state.session_data = None
if "chat_history" not in st.session_state:
    st.session_state.chat_history = []
if "all_chats" not in st.session_state:
    st.session_state.all_chats = []
if "current_chat_id" not in st.session_state:
    st.session_state.current_chat_id = None
if "retry_prompt" not in st.session_state:
    st.session_state.retry_prompt = None











# ----------------------------------------------------------------------------- 
# 3. LOGIN SCREEN
# ----------------------------------------------------------------------------- 

def login_screen():
    """Secure login screen with rate limiting and validation"""
    st.markdown("<br><br>", unsafe_allow_html=True)
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        st.markdown("""
            <div style='text-align: center; margin-bottom: 30px;'>
                <div style='font-size: 80px; margin-bottom: 10px;'>🏦</div>
                <h1 style='color: #667eea; font-size: 3em; margin: 0;'>SecureBank</h1>
                <p style='color: #a0aec0; font-size: 1.2em; margin-top: 10px;'>
                    Secure Banking • Powered by AI
                </p>
            </div>
        """, unsafe_allow_html=True)
        
        with st.form("login_form"):
            st.markdown("##### Enter Your Credentials")
            
            uid = st.text_input(
                "Account Number",
                max_chars=10,
                placeholder="Enter 10-digit account number",
                help="Your unique 10-digit account number"
            )
            
            pin = st.text_input(
                "Security PIN",
                type="password",
                max_chars=4,
                placeholder="Enter 4-digit PIN",
                help="Your 4-digit security PIN"
            )
            
            st.markdown("<br>", unsafe_allow_html=True)
            
            col_btn1, col_btn2 = st.columns(2)
            with col_btn1:
                submit = st.form_submit_button(
                    "🔓 Login",
                    use_container_width=True,
                    type="primary"
                )
            with col_btn2:
                demo = st.form_submit_button(
                    "👁️ View Demo Accounts",
                    use_container_width=True
                )
            
            if submit:
                # Step 1: Input Validation
                account_error = input_validator.validate_account_number(uid)
                pin_error = input_validator.validate_pin(pin)
                
                if account_error:
                    st.error(f"⚠️ {account_error}")
                elif pin_error:
                    st.error(f"⚠️ {pin_error}")
                else:
                    # Step 2: Rate Limiting Check
                    is_locked, lock_message = rate_limiter.is_locked_out(uid)
                    
                    if is_locked:
                        st.error(f"🔒 {lock_message}")
                        st.warning("For security reasons, your account has been temporarily locked.")
                    else:
                        # Step 3: Verify Credentials
                        user_data = st.session_state.db.get(uid)
                        
                        if user_data and password_hasher.verify_password(pin, user_data.get('hashed_pin', '')):
                            # SUCCESS - Login
                            rate_limiter.reset_attempts(uid)
                            
                            # Create session
                            st.session_state.session_data = session_manager.create_session(uid)
                            st.session_state.authenticated = True
                            st.session_state.user_id = uid
                            
                            # Update user data
                            user_data['last_login'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            user_data['failed_login_attempts'] = 0
                            
                            # Load user chats
                            st.session_state.all_chats = user_data.get('chats', [])
                            st.session_state.chat_history = []
                            st.session_state.current_chat_id = None
                            
                            save_data()
                            
                            st.success("✅ Authentication Successful!")
                            time.sleep(0.6)
                            safe_rerun()
                        else:
                            # FAILURE - Invalid credentials
                            rate_limiter.record_attempt(uid)
                            
                            # Update failed attempts
                            if user_data:
                                user_data['failed_login_attempts'] = user_data.get('failed_login_attempts', 0) + 1
                                save_data()
                            
                            # Calculate remaining attempts
                            attempts_made = len(rate_limiter.attempts.get(uid, []))
                            attempts_left = settings.MAX_LOGIN_ATTEMPTS - attempts_made
                            
                            if attempts_left > 0:
                                st.error(f"❌ Invalid credentials. {attempts_left} attempts remaining.")
                            else:
                                st.error(f"❌ Invalid credentials. Account will be locked.")
            
            if demo:
                st.session_state.show_demo = True
        
        # Show demo accounts
        if st.session_state.get("show_demo", False):
            st.markdown("---\n### 🧪 Demo Test Accounts")
            st.info("**Note**: These are demo credentials for testing purposes only.")
            
            col_acc1, col_acc2 = st.columns(2)
            
            with col_acc1:
                st.markdown("""
                    <div style='background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                                padding: 20px; border-radius: 15px; color: white;'>
                        <h4>👤 Personal Account</h4>
                        <p><strong>Account:</strong> 1234567890</p>
                        <p><strong>PIN:</strong> 0000</p>
                    </div>
                """, unsafe_allow_html=True)
            
            with col_acc2:
                st.markdown("""
                    <div style='background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); 
                                padding: 20px; border-radius: 15px; color: white;'>
                        <h4>💼 Business Account</h4>
                        <p><strong>Account:</strong> 0987654321</p>
                        <p><strong>PIN:</strong> 1111</p>
                    </div>
                """, unsafe_allow_html=True)
        
        # Security notice
        st.markdown("---")
        st.caption("🔒 Your connection is secure and encrypted. We never store passwords in plaintext.")

# ----------------------------------------------------------------------------- 
# 4. DASHBOARD SCREEN
# ----------------------------------------------------------------------------- 

def dashboard_screen():
    """Dashboard with session validation"""
    
    # ============================================================================
    # SESSION VALIDATION - ADD THIS AT THE TOP
    # ============================================================================
    if not st.session_state.session_data or not session_manager.is_session_valid(st.session_state.session_data):
        st.error("⚠️ Your session has expired. Please login again.")
        st.session_state.authenticated = False
        st.session_state.user_id = None
        st.session_state.session_data = None
        time.sleep(2)
        safe_rerun()
        return
    
    # Update session activity
    st.session_state.session_data = session_manager.update_activity(st.session_state.session_data)
    user = st.session_state.db[st.session_state.user_id]
    
    # Sidebar
    with st.sidebar:
        st.title("🏦 SecureBank")
        st.write(f"**{user['name']}**")
        st.caption(f"Account: {st.session_state.user_id}")
        st.markdown("---")
        
        
        
        st.subheader("Account Summary")
        st.metric("Balance", format_currency(user['balance']))
        st.metric("Credit Score", user['credit_score'])
        st.markdown("---")
        
        if st.button("🚪 Logout", use_container_width=True):
    # Clear session data
            st.session_state.authenticated = False
            st.session_state.user_id = None
            st.session_state.session_data = None
            st.session_state.chat_history = []
            st.session_state.all_chats = []
            st.session_state.current_chat_id = None
    
            st.success("✅ Logged out successfully!")
            time.sleep(1)
            safe_rerun()
    
    # Header
    c1, c2 = st.columns([3, 1])
    with c1:
        hour = datetime.now().hour
        greeting = "Good Morning" if hour < 12 else "Good Afternoon" if hour < 18 else "Good Evening"
        st.title(f"{greeting}, {user['name'].split()[0]}")
    with c2:
        st.caption("🔒 Secure Connection • Encrypted")
        st.write(datetime.now().strftime("%B %d, %Y"))
    
    # Tabs
    tab1, tab2, tab3, tab4 = st.tabs(["📊 Overview", "📈 Analytics", "💸 Transfer", "💬 Assistant"])
    
    # TAB 1: Overview
    with tab1:
        col_card, col_stats = st.columns([1.5, 2.5])
        with col_card:
            st.markdown(f"""
                <div class="bank-card">
                    <div style="display:flex; justify-content:space-between;">
                        <span>Current Balance</span>
                        <span style="font-size:1.5em;">💳</span>
                    </div>
                    <h1 style="margin:10px 0;">{format_currency(user['balance'])}</h1>
                    <div style="display:flex; justify-content:space-between; margin-top:20px;">
                        <span>**** **** **** {st.session_state.user_id[-4:]}</span>
                        <span>EXP 12/28</span>
                    </div>
                </div>
            """, unsafe_allow_html=True)
        
        with col_stats:
            m1, m2, m3 = st.columns(3)
            df = pd.DataFrame(user['transactions'])
            income = df[df['type'] == 'Credit']['amt'].sum()
            expense = abs(df[df['type'] == 'Debit']['amt'].sum())
            
            m1.metric("Monthly Income", format_currency(income), "+12%")
            m2.metric("Monthly Spend", format_currency(expense), "-5%")
            m3.metric("Credit Score", user['credit_score'], "+15 pts")
            
            dates = pd.date_range(end=datetime.now(), periods=6).strftime("%b %d")
            fig_trend = go.Figure(go.Scatter(x=dates, y=user['history'], fill='tozeroy', 
                                           line=dict(color='#667eea', width=2)))
            fig_trend.update_layout(margin=dict(l=0, r=0, t=0, b=0), height=80, 
                                  paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
                                  xaxis=dict(showgrid=False, visible=False), yaxis=dict(showgrid=False, visible=False))
            st.plotly_chart(fig_trend, use_container_width=True, config={'displayModeBar': False})

        st.subheader("Recent Activity")
        st.dataframe(
            df[['date', 'desc', 'cat', 'amt', 'type']],
            use_container_width=True,
            column_config={
                "amt": st.column_config.NumberColumn("Amount", format="Rs. %.2f"),
                "date": "Date",
                "desc": "Description",
                "cat": "Category",
                "type": "Type"
            },
            hide_index=True
        )
    
    # TAB 2: Analytics
    with tab2:
        st.markdown("### 📊 Financial Analytics Dashboard")
        
        df = pd.DataFrame(user['transactions'])
        
        col1, col2, col3, col4 = st.columns(4)
        
        total_income = df[df['type'] == 'Credit']['amt'].sum()
        total_expense = abs(df[df['type'] == 'Debit']['amt'].sum())
        net_savings = total_income - total_expense
        avg_transaction = df['amt'].abs().mean()
        
        col1.metric("💰 Total Income", format_currency(total_income), "This Month")
        col2.metric("💸 Total Expenses", format_currency(total_expense), delta="-15%", delta_color="inverse")
        col3.metric("📈 Net Savings", format_currency(net_savings), delta="+8%")
        col4.metric("📊 Avg Transaction", format_currency(avg_transaction))
        
        st.markdown("---")
        
        chart_col1, chart_col2 = st.columns(2)
        
        with chart_col1:
            st.markdown("<div class='stat-card'>", unsafe_allow_html=True)
            st.subheader("🎯 Spending by Category")
            
            spending = df[df['type'] == 'Debit'].copy()
            spending['amt'] = spending['amt'].abs()
            category_totals = spending.groupby('cat')['amt'].sum().reset_index()
            
            fig_pie = px.pie(
                category_totals, 
                values='amt', 
                names='cat',
                hole=0.5,
                color_discrete_sequence=['#667eea', '#764ba2', '#f093fb', '#f5576c', '#4facfe']
            )
            fig_pie.update_traces(
                textposition='outside',
                textinfo='label+percent',
                marker=dict(line=dict(color='#0e1117', width=2))
            )
            fig_pie.update_layout(
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font=dict(color='white', size=12),
                showlegend=True,
                legend=dict(orientation="h", yanchor="bottom", y=-0.2, xanchor="center", x=0.5),
                height=350
            )
            st.plotly_chart(fig_pie, use_container_width=True)
            
            st.markdown("**Category Breakdown:**")
            category_table = category_totals.sort_values('amt', ascending=False)
            category_table['Percentage'] = (category_table['amt'] / category_table['amt'].sum() * 100).round(1)
            category_table['amt'] = category_table['amt'].apply(lambda x: format_currency(x))
            category_table.columns = ['Category', 'Amount', 'Share (%)']
            st.dataframe(category_table, hide_index=True, use_container_width=True)
            
            st.markdown("</div>", unsafe_allow_html=True)

        with chart_col2:
            st.markdown("<div class='stat-card'>", unsafe_allow_html=True)
            st.subheader("📈 Balance Trend")
            
            dates = pd.date_range(end=datetime.now(), periods=len(user['history'])).strftime("%b %d")
            
            fig_area = go.Figure()
            
            fig_area.add_trace(go.Scatter(
                x=dates,
                y=user['history'],
                fill='tozeroy',
                name='Balance',
                line=dict(color='#00ff88', width=3),
                fillcolor='rgba(0, 255, 136, 0.3)',
                mode='lines+markers',
                marker=dict(size=8, color='#00ff88', line=dict(width=2, color='white'))
            ))
            
            fig_area.update_layout(
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font=dict(color='white'),
                xaxis=dict(
                    showgrid=True,
                    gridcolor='rgba(255,255,255,0.1)',
                    title="Date"
                ),
                yaxis=dict(
                    showgrid=True,
                    gridcolor='rgba(255,255,255,0.1)',
                    title="Balance (Rs.)"
                ),
                hovermode='x unified',
                height=350
            )
            st.plotly_chart(fig_area, use_container_width=True)
            
            st.markdown("**Balance Statistics:**")
            balance_stats = pd.DataFrame({
                'Metric': ['Current', 'Highest', 'Lowest', 'Average'],
                'Value': [
                    format_currency(user['history'][-1]),
                    format_currency(max(user['history'])),
                    format_currency(min(user['history'])),
                    format_currency(sum(user['history'])/len(user['history']))
                ]
            })
            st.dataframe(balance_stats, hide_index=True, use_container_width=True)
            
            st.markdown("</div>", unsafe_allow_html=True)
        
        st.markdown("---")
        
        col_bar1, col_bar2 = st.columns([2, 1])
        
        with col_bar1:
            st.markdown("<div class='stat-card'>", unsafe_allow_html=True)
            st.subheader("💵 Income vs Expenses Comparison")
            
            type_summary = df.groupby('type')['amt'].apply(lambda x: abs(x).sum()).reset_index()
            
            fig_bar = px.bar(
                type_summary,
                x='type',
                y='amt',
                color='type',
                color_discrete_map={'Credit': '#00ff88', 'Debit': '#ff6b6b'},
                text='amt'
            )
            fig_bar.update_traces(
                texttemplate='Rs. %{text:,.0f}',
                textposition='outside'
            )
            fig_bar.update_layout(
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font=dict(color='white'),
                xaxis_title="Transaction Type",
                yaxis_title="Amount (Rs.)",
                showlegend=False,
                height=300
            )
            st.plotly_chart(fig_bar, use_container_width=True)
            st.markdown("</div>", unsafe_allow_html=True)
        
        with col_bar2:
            st.markdown("<div class='stat-card'>", unsafe_allow_html=True)
            st.subheader("🎯 Financial Health")
            
            savings_rate = (net_savings / total_income * 100) if total_income > 0 else 0
            health_score = min(100, max(0, savings_rate * 2))
            
            fig_gauge = go.Figure(go.Indicator(
                mode="gauge+number",
                value=health_score,
                domain={'x': [0, 1], 'y': [0, 1]},
                title={'text': "Health Score", 'font': {'color': 'white'}},
                number={'suffix': "%", 'font': {'color': 'white'}},
                gauge={
                    'axis': {'range': [None, 100], 'tickcolor': "white"},
                    'bar': {'color': "#00ff88"},
                    'bgcolor': "#1f2937",
                    'borderwidth': 2,
                    'bordercolor': "white",
                    'steps': [
                        {'range': [0, 33], 'color': '#ff6b6b'},
                        {'range': [33, 66], 'color': '#ffd93d'},
                        {'range': [66, 100], 'color': '#00ff88'}
                    ],
                }
            ))
            fig_gauge.update_layout(
                paper_bgcolor='rgba(0,0,0,0)',
                font={'color': "white"},
                height=350,
                margin=dict(l=20, r=20, t=50, b=20)
            )
            st.plotly_chart(fig_gauge, use_container_width=True)
            
            st.metric("Savings Rate", f"{savings_rate:.1f}%")
            st.markdown("</div>", unsafe_allow_html=True)
        
        st.markdown("---")
        
        st.subheader("📋 Transaction Timeline")
        
        df_display = df.copy()
        df_display['amt'] = df_display['amt'].apply(lambda x: format_currency(x))
        df_display = df_display[['date', 'desc', 'cat', 'amt', 'type']]
        df_display.columns = ['Date', 'Description', 'Category', 'Amount', 'Type']
        
        st.dataframe(
            df_display,
            use_container_width=True,
            hide_index=True,
            column_config={
                "Type": st.column_config.TextColumn(
                    "Type",
                    help="Credit or Debit"
                )
            }
        )
    
    # TAB 3: Transfer
    with tab3:
        st.markdown("### 💸 Quick Transfer")
        col_form, col_info = st.columns([1, 1])
        with col_form:
            with st.form("transfer_form"):
                recipient = st.text_input("Recipient Name / Account")
                amount = st.number_input("Amount (Rs.)", min_value=1.0, max_value=100000.0, step=100.0)
                note = st.text_input("Note (Optional)")
                submitted = st.form_submit_button("💳 Send Money", use_container_width=True)
                if submitted:
                    if not recipient:
                        st.error("Please enter a recipient.")
                    else:
                        success, msg = process_transfer(recipient, amount)
                        if success:
                            st.success(f"✅ Successfully sent Rs. {amount:,.2f} to {recipient}!")
                            time.sleep(1)
                            safe_rerun()
                        else:
                            st.error(msg)
        with col_info:
            st.info("**Transfer Limits:**\n\nDaily Limit: Rs. 50,000\n\nSecure transfers with 256-bit encryption.")
    
    # TAB 4: Assistant
    with tab4:
        st.subheader("🤖 AI Banking Assistant")
        if st.session_state.current_chat_id:
            st.caption(f"Session: {st.session_state.current_chat_id[:8]}...")
        else:
            st.caption("New Conversation")
        
        left_col, center_col, right_col = st.columns([2, 4.5, 2])
        
        # LEFT COLUMN: Chat history
        with left_col:
            st.markdown("**Chats**")
            if st.button("➕ New", key="new_left", use_container_width=False):
                start_new_chat()
                safe_rerun()
            
            st.markdown("---")
            
            with st.container(height=400):
                if st.session_state.all_chats:
                    for i, chat in enumerate(st.session_state.all_chats):
                        label = f"🟢 {chat['title']}" if chat['id'] == st.session_state.current_chat_id else chat['title']
                        
                        c_btn, c_del = st.columns([4, 1])
                        with c_btn:
                            if st.button(label, key=f"load_{chat['id']}_{i}", use_container_width=True):
                                load_chat(chat['id'])
                                safe_rerun()
                        with c_del:
                            if st.button("🗑️", key=f"del_{chat['id']}_{i}"):
                                delete_chat(chat['id'])
                                safe_rerun()
                else:
                    st.caption("No history.")
        
        # CENTER COLUMN: Chat interface
        with center_col:
            top_cols = st.columns([1,2])
            
            with top_cols[0]:
                use_ollama = st.checkbox("Ollama", value=USE_OLLAMA, key="ollama_toggle")
            
            st.markdown("<br>", unsafe_allow_html=True)

            # Chat container
            chat_container = st.container()
            with chat_container:
                if not st.session_state.chat_history:
                    st.info("👋 Try: 'Check balance', 'Show transactions', or 'Spending analysis'")
                else:
                    for i, msg in enumerate(st.session_state.chat_history):
                        if msg["role"] == "user":
                            c_msg, c_edit = st.columns([9, 1])
                            with c_msg:
                                st.markdown(f"""
                                    <div class="chat-message-user">
                                        <div class="chat-bubble-user">
                                            {msg["content"]}
                                            <div class="chat-timestamp">{msg['timestamp'].split()[1]}</div>
                                        </div>
                                    </div>
                                """, unsafe_allow_html=True)
                            with c_edit:
                                with st.popover("✏️", use_container_width=True):
                                    new_text = st.text_area("Edit message:", value=msg["content"], key=f"edit_{i}")
                                    if st.button("Save & Retry", key=f"save_{i}"):
                                        # 1. Truncate history
                                        st.session_state.chat_history = st.session_state.chat_history[:i]
                                        # 2. Set retry flag
                                        st.session_state.retry_prompt = new_text
                                        st.session_state.current_chat_id = st.session_state.current_chat_id # Keep ID
                                        safe_rerun()
                        else:
                            st.markdown(f"""
                                <div class="chat-message-assistant">
                                    <div class="chat-bubble-assistant">
                                        {msg["content"]}
                                        <div class="chat-timestamp">{msg['timestamp'].split()[1]}</div>
                                    </div>
                                </div>
                            """, unsafe_allow_html=True)
            # Chat input
            prompt = st.chat_input("Type a message...")
            
            # Handle retry prompt
            if st.session_state.retry_prompt:
                prompt = st.session_state.retry_prompt
                st.session_state.retry_prompt = None
                
            if prompt:
                # STEP 1: Validate query
                is_valid, reason = is_banking_query(prompt)
                
                if not is_valid:
                    # Rejected query - add refusal message
                    add_chat_message("user", prompt)
                    add_chat_message("assistant", reason)
                    save_current_chat()
                    safe_rerun()
                
                # STEP 2: Query is valid (either banking or greeting)
                # Add user message
                add_chat_message("user", prompt)
                
                # STEP 3: Try rule-based response first
                rule_response = get_bot_response(prompt)
                
                if rule_response != "NEED_OLLAMA":
                    # Rule-based response worked (includes greetings!)
                    add_chat_message("assistant", rule_response)
                    save_current_chat()
                    safe_rerun()
                
                # STEP 4: Use Ollama for complex queries
                if use_ollama:
                    save_current_chat()
                    
                    with chat_container:
                        st.markdown(f"""
                            <div class="chat-message-user">
                                <div class="chat-bubble-user">{prompt}</div>
                            </div>
                        """, unsafe_allow_html=True)
                        resp_ph = st.empty()
                        
                        strict_prompt = get_strict_banking_prompt(st.session_state.user_id, prompt)
                        stream = call_ollama_stream(strict_prompt)
                        
                        resp_text = ""
                        for chunk in stream:
                            resp_text += chunk
                            resp_ph.markdown(
                                f"""
                                <div class="chat-message-assistant">
                                    <div class="chat-bubble-assistant">{resp_text}</div>
                                </div>
                                """,
                                unsafe_allow_html=True
                            )
                        
                        # STEP 5: Post-validation
                        resp_text = validate_ollama_response(resp_text, prompt)
                        
                        add_chat_message("assistant", resp_text)
                        save_current_chat()
                        safe_rerun()
                else:
                    # Ollama disabled, use fallback
                    add_chat_message("assistant", "Please enable Ollama for complex queries.")
                    save_current_chat()
                    safe_rerun()
                    
        # RIGHT COLUMN: Quick actions
        with right_col:
            st.markdown("**Quick Actions**")
            if st.button("💳 Show Balance", key="quick_balance", use_container_width=True):
                add_chat_message("user", "What is my balance?")
                add_chat_message("assistant", get_bot_response("balance"))
                save_current_chat()
                safe_rerun()
            
            if st.button("📄 Transactions", key="quick_trans", use_container_width=True):
                add_chat_message("user", "Show my recent transactions")
                add_chat_message("assistant", get_bot_response("transactions"))
                save_current_chat()
                safe_rerun()
            
            st.markdown("---")
            st.markdown("**Suggestions**")
            st.write("• How much did I spend?")
            st.write("• Show transactions")
            st.write("• Transfer money")
            st.write("• Show profile")
            
            st.markdown("---")
            st.markdown("**Export**")
            if st.button("📥 Export Chat", key="export_chat", use_container_width=True):
                if not st.session_state.chat_history:
                    st.warning("No chat to export")
                else:
                    df_export = pd.DataFrame(st.session_state.chat_history)
                    csv = df_export.to_csv(index=False).encode('utf-8')
                    st.download_button("Download CSV", csv, file_name="chat_history.csv", mime="text/csv")
# ----------------------------------------------------------------------------- 
# 6. MAIN EXECUTION
# ----------------------------------------------------------------------------- 

if __name__ == "__main__":
    if st.session_state.authenticated:
        dashboard_screen()
    else:
        login_screen()