# security.py
import bcrypt
import math
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict

class PasswordHasher:
    """Handle password hashing and verification"""
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash a password using bcrypt"""
        salt = bcrypt.gensalt(rounds=12)
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')
    
    @staticmethod
    def verify_password(password: str, hashed: str) -> bool:
        """Verify a password against a hash"""
        try:
            return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
        except Exception:
            return False


class SessionManager:
    """Manage user sessions with timeout"""
    
    def __init__(self, timeout_minutes: int = 15):
        self.timeout_minutes = timeout_minutes
    
    def create_session(self, user_id: str) -> Dict:
        """Create a new session"""
        return {
            'user_id': user_id,
            'token': secrets.token_urlsafe(32),
            'created_at': datetime.now(),
            'last_activity': datetime.now()
        }
    
    def is_session_valid(self, session: Dict) -> bool:
        """Check if session is still valid"""
        if not isinstance(session, dict):
            return False
        
        last_activity = session.get('last_activity')
        if not isinstance(last_activity, datetime):
            return False

        now = datetime.now()
        # A future activity timestamp must not extend a session indefinitely.
        if last_activity > now:
            return False

        elapsed = now - last_activity
        return elapsed < timedelta(minutes=self.timeout_minutes)
    
    def update_activity(self, session: Dict) -> Dict:
        """Update last activity time"""
        if isinstance(session, dict):
            session['last_activity'] = datetime.now()
        return session


class RateLimiter:
    def __init__(self, max_attempts=3, lockout_minutes=15):
        self.max_attempts = max_attempts
        self.lockout_minutes = lockout_minutes
        self.attempts = {}  # {user_id: [timestamp1, timestamp2, ...]}
    
    def record_attempt(self, user_id: str):
        """Record a failed login attempt"""
        current_time = datetime.now()
        
        if user_id not in self.attempts:
            self.attempts[user_id] = []
        
        # Add current attempt
        self.attempts[user_id].append(current_time)
        
        # Clean old attempts (older than lockout period)
        cutoff_time = current_time - timedelta(minutes=self.lockout_minutes)
        self.attempts[user_id] = [
            t for t in self.attempts[user_id] if t > cutoff_time
        ]
    
    def is_locked_out(self, user_id: str) -> tuple[bool, str]:
        """Check if user is locked out"""
        if user_id not in self.attempts:
            return False, ""
        
        current_time = datetime.now()
        cutoff_time = current_time - timedelta(minutes=self.lockout_minutes)
        
        # Remove old attempts
        self.attempts[user_id] = [
            t for t in self.attempts[user_id] if t > cutoff_time
        ]
        
        # Check if locked
        if len(self.attempts[user_id]) >= self.max_attempts:
            oldest_attempt = min(self.attempts[user_id])
            unlock_time = oldest_attempt + timedelta(minutes=self.lockout_minutes)
            remaining = (unlock_time - current_time).seconds // 60
            return True, f"Account locked. Try again in {remaining} minute(s)."
        
        return False, ""
    
    def reset_attempts(self, user_id: str):
        """Reset attempts after successful login"""
        if user_id in self.attempts:
            self.attempts[user_id] = []


class InputValidator:
    """Validate and sanitize user inputs"""
    
    @staticmethod
    def validate_account_number(account: str) -> Optional[str]:
        """Validate account number format"""
        if not isinstance(account, str):
            return "Account number must be a string"
        if not account:
            return "Account number is required"
        
        account = account.strip()
        
        if not account.isdigit():
            return "Account number must contain only digits"
        
        if len(account) != 10:
            return "Account number must be exactly 10 digits"
        
        return None
    
    @staticmethod
    def validate_pin(pin: str) -> Optional[str]:
        """Validate PIN format"""
        if not isinstance(pin, str):
            return "PIN must be a string"
        if not pin:
            return "PIN is required"
        
        pin = pin.strip()
        
        if not pin.isdigit():
            return "PIN must contain only digits"
        
        if len(pin) != 4:
            return "PIN must be exactly 4 digits"
        
        return None
    
    @staticmethod
    def validate_amount(amount: float, max_amount: float = 100000.0, min_amount: float = 1.0) -> Optional[str]:
        """Validate transaction amount"""
        if isinstance(amount, bool) or not isinstance(amount, (int, float)):
            return "Amount must be a finite number"

        amount = float(amount)
        if not math.isfinite(amount):
            return "Amount must be a finite number"

        if amount < min_amount:
            return f"Amount must be at least Rs. {min_amount}"
        
        if amount > max_amount:
            return f"Amount cannot exceed Rs. {max_amount:,.2f}"
        
        return None
    
    @staticmethod
    def sanitize_text(text: str) -> str:
        """Sanitize text input to prevent XSS"""
        import re
        if not isinstance(text, str) or not text:
            return ""
        # Remove potentially dangerous characters
        text = re.sub(r'[<>"\']', '', text)
        return text.strip()
