# security.py
import bcrypt
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, Tuple
from collections import defaultdict
import streamlit as st

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
        if not session:
            return False
        
        last_activity = session.get('last_activity')
        if not last_activity:
            return False
        
        elapsed = datetime.now() - last_activity
        return elapsed < timedelta(minutes=self.timeout_minutes)
    
    def update_activity(self, session: Dict) -> Dict:
        """Update last activity time"""
        if session:
            session['last_activity'] = datetime.now()
        return session


class RateLimiter:
    """Rate limiting for login attempts"""
    
    def __init__(self, max_attempts: int = 5, lockout_minutes: int = 15):
        self.max_attempts = max_attempts
        self.lockout_minutes = lockout_minutes
        self.attempts = defaultdict(list)
    
    def record_attempt(self, identifier: str):
        """Record a login attempt"""
        now = datetime.now()
        self.attempts[identifier].append(now)
        # Clean old attempts
        cutoff = now - timedelta(minutes=self.lockout_minutes)
        self.attempts[identifier] = [
            t for t in self.attempts[identifier] if t > cutoff
        ]
    
    def is_locked_out(self, identifier: str) -> Tuple[bool, Optional[str]]:
        """Check if identifier is locked out"""
        now = datetime.now()
        cutoff = now - timedelta(minutes=self.lockout_minutes)
        
        # Clean old attempts
        self.attempts[identifier] = [
            t for t in self.attempts[identifier] if t > cutoff
        ]
        
        attempt_count = len(self.attempts[identifier])
        
        if attempt_count >= self.max_attempts:
            if self.attempts[identifier]:
                unlock_time = self.attempts[identifier][0] + timedelta(minutes=self.lockout_minutes)
                remaining = unlock_time - now
                minutes_left = max(0, remaining.seconds // 60)
                return True, f"Too many failed attempts. Try again in {minutes_left} minutes."
            return True, "Account temporarily locked."
        
        return False, None
    
    def reset_attempts(self, identifier: str):
        """Reset attempts for identifier"""
        if identifier in self.attempts:
            del self.attempts[identifier]


class InputValidator:
    """Validate and sanitize user inputs"""
    
    @staticmethod
    def validate_account_number(account: str) -> Optional[str]:
        """Validate account number format"""
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
        if amount < min_amount:
            return f"Amount must be at least Rs. {min_amount}"
        
        if amount > max_amount:
            return f"Amount cannot exceed Rs. {max_amount:,.2f}"
        
        return None
    
    @staticmethod
    def sanitize_text(text: str) -> str:
        """Sanitize text input to prevent XSS"""
        import re
        if not text:
            return ""
        # Remove potentially dangerous characters
        text = re.sub(r'[<>"\']', '', text)
        return text.strip()