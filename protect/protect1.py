"""
Lapisan Keamanan 1: Validasi Input dan Perlindungan Dasar
"""

import re
import hashlib
import time
from datetime import datetime, timedelta
import logging
from typing import Dict, Any, Optional, Tuple
import ipaddress

logger = logging.getLogger(__name__)

class ProtectionLayer1:
    def __init__(self):
        self.failed_attempts = {}  # {ip: count}
        self.locked_ips = {}  # {ip: unlock_time}
        
        # Regex patterns untuk validasi
        self.patterns = {
            'username': r'^[a-zA-Z0-9_]{3,20}$',
            'password': r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$',
            'email': r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
            'ip_address': r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$',
            'sql_injection': r'(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|EXEC|ALTER|CREATE|TRUNCATE)\b|\-\-|\/\*|\*\/|\b(OR|AND)\b\s*\d+\s*=\s*\d+)',
            'xss': r'<script|javascript:|onload=|onerror=|onclick=|alert\(|document\.|window\.|eval\(|setTimeout\(|setInterval\('
        }
    
    def validate_input(self, username: str, password: str) -> bool:
        """Validasi input username dan password"""
        
        # Validasi panjang
        if not (3 <= len(username) <= 20):
            self.log_security_event("INVALID_USERNAME_LENGTH", "", "", 
                                   f"Username length: {len(username)}")
            return False
        
        if len(password) < 8:
            self.log_security_event("INVALID_PASSWORD_LENGTH", "", "",
                                   f"Password length: {len(password)}")
            return False
        
        # Validasi karakter
        if not re.match(self.patterns['username'], username):
            self.log_security_event("INVALID_USERNAME_FORMAT", "", "",
                                   f"Username: {username}")
            return False
        
        # Deteksi SQL injection
        if self.detect_sql_injection(username) or self.detect_sql_injection(password):
            self.log_security_event("SQL_INJECTION_ATTEMPT", "", "",
                                   f"Input: {username[:50]}...")
            return False
        
        # Deteksi XSS
        if self.detect_xss(username) or self.detect_xss(password):
            self.log_security_event("XSS_ATTEMPT", "", "",
                                   f"Input: {username[:50]}...")
            return False
        
        return True
    
    def detect_sql_injection(self, input_str: str) -> bool:
        """Deteksi percobaan SQL injection"""
        if re.search(self.patterns['sql_injection'], input_str, re.IGNORECASE):
            return True
        return False
    
    def detect_xss(self, input_str: str) -> bool:
        """Deteksi percobaan XSS"""
        if re.search(self.patterns['xss'], input_str, re.IGNORECASE):
            return True
        return False
    
    def sanitize_input(self, input_str: str) -> str:
        """Sanitasi input untuk mencegah injection"""
        import html
        
        # Escape HTML characters
        sanitized = html.escape(input_str)
        
        # Remove SQL comments
        sanitized = re.sub(r'--.*$', '', sanitized, flags=re.MULTILINE)
        sanitized = re.sub(r'/\*.*?\*/', '', sanitized, flags=re.DOTALL)
        
        # Remove null bytes
        sanitized = sanitized.replace('\x00', '')
        
        return sanitized.strip()
    
    def add_failed_attempt(self, ip_address: str, username: str = ""):
        """Tambah failed attempt counter untuk IP"""
        if ip_address not in self.failed_attempts:
            self.failed_attempts[ip_address] = {
                'count': 0,
                'usernames': set(),
                'first_attempt': datetime.now()
            }
        
        self.failed_attempts[ip_address]['count'] += 1
        
        if username:
            self.failed_attempts[ip_address]['usernames'].add(username)
        
        # Jika lebih dari 5 attempts dalam 5 menit, lock IP
        if self.failed_attempts[ip_address]['count'] >= 5:
            lock_duration = min(2 ** (self.failed_attempts[ip_address]['count'] - 5), 3600)
            self.locked_ips[ip_address] = datetime.now() + timedelta(seconds=lock_duration)
            
            self.log_security_event("IP_LOCKED", ip_address, "",
                                   f"Failed attempts: {self.failed_attempts[ip_address]['count']}, "
                                   f"Lock duration: {lock_duration}s")
    
    def is_ip_locked(self, ip_address: str) -> bool:
        """Cek apakah IP sedang di-lock"""
        if ip_address in self.locked_ips:
            if datetime.now() < self.locked_ips[ip_address]:
                return True
            else:
                # Hapus dari lock jika sudah expired
                del self.locked_ips[ip_address]
                if ip_address in self.failed_attempts:
                    del self.failed_attempts[ip_address]
        
        return False
    
    def get_failed_attempts(self, ip_address: str) -> Dict[str, Any]:
        """Get failed attempts info untuk IP"""
        return self.failed_attempts.get(ip_address, {'count': 0, 'usernames': set()})
    
    def validate_ip_address(self, ip_str: str) -> bool:
        """Validasi format IP address"""
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False
    
    def is_private_ip(self, ip_str: str) -> bool:
        """Cek apakah IP adalah private/internal IP"""
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private
        except ValueError:
            return False
    
    def generate_csrf_token(self) -> Tuple[str, str]:
        """Generate CSRF token"""
        import secrets
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        
        return token, token_hash
    
    def verify_csrf_token(self, token: str, token_hash: str) -> bool:
        """Verifikasi CSRF token"""
        computed_hash = hashlib.sha256(token.encode()).hexdigest()
        return computed_hash == token_hash
    
    def log_security_event(self, event_type: str, ip_address: str, 
                          user_agent: str, details: str = ""):
        """Log event keamanan"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'event_type': event_type,
            'ip_address': ip_address,
            'user_agent': user_agent[:200],
            'details': details[:500]
        }
        
        logger.warning(f"Security Event - {event_type}: IP={ip_address}, Details={details}")
        
        # Simpan ke file log
        try:
            with open('security_layer1.log', 'a') as f:
                f.write(f"{log_entry}\n")
        except Exception as e:
            logger.error(f"Failed to write security log: {e}")
    
    def cleanup_old_data(self, max_age_hours: int = 24):
        """Cleanup data lama"""
        cutoff = datetime.now() - timedelta(hours=max_age_hours)
        
        # Cleanup failed attempts
        ips_to_remove = []
        for ip, data in self.failed_attempts.items():
            if data['first_attempt'] < cutoff:
                ips_to_remove.append(ip)
        
        for ip in ips_to_remove:
            del self.failed_attempts[ip]
        
        # Cleanup locked IPs
        ips_to_remove = []
        for ip, unlock_time in self.locked_ips.items():
            if unlock_time < cutoff:
                ips_to_remove.append(ip)
        
        for ip in ips_to_remove:
            del self.locked_ips[ip]
        
        logger.info(f"Cleaned up {len(ips_to_remove)} old IP records")