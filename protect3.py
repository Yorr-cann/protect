"""
Lapisan Keamanan 3: Rate Limiting dan Perlindungan Resource
"""

import time
from datetime import datetime, timedelta
import logging
from typing import Dict, Any, Optional, List
from collections import defaultdict
import threading

logger = logging.getLogger(__name__)

class ProtectionLayer3:
    def __init__(self):
        self.rate_limits = defaultdict(lambda: defaultdict(list))
        self.resource_access = defaultdict(lambda: defaultdict(int))
        self.user_behavior = defaultdict(lambda: defaultdict(list))
        
        # Konfigurasi rate limiting
        self.limits = {
            'login': {'limit': 5, 'window': 300},  # 5 attempts dalam 5 menit
            'api': {'limit': 100, 'window': 60},   # 100 requests per menit
            'session': {'limit': 10, 'window': 3600},  # 10 sessions per jam
            'password_reset': {'limit': 3, 'window': 3600},  # 3 reset per jam
            'general': {'limit': 1000, 'window': 3600}  # 1000 requests per jam
        }
        
        # Resource protection rules
        self.resource_rules = {
            '/admin/': {'min_role': 'admin', 'rate_limit': 50},
            '/api/dashboard-data': {'rate_limit': 30},
            '/api/tools': {'rate_limit': 60},
            '/tool/': {'rate_limit': 20}
        }
        
        self.lock = threading.RLock()
    
    def check_rate_limit(self, identifier: str, request_type: str = 'general') -> bool:
        """
        Cek rate limit untuk identifier
        
        Returns:
            True jika diizinkan, False jika blocked
        """
        with self.lock:
            now = time.time()
            
            # Get limit configuration
            limit_config = self.limits.get(request_type, self.limits['general'])
            limit = limit_config['limit']
            window = limit_config['window']
            
            # Clean old timestamps
            timestamps = self.rate_limits[identifier][request_type]
            timestamps = [ts for ts in timestamps if now - ts < window]
            self.rate_limits[identifier][request_type] = timestamps
            
            # Cek apakah melebihi limit
            if len(timestamps) >= limit:
                self.log_security_event("RATE_LIMIT_EXCEEDED", identifier, "",
                                       f"Type: {request_type}, Count: {len(timestamps)}")
                return False
            
            # Tambahkan timestamp baru
            timestamps.append(now)
            
            # Trim jika terlalu banyak
            if len(timestamps) > limit * 2:
                self.rate_limits[identifier][request_type] = timestamps[-limit:]
            
            return True
    
    def check_ip_rate_limit(self, ip_address: str) -> bool:
        """Cek rate limit untuk IP address"""
        return self.check_rate_limit(f"ip:{ip_address}", 'general')
    
    def check_user_rate_limit(self, user_id: int) -> bool:
        """Cek rate limit untuk user"""
        return self.check_rate_limit(f"user:{user_id}", 'general')
    
    def check_login_rate_limit(self, ip_address: str) -> bool:
        """Cek rate limit untuk login attempts"""
        return self.check_rate_limit(f"login_ip:{ip_address}", 'login')
    
    def check_resource_access(self, user_id: int, resource_path: str, 
                             user_role: str = 'user') -> bool:
        """Cek akses ke resource dengan rate limiting"""
        
        # Cek resource rules
        for path_prefix, rules in self.resource_rules.items():
            if resource_path.startswith(path_prefix):
                # Cek role-based access
                min_role = rules.get('min_role')
                if min_role and not self.has_minimum_role(user_role, min_role):
                    self.log_security_event("UNAUTHORIZED_RESOURCE_ACCESS", 
                                           f"user:{user_id}", "",
                                           f"Resource: {resource_path}, Role: {user_role}")
                    return False
                
                # Apply resource-specific rate limit
                rate_limit = rules.get('rate_limit', 30)
                identifier = f"user:{user_id}:{path_prefix}"
                
                if not self.check_custom_rate_limit(identifier, rate_limit, 60):
                    self.log_security_event("RESOURCE_RATE_LIMIT_EXCEEDED",
                                           f"user:{user_id}", "",
                                           f"Resource: {resource_path}")
                    return False
        
        # Track resource access untuk behavioral analysis
        self.track_user_behavior(user_id, resource_path)
        
        return True
    
    def check_custom_rate_limit(self, identifier: str, limit: int, 
                               window_seconds: int) -> bool:
        """Cek custom rate limit"""
        with self.lock:
            now = time.time()
            key = f"custom:{identifier}"
            
            # Clean old timestamps
            timestamps = self.rate_limits[key]['custom']
            timestamps = [ts for ts in timestamps if now - ts < window_seconds]
            
            # Cek limit
            if len(timestamps) >= limit:
                return False
            
            # Add new timestamp
            timestamps.append(now)
            self.rate_limits[key]['custom'] = timestamps[-limit:]  # Keep only last N
            
            return True
    
    def has_minimum_role(self, user_role: str, required_role: str) -> bool:
        """Cek apakah user memiliki role yang cukup"""
        role_hierarchy = {
            'user': 1,
            'premium': 2,
            'moderator': 3,
            'admin': 4,
            'superadmin': 5
        }
        
        user_level = role_hierarchy.get(user_role.lower(), 0)
        required_level = role_hierarchy.get(required_role.lower(), 999)
        
        return user_level >= required_level
    
    def track_user_behavior(self, user_id: int, resource_path: str):
        """Track user behavior untuk analisis"""
        with self.lock:
            now = datetime.now()
            hour_key = now.strftime('%Y-%m-%d %H:00')
            
            # Track resource access per hour
            self.user_behavior[user_id][hour_key].append({
                'timestamp': now.isoformat(),
                'resource': resource_path,
                'method': 'GET'  # Simplified
            })
            
            # Keep only last 24 hours of data
            cutoff = now - timedelta(hours=24)
            cutoff_key = cutoff.strftime('%Y-%m-%d %H:00')
            
            keys_to_remove = []
            for hour_key in list(self.user_behavior[user_id].keys()):
                if hour_key < cutoff_key:
                    keys_to_remove.append(hour_key)
            
            for key in keys_to_remove:
                del self.user_behavior[user_id][key]
    
    def analyze_user_behavior(self, user_id: int) -> Dict[str, Any]:
        """Analisis behavior pattern user"""
        with self.lock:
            if user_id not in self.user_behavior:
                return {'risk_score': 0, 'anomalies': []}
            
            behavior_data = self.user_behavior[user_id]
            
            # Hitung metrics
            total_requests = sum(len(requests) for requests in behavior_data.values())
            unique_hours = len(behavior_data)
            
            if unique_hours == 0:
                return {'risk_score': 0, 'anomalies': []}
            
            # Hitung requests per hour
            avg_requests_per_hour = total_requests / unique_hours
            
            # Hitung risk score berdasarkan:
            # 1. Request rate yang tidak normal
            # 2. Waktu akses yang tidak biasa
            # 3. Pola resource access
            
            risk_score = 0
            
            # High request rate (> 100 per jam)
            if avg_requests_per_hour > 100:
                risk_score += 30
            
            # Burst detection (lebih dari 50 requests dalam 5 menit)
            for hour_key, requests in behavior_data.items():
                if len(requests) > 50:
                    # Check timestamps untuk burst dalam 5 menit
                    timestamps = [datetime.fromisoformat(r['timestamp']) 
                                 for r in requests]
                    timestamps.sort()
                    
                    for i in range(len(timestamps) - 10):
                        time_diff = (timestamps[i + 10] - timestamps[i]).total_seconds()
                        if time_diff < 300:  # 10 requests dalam 5 menit
                            risk_score += 40
                            break
            
            anomalies = []
            
            if risk_score > 50:
                anomalies.append({
                    'type': 'HIGH_REQUEST_RATE',
                    'score': risk_score,
                    'details': f"Average requests per hour: {avg_requests_per_hour:.1f}"
                })
            
            return {
                'risk_score': min(risk_score, 100),
                'anomalies': anomalies,
                'metrics': {
                    'total_requests': total_requests,
                    'unique_hours': unique_hours,
                    'avg_requests_per_hour': avg_requests_per_hour
                }
            }
    
    def detect_brute_force(self, ip_address: str, username: str = None) -> bool:
        """Deteksi brute force attack"""
        identifier = f"brute_ip:{ip_address}"
        
        # Cek rate limit dengan window pendek
        if not self.check_custom_rate_limit(identifier, 10, 60):  # 10 attempts per minute
            self.log_security_event("BRUTE_FORCE_DETECTED", ip_address, "",
                                   f"Username: {username}")
            return True
        
        # Cek multiple usernames dari IP yang sama
        if username:
            user_key = f"brute_ip_users:{ip_address}"
            with self.lock:
                if user_key not in self.rate_limits:
                    self.rate_limits[user_key]['users'] = set()
                
                users_set = self.rate_limits[user_key]['users']
                users_set.add(username)
                
                # Jika > 3 usernames berbeda dalam 10 menit
                if len(users_set) > 3:
                    self.log_security_event("MULTIPLE_USERNAME_ATTEMPT", ip_address, "",
                                           f"Usernames: {len(users_set)}")
                    return True
        
        return False
    
    def block_identifier(self, identifier: str, duration_seconds: int = 3600):
        """Block identifier untuk periode tertentu"""
        with self.lock:
            block_key = f"blocked:{identifier}"
            expiry = time.time() + duration_seconds
            self.rate_limits[block_key]['expiry'] = expiry
            
            self.log_security_event("IDENTIFIER_BLOCKED", identifier, "",
                                   f"Duration: {duration_seconds}s")
    
    def is_identifier_blocked(self, identifier: str) -> bool:
        """Cek apakah identifier di-block"""
        with self.lock:
            block_key = f"blocked:{identifier}"
            if block_key in self.rate_limits:
                expiry = self.rate_limits[block_key].get('expiry', 0)
                if time.time() < expiry:
                    return True
                else:
                    # Hapus jika expired
                    del self.rate_limits[block_key]
            
            return False
    
    def log_security_event(self, event_type: str, identifier: str, 
                          user_agent: str, details: str = ""):
        """Log event keamanan"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'layer': 'PROTECT3',
            'event_type': event_type,
            'identifier': identifier,
            'user_agent': user_agent[:200],
            'details': details[:500]
        }
        
        logger.warning(f"Protect3 Event - {event_type}: {identifier}, Details={details}")
        
        # Simpan ke file log
        try:
            with open('security_layer3.log', 'a') as f:
                f.write(f"{log_entry}\n")
        except Exception as e:
            logger.error(f"Failed to write security log: {e}")
    
    def cleanup_old_data(self, max_age_hours: int = 24):
        """Cleanup data lama"""
        with self.lock:
            now = time.time()
            cutoff = now - (max_age_hours * 3600)
            
            # Cleanup rate limits
            for identifier in list(self.rate_limits.keys()):
                for request_type in list(self.rate_limits[identifier].keys()):
                    if request_type == 'expiry':
                        continue
                    
                    # Filter timestamps
                    timestamps = self.rate_limits[identifier][request_type]
                    if isinstance(timestamps, list):
                        filtered = [ts for ts in timestamps if ts > cutoff]
                        self.rate_limits[identifier][request_type] = filtered
            
            # Cleanup user behavior data
            cutoff_dt = datetime.now() - timedelta(hours=max_age_hours)
            cutoff_key = cutoff_dt.strftime('%Y-%m-%d %H:00')
            
            for user_id in list(self.user_behavior.keys()):
                for hour_key in list(self.user_behavior[user_id].keys()):
                    if hour_key < cutoff_key:
                        del self.user_behavior[user_id][hour_key]
                
                # Hapus entry user jika kosong
                if not self.user_behavior[user_id]:
                    del self.user_behavior[user_id]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics"""
        with self.lock:
            return {
                'rate_limit_entries': len(self.rate_limits),
                'tracked_users': len(self.user_behavior),
                'total_behavior_records': sum(
                    len(hours) 
                    for user_data in self.user_behavior.values() 
                    for hours in user_data.values()
                )
            }