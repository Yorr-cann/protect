"""
Lapisan Keamanan 4: Analisis Perilaku dan Deteksi Anomali
"""

import json
import hashlib
from datetime import datetime, timedelta
import logging
from typing import Dict, Any, List, Optional, Tuple
import statistics
from collections import defaultdict
import threading
import re

logger = logging.getLogger(__name__)

class ProtectionLayer4:
    def __init__(self):
        self.user_profiles = defaultdict(dict)
        self.anomaly_scores = defaultdict(lambda: defaultdict(float))
        self.behavior_patterns = defaultdict(lambda: defaultdict(list))
        
        # Thresholds untuk anomaly detection
        self.thresholds = {
            'login_time_anomaly': 0.8,
            'geo_velocity': 500,  # km/jam (tidak mungkin berpindah lebih cepat dari ini)
            'device_change_risk': 0.7,
            'request_pattern_change': 0.6,
            'resource_access_anomaly': 0.75
        }
        
        # Learning period (dalam hari)
        self.learning_period = 7
        
        self.lock = threading.RLock()
    
    def analyze_login_pattern(self, user_id: int, ip_address: str, 
                             user_agent: str, login_time: datetime) -> Dict[str, Any]:
        """Analisis pola login user"""
        
        with self.lock:
            user_key = f"user:{user_id}"
            
            # Get atau init user profile
            if user_key not in self.user_profiles:
                self.user_profiles[user_key] = self._init_user_profile(user_id)
            
            profile = self.user_profiles[user_key]
            
            # Extract features
            features = self._extract_login_features(ip_address, user_agent, login_time)
            
            # Deteksi anomali
            anomalies = []
            risk_score = 0
            
            # 1. Anomali waktu login
            time_anomaly = self._detect_time_anomaly(profile, login_time)
            if time_anomaly['is_anomaly']:
                anomalies.append({
                    'type': 'LOGIN_TIME_ANOMALY',
                    'score': time_anomaly['score'],
                    'details': time_anomaly['details']
                })
                risk_score += time_anomaly['score']
            
            # 2. Anomali device
            device_anomaly = self._detect_device_anomaly(profile, user_agent)
            if device_anomaly['is_anomaly']:
                anomalies.append({
                    'type': 'DEVICE_ANOMALY',
                    'score': device_anomaly['score'],
                    'details': device_anomaly['details']
                })
                risk_score += device_anomaly['score']
            
            # 3. Anomali lokasi (jika ada data geolocation)
            # Ini membutuhkan integrasi dengan service geolocation
            
            # Update profile dengan login terbaru
            self._update_user_profile(profile, features)
            
            # Update anomaly scores
            self.anomaly_scores[user_key]['login'] = risk_score
            
            return {
                'risk_score': risk_score,
                'anomalies': anomalies,
                'features': features
            }
    
    def analyze_user_behavior(self, user_id: int, resource_path: str, 
                             request_method: str, request_data: Dict = None) -> Dict[str, Any]:
        """Analisis perilaku user saat mengakses resource"""
        
        with self.lock:
            user_key = f"user:{user_id}"
            
            # Get atau init user profile
            if user_key not in self.user_profiles:
                self.user_profiles[user_key] = self._init_user_profile(user_id)
            
            profile = self.user_profiles[user_key]
            
            # Track behavior pattern
            behavior_key = f"{resource_path}:{request_method}"
            timestamp = datetime.now()
            
            behavior_record = {
                'timestamp': timestamp.isoformat(),
                'resource': resource_path,
                'method': request_method,
                'data_hash': hashlib.md5(
                    json.dumps(request_data, sort_keys=True).encode()
                ).hexdigest() if request_data else None
            }
            
            self.behavior_patterns[user_key][behavior_key].append(behavior_record)
            
            # Keep only recent records (24 jam terakhir)
            cutoff = timestamp - timedelta(hours=24)
            self.behavior_patterns[user_key][behavior_key] = [
                record for record in self.behavior_patterns[user_key][behavior_key]
                if datetime.fromisoformat(record['timestamp']) > cutoff
            ]
            
            # Deteksi anomali dalam pola akses resource
            anomalies = []
            risk_score = 0
            
            # 1. Deteksi akses resource yang tidak biasa
            resource_anomaly = self._detect_resource_anomaly(profile, resource_path, request_method)
            if resource_anomaly['is_anomaly']:
                anomalies.append({
                    'type': 'RESOURCE_ACCESS_ANOMALY',
                    'score': resource_anomaly['score'],
                    'details': resource_anomaly['details']
                })
                risk_score += resource_anomaly['score']
            
            # 2. Deteksi rate yang tidak normal
            rate_anomaly = self._detect_rate_anomaly(user_key, behavior_key)
            if rate_anomaly['is_anomaly']:
                anomalies.append({
                    'type': 'REQUEST_RATE_ANOMALY',
                    'score': rate_anomaly['score'],
                    'details': rate_anomaly['details']
                })
                risk_score += rate_anomaly['score']
            
            # 3. Deteksi pola waktu yang tidak biasa
            time_anomaly = self._detect_behavior_time_anomaly(profile, timestamp)
            if time_anomaly['is_anomaly']:
                anomalies.append({
                    'type': 'BEHAVIOR_TIME_ANOMALY',
                    'score': time_anomaly['score'],
                    'details': time_anomaly['details']
                })
                risk_score += time_anomaly['score']
            
            # Update profile
            profile['last_activity'] = timestamp.isoformat()
            profile['total_requests'] = profile.get('total_requests', 0) + 1
            
            # Update anomaly scores
            self.anomaly_scores[user_key]['behavior'] = risk_score
            
            return {
                'risk_score': risk_score,
                'anomalies': anomalies,
                'behavior_key': behavior_key,
                'request_count': len(self.behavior_patterns[user_key][behavior_key])
            }
    
    def _init_user_profile(self, user_id: int) -> Dict[str, Any]:
        """Initialize user profile"""
        return {
            'user_id': user_id,
            'created_at': datetime.now().isoformat(),
            'login_times': [],
            'devices': set(),
            'common_ips': set(),
            'resource_access_patterns': defaultdict(list),
            'active_hours': defaultdict(int),
            'last_update': datetime.now().isoformat()
        }
    
    def _extract_login_features(self, ip_address: str, user_agent: str, 
                               login_time: datetime) -> Dict[str, Any]:
        """Extract features dari login attempt"""
        
        # Parse user agent
        browser, os, device = self._parse_user_agent(user_agent)
        
        # Extract time features
        hour = login_time.hour
        day_of_week = login_time.weekday()
        is_weekend = day_of_week >= 5
        
        return {
            'ip_address': ip_address,
            'user_agent': user_agent,
            'browser': browser,
            'os': os,
            'device': device,
            'login_time': login_time.isoformat(),
            'hour': hour,
            'day_of_week': day_of_week,
            'is_weekend': is_weekend,
            'device_fingerprint': self._generate_device_fingerprint(user_agent)
        }
    
    def _parse_user_agent(self, user_agent: str) -> Tuple[str, str, str]:
        """Parse user agent string"""
        # Simplified parsing - untuk production gunakan library seperti user_agents
        browser = "Unknown"
        os = "Unknown"
        device = "Desktop"
        
        if 'Chrome' in user_agent:
            browser = 'Chrome'
        elif 'Firefox' in user_agent:
            browser = 'Firefox'
        elif 'Safari' in user_agent:
            browser = 'Safari'
        elif 'Edge' in user_agent:
            browser = 'Edge'
        
        if 'Windows' in user_agent:
            os = 'Windows'
        elif 'Mac' in user_agent:
            os = 'macOS'
        elif 'Linux' in user_agent:
            os = 'Linux'
        elif 'Android' in user_agent:
            os = 'Android'
            device = 'Mobile'
        elif 'iPhone' in user_agent or 'iPad' in user_agent:
            os = 'iOS'
            device = 'Mobile'
        
        return browser, os, device
    
    def _generate_device_fingerprint(self, user_agent: str) -> str:
        """Generate device fingerprint dari user agent"""
        return hashlib.md5(user_agent.encode()).hexdigest()
    
    def _detect_time_anomaly(self, profile: Dict, login_time: datetime) -> Dict[str, Any]:
        """Deteksi anomali waktu login"""
        
        login_times = profile.get('login_times', [])
        current_hour = login_time.hour
        
        if not login_times:
            # First login, tidak ada baseline
            return {'is_anomaly': False, 'score': 0, 'details': 'First login'}
        
        # Hitung distribusi jam login sebelumnya
        hour_counts = defaultdict(int)
        for lt in login_times[-100:]:  # Gunakan 100 login terakhir
            hour = datetime.fromisoformat(lt).hour
            hour_counts[hour] += 1
        
        # Hitung probability jam saat ini
        total_logins = sum(hour_counts.values())
        if total_logins == 0:
            return {'is_anomaly': False, 'score': 0, 'details': 'Insufficient data'}
        
        current_prob = hour_counts.get(current_hour, 0) / total_logins
        
        # Jika probability sangat rendah (< 0.05), flag sebagai anomali
        if current_prob < 0.05:
            score = min(100, int((0.05 - current_prob) * 2000))
            return {
                'is_anomaly': True,
                'score': score,
                'details': f'Unusual login hour: {current_hour}:00, Probability: {current_prob:.3f}'
            }
        
        return {'is_anomaly': False, 'score': 0, 'details': f'Normal hour: {current_hour}:00'}
    
    def _detect_device_anomaly(self, profile: Dict, user_agent: str) -> Dict[str, Any]:
        """Deteksi anomali device"""
        
        devices = profile.get('devices', set())
        current_device_fp = self._generate_device_fingerprint(user_agent)
        
        if not devices:
            # First device
            return {'is_anomaly': False, 'score': 0, 'details': 'First device'}
        
        if current_device_fp in devices:
            # Device dikenal
            return {'is_anomaly': False, 'score': 0, 'details': 'Known device'}
        
        # Device baru
        browser, os, device_type = self._parse_user_agent(user_agent)
        
        # Cek apakah ada device dengan OS/browser yang sama
        similar_devices = 0
        for device in devices:
            # Simplified similarity check
            if browser in device or os in device:
                similar_devices += 1
        
        # Hitung risk score
        if similar_devices == 0:
            # Device sama sekali baru
            score = 80
            details = f'Completely new device: {browser} on {os}'
        else:
            # Device agak mirip
            score = 40
            details = f'New but similar device: {browser} on {os}'
        
        return {
            'is_anomaly': True,
            'score': score,
            'details': details
        }
    
    def _detect_resource_anomaly(self, profile: Dict, resource_path: str, 
                                request_method: str) -> Dict[str, Any]:
        """Deteksi anomali akses resource"""
        
        patterns = profile.get('resource_access_patterns', defaultdict(list))
        pattern_key = f"{resource_path}:{request_method}"
        
        if not patterns or pattern_key not in patterns:
            # Resource baru untuk user
            return {
                'is_anomaly': True,
                'score': 60,
                'details': f'New resource access: {pattern_key}'
            }
        
        # Hitung frekuensi akses normal
        access_times = patterns[pattern_key]
        if len(access_times) < 5:
            # Tidak cukup data
            return {'is_anomaly': False, 'score': 0, 'details': 'Insufficient data'}
        
        # Untuk sekarang, return normal
        # Di implementasi sebenarnya, bisa lakukan analisis lebih dalam
        return {'is_anomaly': False, 'score': 0, 'details': 'Normal resource access'}
    
    def _detect_rate_anomaly(self, user_key: str, behavior_key: str) -> Dict[str, Any]:
        """Deteksi anomali rate request"""
        
        records = self.behavior_patterns[user_key][behavior_key]
        
        if len(records) < 10:
            # Tidak cukup data
            return {'is_anomaly': False, 'score': 0, 'details': 'Insufficient data'}
        
        # Hitung interval antara requests
        intervals = []
        for i in range(1, len(records)):
            prev_time = datetime.fromisoformat(records[i-1]['timestamp'])
            curr_time = datetime.fromisoformat(records[i]['timestamp'])
            interval = (curr_time - prev_time).total_seconds()
            intervals.append(interval)
        
        if not intervals:
            return {'is_anomaly': False, 'score': 0, 'details': 'No intervals'}
        
        # Hitung mean dan std
        mean_interval = statistics.mean(intervals)
        if mean_interval == 0:
            return {'is_anomaly': False, 'score': 0, 'details': 'Zero mean interval'}
        
        # Cek interval terakhir
        last_interval = intervals[-1]
        
        # Jika interval terakhir jauh lebih kecil dari mean (burst)
        if last_interval < mean_interval * 0.1:  # 10% dari mean
            score = min(100, int((mean_interval / last_interval) * 10))
            return {
                'is_anomaly': True,
                'score': score,
                'details': f'Burst detected: interval {last_interval:.1f}s vs mean {mean_interval:.1f}s'
            }
        
        return {'is_anomaly': False, 'score': 0, 'details': f'Normal rate: {mean_interval:.1f}s avg'}
    
    def _detect_behavior_time_anomaly(self, profile: Dict, timestamp: datetime) -> Dict[str, Any]:
        """Deteksi anomali waktu aktivitas"""
        
        active_hours = profile.get('active_hours', defaultdict(int))
        current_hour = timestamp.hour
        
        if not active_hours:
            return {'is_anomaly': False, 'score': 0, 'details': 'First activity'}
        
        # Hitung total aktivitas
        total_activity = sum(active_hours.values())
        if total_activity == 0:
            return {'is_anomaly': False, 'score': 0, 'details': 'No activity history'}
        
        # Hitung probability jam aktif
        current_prob = active_hours.get(current_hour, 0) / total_activity
        
        # Jika sangat tidak biasa (< 0.01)
        if current_prob < 0.01:
            score = min(100, int((0.01 - current_prob) * 10000))
            return {
                'is_anomaly': True,
                'score': score,
                'details': f'Unusual activity hour: {current_hour}:00, Probability: {current_prob:.4f}'
            }
        
        return {'is_anomaly': False, 'score': 0, 'details': f'Normal activity hour: {current_hour}:00'}
    
    def _update_user_profile(self, profile: Dict, features: Dict):
        """Update user profile dengan features baru"""
        
        # Update login times
        login_times = profile.get('login_times', [])
        login_times.append(features['login_time'])
        # Keep only last 1000 logins
        profile['login_times'] = login_times[-1000:]
        
        # Update devices
        devices = profile.get('devices', set())
        devices.add(features['device_fingerprint'])
        profile['devices'] = devices
        
        # Update common IPs
        common_ips = profile.get('common_ips', set())
        common_ips.add(features['ip_address'])
        profile['common_ips'] = common_ips
        
        # Update active hours
        active_hours = profile.get('active_hours', defaultdict(int))
        active_hours[features['hour']] += 1
        profile['active_hours'] = active_hours
        
        profile['last_update'] = datetime.now().isoformat()
    
    def get_user_risk_score(self, user_id: int) -> Dict[str, Any]:
        """Get overall risk score untuk user"""
        with self.lock:
            user_key = f"user:{user_id}"
            
            login_score = self.anomaly_scores[user_key].get('login', 0)
            behavior_score = self.anomaly_scores[user_key].get('behavior', 0)
            
            overall_score = max(login_score, behavior_score)
            
            # Decay score over time (1% per minute)
            decay_factor = 0.99
            
            return {
                'overall_score': overall_score,
                'login_score': login_score,
                'behavior_score': behavior_score,
                'profile_age': self._get_profile_age(user_key),
                'decayed_score': overall_score * (decay_factor ** self._get_minutes_since_last_activity(user_key))
            }
    
    def _get_profile_age(self, user_key: str) -> Optional[float]:
        """Get profile age dalam hari"""
        if user_key in self.user_profiles:
            created_at = datetime.fromisoformat(self.user_profiles[user_key]['created_at'])
            age = (datetime.now() - created_at).total_seconds() / 86400  # dalam hari
            return age
        return None
    
    def _get_minutes_since_last_activity(self, user_key: str) -> float:
        """Get minutes since last activity"""
        if user_key in self.user_profiles:
            last_update = self.user_profiles[user_key].get('last_update')
            if last_update:
                last_time = datetime.fromisoformat(last_update)
                return (datetime.now() - last_time).total_seconds() / 60
        return 1440  # 24 jam dalam menit
    
    def log_security_event(self, event_type: str, user_id: str, 
                          details: str = ""):
        """Log event keamanan"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'layer': 'PROTECT4',
            'event_type': event_type,
            'user_id': user_id,
            'details': details[:500]
        }
        
        logger.warning(f"Protect4 Event - {event_type}: User={user_id}, Details={details}")
        
        # Simpan ke file log
        try:
            with open('security_layer4.log', 'a') as f:
                f.write(f"{log_entry}\n")
        except Exception as e:
            logger.error(f"Failed to write security log: {e}")
    
    def cleanup_old_profiles(self, max_age_days: int = 30):
        """Cleanup old user profiles"""
        with self.lock:
            cutoff = datetime.now() - timedelta(days=max_age_days)
            
            profiles_to_remove = []
            for user_key, profile in self.user_profiles.items():
                created_at = datetime.fromisoformat(profile['created_at'])
                if created_at < cutoff:
                    profiles_to_remove.append(user_key)
            
            for user_key in profiles_to_remove:
                del self.user_profiles[user_key]
                if user_key in self.anomaly_scores:
                    del self.anomaly_scores[user_key]
                if user_key in self.behavior_patterns:
                    del self.behavior_patterns[user_key]
            
            logger.info(f"Cleaned up {len(profiles_to_remove)} old user profiles")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics"""
        with self.lock:
            total_profiles = len(self.user_profiles)
            total_behavior_records = sum(
                len(records) 
                for user_patterns in self.behavior_patterns.values() 
                for records in user_patterns.values()
            )
            
            # Hitung average risk scores
            risk_scores = []
            for user_key in self.user_profiles.keys():
                user_id = user_key.split(':')[1]
                risk_info = self.get_user_risk_score(int(user_id))
                risk_scores.append(risk_info['overall_score'])
            
            avg_risk = statistics.mean(risk_scores) if risk_scores else 0
            
            return {
                'total_profiles': total_profiles,
                'total_behavior_records': total_behavior_records,
                'average_risk_score': avg_risk,
                'high_risk_users': len([s for s in risk_scores if s > 50])
            }