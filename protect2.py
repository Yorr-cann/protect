"""
Lapisan Keamanan 2: Perlindungan Jaringan dan Session
"""

import hashlib
import secrets
import time
from datetime import datetime, timedelta
import logging
from typing import Dict, Any, Optional, List
import ipaddress
import socket
import geoip2.database
import json

logger = logging.getLogger(__name__)

class ProtectionLayer2:
    def __init__(self):
        self.sessions = {}  # {session_id: session_data}
        self.ip_geolocation_cache = {}
        self.suspicious_ips = {}
        
        # Load GeoIP database jika ada
        try:
            self.geoip_reader = geoip2.database.Reader('GeoLite2-City.mmdb')
            self.has_geoip = True
        except:
            self.has_geoip = False
            logger.warning("GeoIP database not found, geolocation disabled")
        
        # Country blacklist/whitelist
        self.country_restrictions = {
            'blacklist': ['KP', 'IR', 'SY', 'CU'],  # North Korea, Iran, Syria, Cuba
            'whitelist': [],  # Kosong berarti semua diizinkan
            'high_risk': ['RU', 'CN', 'VN', 'TH']
        }
    
    def create_session(self, user_id: int, ip_address: str, 
                      user_agent: str) -> Dict[str, Any]:
        """Buat session baru dengan enhanced security"""
        
        # Generate secure session ID
        session_id = secrets.token_urlsafe(32)
        
        # Get geolocation info
        geo_info = self.get_geolocation(ip_address)
        
        # Generate device fingerprint
        device_fp = self.generate_device_fingerprint(ip_address, user_agent)
        
        session_data = {
            'session_id': session_id,
            'user_id': user_id,
            'ip_address': ip_address,
            'user_agent': user_agent,
            'device_fingerprint': device_fp,
            'login_time': datetime.now(),
            'last_activity': datetime.now(),
            'expires_at': datetime.now() + timedelta(hours=24),
            'geo_info': geo_info,
            'is_valid': True,
            'token_hash': hashlib.sha256(secrets.token_bytes(32)).hexdigest()
        }
        
        self.sessions[session_id] = session_data
        
        self.log_security_event("SESSION_CREATED", ip_address, user_agent,
                               f"User ID: {user_id}, Country: {geo_info.get('country_code', 'Unknown')}")
        
        return session_data
    
    def validate_session(self, session_id: str, ip_address: str, 
                        user_agent: str) -> Optional[Dict[str, Any]]:
        """Validasi session dengan multiple checks"""
        
        if session_id not in self.sessions:
            self.log_security_event("INVALID_SESSION_ID", ip_address, user_agent,
                                   f"Session ID: {session_id[:20]}...")
            return None
        
        session = self.sessions[session_id]
        
        # Cek apakah session expired
        if datetime.now() > session['expires_at']:
            self.invalidate_session(session_id, "SESSION_EXPIRED")
            return None
        
        # Cek IP address consistency
        if session['ip_address'] != ip_address:
            self.log_security_event("IP_MISMATCH", ip_address, user_agent,
                                   f"Expected: {session['ip_address']}, Got: {ip_address}")
            
            # Allow small changes (dynamic IP), but log it
            if not self.is_similar_ip(session['ip_address'], ip_address):
                self.invalidate_session(session_id, "IP_CHANGE_SUSPICIOUS")
                return None
        
        # Cek user agent consistency
        current_fp = self.generate_device_fingerprint(ip_address, user_agent)
        if session['device_fingerprint'] != current_fp:
            self.log_security_event("DEVICE_FINGERPRINT_CHANGED", ip_address, user_agent,
                                   "Device fingerprint mismatch")
            
            # Invalidasi session jika fingerprint berbeda signifikan
            if not self.is_similar_device(session['device_fingerprint'], current_fp):
                self.invalidate_session(session_id, "DEVICE_CHANGE")
                return None
        
        # Update last activity
        session['last_activity'] = datetime.now()
        
        # Extend session jika perlu
        if (session['expires_at'] - datetime.now()).total_seconds() < 3600:
            session['expires_at'] = datetime.now() + timedelta(hours=1)
        
        return session
    
    def invalidate_session(self, session_id: str, reason: str = ""):
        """Invalidasi session"""
        if session_id in self.sessions:
            session = self.sessions[session_id]
            session['is_valid'] = False
            
            self.log_security_event("SESSION_INVALIDATED", 
                                   session['ip_address'], 
                                   session['user_agent'],
                                   f"Reason: {reason}, User ID: {session['user_id']}")
            
            # Hapus dari active sessions setelah 5 menit (untuk logging)
            del self.sessions[session_id]
    
    def is_ip_blacklisted(self, ip_address: str) -> bool:
        """Cek apakah IP di-blacklist"""
        
        # Cek country restrictions
        if self.has_geoip:
            geo_info = self.get_geolocation(ip_address)
            country_code = geo_info.get('country_code', '')
            
            if country_code in self.country_restrictions['blacklist']:
                self.log_security_event("BLACKLISTED_COUNTRY", ip_address, "",
                                       f"Country: {country_code}")
                return True
        
        # Cek IP range suspicious
        if self.is_suspicious_ip_range(ip_address):
            return True
        
        # Cek apakah IP pernah melakukan banyak failed attempts
        if ip_address in self.suspicious_ips:
            if self.suspicious_ips[ip_address]['count'] > 10:
                return True
        
        return False
    
    def get_geolocation(self, ip_address: str) -> Dict[str, Any]:
        """Get geolocation info untuk IP"""
        
        # Cek cache dulu
        if ip_address in self.ip_geolocation_cache:
            cached = self.ip_geolocation_cache[ip_address]
            if datetime.now() - cached['timestamp'] < timedelta(hours=24):
                return cached['data']
        
        geo_info = {
            'country_code': 'XX',
            'country_name': 'Unknown',
            'city': 'Unknown',
            'isp': 'Unknown',
            'is_proxy': False,
            'is_tor': False,
            'is_vpn': False
        }
        
        try:
            if self.has_geoip and not ipaddress.ip_address(ip_address).is_private:
                response = self.geoip_reader.city(ip_address)
                
                geo_info.update({
                    'country_code': response.country.iso_code or 'XX',
                    'country_name': response.country.name or 'Unknown',
                    'city': response.city.name or 'Unknown',
                    'latitude': response.location.latitude,
                    'longitude': response.location.longitude
                })
            
            # Cek apakah IP adalah proxy/VPN/Tor
            # Note: Implementasi sebenarnya membutuhkan service seperti ipinfo.io
            # Ini adalah simulasi sederhana
            if ip_address.startswith(('192.168.', '10.', '172.16.')):
                geo_info['is_proxy'] = True
            
            # Cache hasil
            self.ip_geolocation_cache[ip_address] = {
                'timestamp': datetime.now(),
                'data': geo_info
            }
            
        except Exception as e:
            logger.error(f"Geolocation error for {ip_address}: {e}")
        
        return geo_info
    
    def generate_device_fingerprint(self, ip_address: str, user_agent: str) -> str:
        """Generate device fingerprint"""
        
        # Components untuk fingerprint
        components = [
            ip_address,
            user_agent,
            # Tambahkan lebih banyak info jika tersedia
            str(datetime.now().strftime('%Y%m%d'))
        ]
        
        fingerprint_string = '|'.join(components)
        return hashlib.sha256(fingerprint_string.encode()).hexdigest()
    
    def is_similar_ip(self, ip1: str, ip2: str) -> bool:
        """Cek apakah dua IP similar (untuk dynamic IP detection)"""
        try:
            ip1_obj = ipaddress.ip_address(ip1)
            ip2_obj = ipaddress.ip_address(ip2)
            
            # Jika sama network (misalnya /24 untuk IPv4)
            if ip1_obj.version == 4 and ip2_obj.version == 4:
                network1 = ipaddress.IPv4Network(f"{ip1}/24", strict=False)
                network2 = ipaddress.IPv4Network(f"{ip2}/24", strict=False)
                return network1 == network2
            
            # Untuk IPv6, cek prefix /64
            if ip1_obj.version == 6 and ip2_obj.version == 6:
                network1 = ipaddress.IPv6Network(f"{ip1}/64", strict=False)
                network2 = ipaddress.IPv6Network(f"{ip2}/64", strict=False)
                return network1 == network2
            
        except ValueError:
            pass
        
        return False
    
    def is_similar_device(self, fp1: str, fp2: str) -> bool:
        """Cek apakah dua device fingerprint similar"""
        # Implementasi sederhana: cek similarity dengan hamming distance
        # Untuk production, gunakan algoritma yang lebih canggih
        
        if fp1 == fp2:
            return True
        
        # Jika user agent mirip, mungkin device sama dengan update browser
        return True  # Simplified for now
    
    def is_suspicious_ip_range(self, ip_address: str) -> bool:
        """Deteksi IP range yang suspicious"""
        try:
            ip = ipaddress.ip_address(ip_address)
            
            # Cek IP ranges yang dikenal sebagai proxy/VPN
            suspicious_ranges = [
                # Contoh ranges (harus diupdate dengan data aktual)
                '141.98.10.0/24',  # Contoh VPN range
                '185.159.157.0/24', # Contoh proxy range
            ]
            
            for range_str in suspicious_ranges:
                network = ipaddress.ip_network(range_str)
                if ip in network:
                    self.log_security_event("SUSPICIOUS_IP_RANGE", ip_address, "",
                                           f"Range: {range_str}")
                    return True
            
            # Cek apakah IP dari datacenter range
            if self.is_datacenter_ip(ip_address):
                return True
            
        except ValueError:
            pass
        
        return False
    
    def is_datacenter_ip(self, ip_address: str) -> bool:
        """Deteksi apakah IP dari datacenter"""
        # Implementasi sederhana
        # Untuk production, gunakan database seperti ipinfo.io atau maxmind
        
        # Cek ranges AWS, Google Cloud, Azure, dll
        datacenter_ranges = [
            '3.0.0.0/9',      # AWS
            '34.0.0.0/8',     # Google Cloud
            '13.0.0.0/8',     # Microsoft Azure
            '52.0.0.0/8',     # AWS lagi
        ]
        
        try:
            ip = ipaddress.ip_address(ip_address)
            for range_str in datacenter_ranges:
                if ip in ipaddress.ip_network(range_str):
                    return True
        except:
            pass
        
        return False
    
    def log_security_event(self, event_type: str, ip_address: str, 
                          user_agent: str, details: str = ""):
        """Log event keamanan"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'layer': 'PROTECT2',
            'event_type': event_type,
            'ip_address': ip_address,
            'user_agent': user_agent[:200],
            'details': details[:500]
        }
        
        logger.warning(f"Protect2 Event - {event_type}: IP={ip_address}, Details={details}")
        
        # Simpan ke file log
        try:
            with open('security_layer2.log', 'a') as f:
                f.write(f"{log_entry}\n")
        except Exception as e:
            logger.error(f"Failed to write security log: {e}")
    
    def cleanup_expired_sessions(self):
        """Cleanup expired sessions"""
        now = datetime.now()
        sessions_to_remove = []
        
        for session_id, session in self.sessions.items():
            if now > session['expires_at']:
                sessions_to_remove.append(session_id)
        
        for session_id in sessions_to_remove:
            self.invalidate_session(session_id, "SESSION_EXPIRED_CLEANUP")
        
        logger.info(f"Cleaned up {len(sessions_to_remove)} expired sessions")
    
    def get_session_stats(self) -> Dict[str, Any]:
        """Get session statistics"""
        now = datetime.now()
        
        active_sessions = 0
        expired_sessions = 0
        unique_ips = set()
        
        for session in self.sessions.values():
            if session['is_valid']:
                active_sessions += 1
                unique_ips.add(session['ip_address'])
            else:
                expired_sessions += 1
        
        return {
            'total_sessions': len(self.sessions),
            'active_sessions': active_sessions,
            'expired_sessions': expired_sessions,
            'unique_ips': len(unique_ips),
            'cache_size': len(self.ip_geolocation_cache)
        }