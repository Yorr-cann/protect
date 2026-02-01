"""
Lapisan Keamanan 5: Threat Intelligence Real-time dan Perlindungan Lanjutan
"""

import threading
import time
from datetime import datetime, timedelta
import logging
from typing import Dict, Any, List, Optional, Set
import hashlib
import json
import requests
from collections import defaultdict
import socket
import ipaddress

logger = logging.getLogger(__name__)

class ProtectionLayer5:
    def __init__(self):
        self.threat_intelligence = defaultdict(dict)
        self.real_time_threats = defaultdict(list)
        self.threat_patterns = defaultdict(set)
        
        # External threat intelligence feeds (contoh)
        self.threat_feeds = [
            # "https://feeds.example.com/threats.json",  # Contoh feed
        ]
        
        # Internal threat patterns
        self._init_threat_patterns()
        
        # Machine learning model (simplified)
        self.threat_model = {
            'weights': {
                'ip_reputation': 0.3,
                'behavior_anomaly': 0.25,
                'geo_anomaly': 0.2,
                'temporal_anomaly': 0.15,
                'payload_analysis': 0.1
            },
            'threshold': 0.7
        }
        
        self.lock = threading.RLock()
        
        # Start threat intelligence updater
        self.update_thread = threading.Thread(target=self._update_threat_intelligence, daemon=True)
        self.update_thread.start()
    
    def _init_threat_patterns(self):
        """Initialize threat patterns"""
        
        # SQL Injection patterns
        sql_patterns = {
            r"'.*--",
            r"'.*;",
            r"\bUNION\b.*\bSELECT\b",
            r"\bOR\b\s*['\"]?\s*\d+\s*=\s*\d+",
            r"\bAND\b\s*['\"]?\s*\d+\s*=\s*\d+",
            r"\bDROP\b.*\bTABLE\b",
            r"\bDELETE\b.*\bFROM\b",
            r"\bINSERT\b.*\bINTO\b",
            r"\bUPDATE\b.*\bSET\b",
            r"\bEXEC\b.*\(",
            r"\bWAITFOR\b.*\bDELAY\b",
            r"\bSLEEP\s*\(",
            r"\bBENCHMARK\s*\(",
        }
        self.threat_patterns['sql_injection'] = sql_patterns
        
        # XSS patterns
        xss_patterns = {
            r"<script.*>.*</script>",
            r"javascript:",
            r"onload\s*=",
            r"onerror\s*=",
            r"onclick\s*=",
            r"alert\s*\(",
            r"document\.cookie",
            r"window\.location",
            r"eval\s*\(",
            r"setTimeout\s*\(",
            r"setInterval\s*\(",
            r"<iframe.*>",
            r"<img.*onerror.*>",
        }
        self.threat_patterns['xss'] = xss_patterns
        
        # Command injection patterns
        cmd_patterns = {
            r";\s*(ls|dir|cat|type|rm|del|mkdir|cd)",
            r"\|\s*(ls|dir|cat|type|rm|del|mkdir|cd)",
            r"&\s*(ls|dir|cat|type|rm|del|mkdir|cd)",
            r"\$\(",
            r"`.*`",
            r"\.\./",
            r"\.\.\\",
            r"/etc/passwd",
            r"C:\\Windows\\",
            r"ping.*-n.*\d+",
            r"wget.*http",
            r"curl.*http",
        }
        self.threat_patterns['command_injection'] = cmd_patterns
        
        # Path traversal patterns
        path_patterns = {
            r"\.\./\.\./",
            r"\.\.\\\.\.\\",
            r"/etc/",
            r"/bin/",
            r"/usr/",
            r"C:\\",
            r"\.\.%2f",
            r"%2e%2e%2f",
        }
        self.threat_patterns['path_traversal'] = path_patterns
    
    def detect_threat(self, user_id: int, ip_address: str, 
                     user_agent: str, request_data: Dict = None) -> Dict[str, Any]:
        """
        Deteksi threat secara real-time
        
        Returns:
            Dict berisi threat score dan details
        """
        
        with self.lock:
            threat_score = 0
            threats_found = []
            
            # 1. Check IP reputation
            ip_threat = self._check_ip_reputation(ip_address)
            if ip_threat['score'] > 0:
                threat_score += ip_threat['score'] * self.threat_model['weights']['ip_reputation']
                threats_found.append(ip_threat)
            
            # 2. Check user agent anomalies
            ua_threat = self._check_user_agent_threat(user_agent)
            if ua_threat['score'] > 0:
                threat_score += ua_threat['score'] * self.threat_model['weights']['behavior_anomaly']
                threats_found.append(ua_threat)
            
            # 3. Check geo anomalies
            geo_threat = self._check_geo_anomaly(user_id, ip_address)
            if geo_threat['score'] > 0:
                threat_score += geo_threat['score'] * self.threat_model['weights']['geo_anomaly']
                threats_found.append(geo_threat)
            
            # 4. Check temporal anomalies
            time_threat = self._check_temporal_anomaly()
            if time_threat['score'] > 0:
                threat_score += time_threat['score'] * self.threat_model['weights']['temporal_anomaly']
                threats_found.append(time_threat)
            
            # 5. Payload analysis
            if request_data:
                payload_threat = self._analyze_payload(request_data)
                if payload_threat['score'] > 0:
                    threat_score += payload_threat['score'] * self.threat_model['weights']['payload_analysis']
                    threats_found.append(payload_threat)
            
            # 6. Check real-time threat intelligence
            rti_threat = self._check_real_time_threats(ip_address, user_agent)
            if rti_threat['score'] > 0:
                threat_score += rti_threat['score']
                threats_found.append(rti_threat)
            
            # Normalize score to 0-100
            threat_score = min(100, int(threat_score * 100))
            
            # Log jika threat score tinggi
            if threat_score > 50:
                self.log_security_event("THREAT_DETECTED", f"user:{user_id}", "",
                                       f"Score: {threat_score}, Threats: {len(threats_found)}")
            
            return {
                'threat_score': threat_score,
                'is_threat': threat_score >= (self.threat_model['threshold'] * 100),
                'threats_found': threats_found,
                'timestamp': datetime.now().isoformat()
            }
    
    def _check_ip_reputation(self, ip_address: str) -> Dict[str, Any]:
        """Check IP reputation"""
        
        score = 0
        details = []
        
        # Cek apakah IP di threat intelligence
        ip_key = f"ip:{ip_address}"
        if ip_key in self.threat_intelligence:
            threat_data = self.threat_intelligence[ip_key]
            score = threat_data.get('severity', 0) * 10
            details.append(f"Known threat IP: {threat_data.get('reason', 'Unknown')}")
        
        # Cek apakah IP dari datacenter/VPN
        if self._is_datacenter_ip(ip_address):
            score += 20
            details.append("IP from datacenter/VPN")
        
        # Cek apakah IP dari high-risk country
        if self._is_high_risk_country(ip_address):
            score += 30
            details.append("IP from high-risk country")
        
        # Cek apakah IP adalah Tor exit node
        if self._is_tor_exit_node(ip_address):
            score += 50
            details.append("Tor exit node detected")
        
        return {
            'type': 'IP_REPUTATION',
            'score': min(score, 100),
            'details': details
        }
    
    def _check_user_agent_threat(self, user_agent: str) -> Dict[str, Any]:
        """Check user agent untuk threats"""
        
        score = 0
        details = []
        
        # Cek empty user agent
        if not user_agent or user_agent == '':
            score += 40
            details.append("Empty user agent")
        
        # Cek known malicious user agents
        malicious_agents = [
            'sqlmap', 'nmap', 'nessus', 'nikto', 'metasploit',
            'wpscan', 'acunetix', 'appscan', 'burpsuite',
            'zgrab', 'masscan', 'gobuster', 'dirb', 'wfuzz'
        ]
        
        ua_lower = user_agent.lower()
        for malicious in malicious_agents:
            if malicious in ua_lower:
                score += 60
                details.append(f"Security scanner detected: {malicious}")
                break
        
        # Cek suspicious patterns
        suspicious_patterns = [
            r'curl/\d', r'wget/\d', r'python-requests/\d',
            r'Go-http-client/\d', r'Java/\d', r'HttpClient'
        ]
        
        import re
        for pattern in suspicious_patterns:
            if re.search(pattern, user_agent, re.IGNORECASE):
                score += 20
                details.append(f"Suspicious user agent pattern: {pattern}")
                break
        
        return {
            'type': 'USER_AGENT_THREAT',
            'score': min(score, 100),
            'details': details
        }
    
    def _check_geo_anomaly(self, user_id: int, ip_address: str) -> Dict[str, Any]:
        """Check geographic anomalies"""
        
        # Ini membutuhkan integrasi dengan geolocation service
        # Untuk sekarang, return minimal score
        
        return {
            'type': 'GEO_ANOMALY',
            'score': 0,
            'details': ['Geolocation check not implemented']
        }
    
    def _check_temporal_anomaly(self) -> Dict[str, Any]:
        """Check temporal anomalies"""
        
        score = 0
        details = []
        
        current_hour = datetime.now().hour
        
        # Night time activity (lebih risky)
        if 0 <= current_hour < 6:
            score += 20
            details.append("Night time activity (00:00-06:00)")
        
        # Weekend activity
        if datetime.now().weekday() >= 5:
            score += 10
            details.append("Weekend activity")
        
        return {
            'type': 'TEMPORAL_ANOMALY',
            'score': score,
            'details': details
        }
    
    def _analyze_payload(self, request_data: Dict) -> Dict[str, Any]:
        """Analyze request payload untuk threats"""
        
        score = 0
        threats_found = []
        
        # Convert dict ke string untuk pattern matching
        payload_str = json.dumps(request_data)
        
        # Check untuk setiap threat pattern
        for threat_type, patterns in self.threat_patterns.items():
            for pattern in patterns:
                import re
                if re.search(pattern, payload_str, re.IGNORECASE):
                    score += {
                        'sql_injection': 80,
                        'xss': 70,
                        'command_injection': 90,
                        'path_traversal': 60
                    }.get(threat_type, 50)
                    
                    threats_found.append({
                        'type': threat_type.upper(),
                        'pattern': pattern,
                        'severity': 'HIGH' if threat_type in ['sql_injection', 'command_injection'] else 'MEDIUM'
                    })
                    break  # Hanya hitung sekali per threat type
        
        return {
            'type': 'PAYLOAD_ANALYSIS',
            'score': min(score, 100),
            'details': threats_found
        }
    
    def _check_real_time_threats(self, ip_address: str, user_agent: str) -> Dict[str, Any]:
        """Check real-time threat intelligence"""
        
        score = 0
        details = []
        
        # Cek IP dalam real-time threats
        if ip_address in self.real_time_threats:
            threats = self.real_time_threats[ip_address]
            score = len(threats) * 20
            details.extend([t['reason'] for t in threats[-3:]])  # Last 3 threats
        
        # Cek untuk coordinated attacks
        coordinated = self._detect_coordinated_attack(ip_address)
        if coordinated['detected']:
            score += 40
            details.append(f"Coordinated attack pattern: {coordinated['pattern']}")
        
        return {
            'type': 'REAL_TIME_THREAT',
            'score': min(score, 100),
            'details': details
        }
    
    def _is_datacenter_ip(self, ip_address: str) -> bool:
        """Check jika IP dari datacenter"""
        try:
            ip = ipaddress.ip_address(ip_address)
            
            # Known datacenter IP ranges
            datacenter_ranges = [
                '3.0.0.0/9',      # AWS
                '34.0.0.0/8',     # Google Cloud
                '13.0.0.0/8',     # Microsoft Azure
                '52.0.0.0/8',     # AWS
                '35.0.0.0/8',     # Google Cloud
                '20.0.0.0/8',     # Microsoft Azure
            ]
            
            for range_str in datacenter_ranges:
                if ip in ipaddress.ip_network(range_str):
                    return True
        except:
            pass
        
        return False
    
    def _is_high_risk_country(self, ip_address: str) -> bool:
        """Check jika IP dari high-risk country"""
        # Ini membutuhkan geolocation database
        # Untuk sekarang, return False
        return False
    
    def _is_tor_exit_node(self, ip_address: str) -> bool:
        """Check jika IP adalah Tor exit node"""
        # Ini membutuhkan Tor exit node list
        # Untuk sekarang, return False
        return False
    
    def _detect_coordinated_attack(self, ip_address: str) -> Dict[str, Any]:
        """Deteksi coordinated attack patterns"""
        
        # Simpan request timestamp untuk IP ini
        ip_key = f"request_times:{ip_address}"
        if ip_key not in self.threat_intelligence:
            self.threat_intelligence[ip_key] = []
        
        request_times = self.threat_intelligence[ip_key]
        request_times.append(time.time())
        
        # Keep only last 60 seconds
        cutoff = time.time() - 60
        request_times = [t for t in request_times if t > cutoff]
        self.threat_intelligence[ip_key] = request_times
        
        # Cek untuk DDoS pattern (banyak requests dalam waktu singkat)
        if len(request_times) > 100:  # 100 requests per minute
            return {
                'detected': True,
                'pattern': 'DDoS',
                'rate': len(request_times)
            }
        
        # Cek untuk scanning pattern (regular interval)
        if len(request_times) > 10:
            intervals = []
            for i in range(1, len(request_times)):
                intervals.append(request_times[i] - request_times[i-1])
            
            # Jika intervals sangat regular (low variance)
            if intervals:
                import statistics
                if len(intervals) > 5:
                    variance = statistics.variance(intervals)
                    if variance < 0.1:  # Very regular
                        return {
                            'detected': True,
                            'pattern': 'SCANNING',
                            'regularity': variance
                        }
        
        return {'detected': False, 'pattern': 'None'}
    
    def add_threat_intelligence(self, threat_type: str, threat_value: str, 
                               severity: int, source: str, reason: str = ""):
        """Add threat intelligence"""
        
        with self.lock:
            key = f"{threat_type}:{threat_value}"
            
            self.threat_intelligence[key] = {
                'threat_type': threat_type,
                'threat_value': threat_value,
                'severity': severity,
                'source': source,
                'reason': reason,
                'first_seen': datetime.now().isoformat(),
                'last_seen': datetime.now().isoformat(),
                'count': self.threat_intelligence.get(key, {}).get('count', 0) + 1
            }
            
            # Untuk IP threats, tambah ke real-time threats
            if threat_type == 'ip':
                if threat_value not in self.real_time_threats:
                    self.real_time_threats[threat_value] = []
                
                self.real_time_threats[threat_value].append({
                    'timestamp': datetime.now().isoformat(),
                    'severity': severity,
                    'reason': reason,
                    'source': source
                })
                
                # Keep only last 10 threats per IP
                if len(self.real_time_threats[threat_value]) > 10:
                    self.real_time_threats[threat_value] = self.real_time_threats[threat_value][-10:]
            
            logger.info(f"Added threat intelligence: {key} - {reason}")
    
    def _update_threat_intelligence(self):
        """Update threat intelligence dari external feeds"""
        
        while True:
            try:
                for feed_url in self.threat_feeds:
                    try:
                        response = requests.get(feed_url, timeout=10)
                        if response.status_code == 200:
                            threats = response.json()
                            self._process_threat_feed(threats, feed_url)
                    except Exception as e:
                        logger.error(f"Failed to fetch threat feed {feed_url}: {e}")
                
                # Cleanup old threats (older than 30 days)
                self._cleanup_old_threats(30)
                
            except Exception as e:
                logger.error(f"Error in threat intelligence update: {e}")
            
            # Update setiap 1 jam
            time.sleep(3600)
    
    def _process_threat_feed(self, threats: List[Dict], source: str):
        """Process threat feed data"""
        
        for threat in threats:
            threat_type = threat.get('type', 'ip')
            threat_value = threat.get('value', '')
            severity = threat.get('severity', 5)
            reason = threat.get('reason', 'External threat feed')
            
            if threat_value:
                self.add_threat_intelligence(threat_type, threat_value, 
                                           severity, source, reason)
    
    def _cleanup_old_threats(self, max_age_days: int):
        """Cleanup old threat intelligence"""
        
        with self.lock:
            cutoff = datetime.now() - timedelta(days=max_age_days)
            keys_to_remove = []
            
            for key, threat_data in self.threat_intelligence.items():
                last_seen = datetime.fromisoformat(threat_data['last_seen'])
                if last_seen < cutoff:
                    keys_to_remove.append(key)
            
            for key in keys_to_remove:
                del self.threat_intelligence[key]
            
            # Cleanup real-time threats
            ips_to_clean = []
            for ip, threats in self.real_time_threats.items():
                # Filter threats older than 7 days
                recent_threats = []
                for threat in threats:
                    threat_time = datetime.fromisoformat(threat['timestamp'])
                    if threat_time > cutoff:
                        recent_threats.append(threat)
                
                if recent_threats:
                    self.real_time_threats[ip] = recent_threats
                else:
                    ips_to_clean.append(ip)
            
            for ip in ips_to_clean:
                del self.real_time_threats[ip]
            
            logger.info(f"Cleaned up {len(keys_to_remove)} old threats")
    
    def log_security_event(self, event_type: str, identifier: str, 
                          user_agent: str, details: str = ""):
        """Log event keamanan"""
        
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'layer': 'PROTECT5',
            'event_type': event_type,
            'identifier': identifier,
            'user_agent': user_agent[:200],
            'details': details[:500]
        }
        
        logger.warning(f"Protect5 Event - {event_type}: {identifier}, Details={details}")
        
        # Simpan ke file log
        try:
            with open('security_layer5.log', 'a') as f:
                f.write(f"{log_entry}\n")
        except Exception as e:
            logger.error(f"Failed to write security log: {e}")
        
        # Jika high severity event, tambah ke threat intelligence
        if event_type in ['THREAT_DETECTED', 'COORDINATED_ATTACK']:
            # Extract IP dari identifier jika ada
            if 'ip:' in identifier:
                ip = identifier.split('ip:')[-1]
                self.add_threat_intelligence('ip', ip, 8, 'internal', 
                                           f"{event_type}: {details[:100]}")
    
    def get_threat_statistics(self) -> Dict[str, Any]:
        """Get threat statistics"""
        
        with self.lock:
            total_threats = len(self.threat_intelligence)
            
            # Count by type
            threats_by_type = defaultdict(int)
            for threat_data in self.threat_intelligence.values():
                threats_by_type[threat_data['threat_type']] += 1
            
            # Real-time threat stats
            active_ips = len(self.real_time_threats)
            total_rt_threats = sum(len(threats) for threats in self.real_time_threats.values())
            
            return {
                'total_threats': total_threats,
                'threats_by_type': dict(threats_by_type),
                'active_threat_ips': active_ips,
                'total_real_time_threats': total_rt_threats,
                'threat_patterns_loaded': sum(len(patterns) for patterns in self.threat_patterns.values())
            }