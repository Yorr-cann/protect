"""
Database handler untuk IndictiveCore
"""

import sqlite3
import json
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class SecureDatabase:
    def __init__(self, db_path='secure_data.db'):
        self.db_path = db_path
        self.conn = None
        self.connect()
        self.init_tables()
    
    def connect(self):
        try:
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self.conn.execute('PRAGMA journal_mode=WAL')
            self.conn.execute('PRAGMA foreign_keys=ON')
            logger.info(f"Connected to database: {self.db_path}")
        except Exception as e:
            logger.error(f"Database connection error: {e}")
            raise
    
    def init_tables(self):
        cursor = self.conn.cursor()
        
        # Tabel encryption keys
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS encryption_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_name TEXT UNIQUE NOT NULL,
                key_value TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_used TIMESTAMP,
                status TEXT DEFAULT 'active'
            )
        ''')
        
        # Tabel security policies
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_policies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                policy_name TEXT UNIQUE NOT NULL,
                policy_value TEXT NOT NULL,
                description TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Tabel audit trails
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_trails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action_type TEXT NOT NULL,
                resource_type TEXT,
                resource_id TEXT,
                ip_address TEXT,
                user_agent TEXT,
                details TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Tabel threat intelligence
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_intelligence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                threat_type TEXT NOT NULL,
                threat_value TEXT NOT NULL,
                severity INTEGER DEFAULT 1,
                source TEXT,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP,
                is_active INTEGER DEFAULT 1
            )
        ''')
        
        # Insert default policies
        default_policies = [
            ('max_login_attempts', '5', 'Maximum login attempts before lockout'),
            ('session_timeout', '3600', 'Session timeout in seconds'),
            ('password_min_length', '12', 'Minimum password length'),
            ('require_mfa', 'true', 'Require multi-factor authentication'),
            ('ip_whitelist', '[]', 'List of allowed IP addresses'),
            ('rate_limit_per_minute', '10', 'Requests per minute limit')
        ]
        
        for policy in default_policies:
            cursor.execute('''
                INSERT OR IGNORE INTO security_policies (policy_name, policy_value, description)
                VALUES (?, ?, ?)
            ''', policy)
        
        self.conn.commit()
    
    def log_audit(self, user_id, action_type, resource_type=None, resource_id=None,
                 ip_address=None, user_agent=None, details=None):
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT INTO audit_trails 
                (user_id, action_type, resource_type, resource_id, ip_address, user_agent, details)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (user_id, action_type, resource_type, resource_id, ip_address, user_agent, 
                  json.dumps(details) if details else None))
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Audit log error: {e}")
            return False
    
    def get_policy(self, policy_name):
        cursor = self.conn.cursor()
        cursor.execute('SELECT policy_value FROM security_policies WHERE policy_name = ?',
                      (policy_name,))
        result = cursor.fetchone()
        return result[0] if result else None
    
    def update_policy(self, policy_name, policy_value):
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                UPDATE security_policies 
                SET policy_value = ?, updated_at = ?
                WHERE policy_name = ?
            ''', (policy_value, datetime.now().isoformat(), policy_name))
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Policy update error: {e}")
            return False
    
    def add_threat(self, threat_type, threat_value, severity=1, source=None):
        try:
            cursor = self.conn.cursor()
            # Cek apakah threat sudah ada
            cursor.execute('''
                SELECT id FROM threat_intelligence 
                WHERE threat_type = ? AND threat_value = ?
            ''', (threat_type, threat_value))
            
            existing = cursor.fetchone()
            
            if existing:
                # Update last seen
                cursor.execute('''
                    UPDATE threat_intelligence 
                    SET last_seen = ?, is_active = 1 
                    WHERE id = ?
                ''', (datetime.now().isoformat(), existing[0]))
            else:
                # Insert new threat
                cursor.execute('''
                    INSERT INTO threat_intelligence 
                    (threat_type, threat_value, severity, source, last_seen)
                    VALUES (?, ?, ?, ?, ?)
                ''', (threat_type, threat_value, severity, source, 
                      datetime.now().isoformat()))
            
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Threat add error: {e}")
            return False
    
    def get_threats(self, threat_type=None, active_only=True):
        cursor = self.conn.cursor()
        
        if threat_type:
            if active_only:
                cursor.execute('''
                    SELECT * FROM threat_intelligence 
                    WHERE threat_type = ? AND is_active = 1
                    ORDER BY last_seen DESC
                ''', (threat_type,))
            else:
                cursor.execute('''
                    SELECT * FROM threat_intelligence 
                    WHERE threat_type = ?
                    ORDER BY last_seen DESC
                ''', (threat_type,))
        else:
            if active_only:
                cursor.execute('''
                    SELECT * FROM threat_intelligence 
                    WHERE is_active = 1
                    ORDER BY last_seen DESC
                ''')
            else:
                cursor.execute('''
                    SELECT * FROM threat_intelligence 
                    ORDER BY last_seen DESC
                ''')
        
        columns = [desc[0] for desc in cursor.description]
        threats = []
        
        for row in cursor.fetchall():
            threat = dict(zip(columns, row))
            threat['first_seen'] = datetime.fromisoformat(threat['first_seen'])
            threat['last_seen'] = datetime.fromisoformat(threat['last_seen']) if threat['last_seen'] else None
            threats.append(threat)
        
        return threats
    
    def store_encryption_key(self, key_name, key_value):
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO encryption_keys (key_name, key_value, last_used)
                VALUES (?, ?, ?)
            ''', (key_name, key_value, datetime.now().isoformat()))
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Key storage error: {e}")
            return False
    
    def get_encryption_key(self, key_name):
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT key_value FROM encryption_keys 
            WHERE key_name = ? AND status = 'active'
        ''', (key_name,))
        result = cursor.fetchone()
        
        if result:
            # Update last used timestamp
            cursor.execute('''
                UPDATE encryption_keys 
                SET last_used = ? 
                WHERE key_name = ?
            ''', (datetime.now().isoformat(), key_name))
            self.conn.commit()
            return result[0]
        
        return None
    
    def close(self):
        if self.conn:
            self.conn.close()
            logger.info("Database connection closed")
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

# Singleton instance
secure_db = SecureDatabase()
