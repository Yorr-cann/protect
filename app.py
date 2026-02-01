#!/usr/bin/env python3
"""
IndictiveCore - Advanced Dashboard System dengan 5 Lapis Keamanan
"""

import os
import sqlite3
import hashlib
import time
import secrets
import json
import logging
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, session, jsonify, make_response
from functools import wraps
import base64
import uuid
import hmac
from cryptography.fernet import Fernet
import threading
import ipaddress
from user_agents import parse
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import pyotp
from itsdangerous import URLSafeTimedSerializer
import bcrypt

# Import lapisan keamanan
from protect.protect1 import ProtectionLayer1
from protect.protect2 import ProtectionLayer2
from protect.protect3 import ProtectionLayer3
from protect.protect4 import ProtectionLayer4
from protect.protect5 import ProtectionLayer5

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', Fernet.generate_key().decode())

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('security.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Rate Limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

# Inisialisasi lapisan keamanan
protect1 = ProtectionLayer1()
protect2 = ProtectionLayer2()
protect3 = ProtectionLayer3()
protect4 = ProtectionLayer4()
protect5 = ProtectionLayer5()

class Database:
    def __init__(self):
        self.conn = sqlite3.connect('users.db', check_same_thread=False)
        self.create_tables()
    
    def create_tables(self):
        cursor = self.conn.cursor()
        
        # Tabel utama pengguna
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                email TEXT,
                phone TEXT,
                role TEXT DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                status TEXT DEFAULT 'active',
                expiration_date TIMESTAMP,
                mfa_secret TEXT,
                security_level INTEGER DEFAULT 1
            )
        ''')
        
        # Tabel sesi
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                user_id INTEGER,
                ip_address TEXT,
                user_agent TEXT,
                login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active INTEGER DEFAULT 1,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Tabel log keamanan
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT,
                ip_address TEXT,
                user_agent TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                details TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Tabel blacklist IP
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ip_blacklist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                reason TEXT,
                blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP
            )
        ''')
        
        # Tabel failed login attempts
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS failed_logins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT,
                username TEXT,
                attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_agent TEXT
            )
        ''')
        
        self.conn.commit()
    
    def get_user(self, username):
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        return cursor.fetchone()
    
    def create_user(self, username, password, email=None, phone=None):
        try:
            # Generate salt dan hash password dengan bcrypt
            salt = bcrypt.gensalt()
            password_hash = bcrypt.hashpw(password.encode(), salt)
            
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT INTO users (username, password_hash, salt, email, phone, expiration_date)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (username, password_hash, salt, email, phone, 
                  (datetime.now() + timedelta(days=30)).strftime('%Y-%m-%d %H:%M:%S')))
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Error creating user: {e}")
            return False
    
    def validate_user(self, username, password):
        user = self.get_user(username)
        if not user:
            return None
        
        try:
            # Verifikasi password dengan bcrypt
            if bcrypt.checkpw(password.encode(), user[2]):
                return user
        except Exception as e:
            logger.error(f"Password validation error: {e}")
        
        return None
    
    def log_security_event(self, user_id, action, ip_address, user_agent, details=""):
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO security_logs (user_id, action, ip_address, user_agent, details)
            VALUES (?, ?, ?, ?, ?)
        ''', (user_id, action, ip_address, user_agent, details))
        self.conn.commit()
    
    def create_session(self, user_id, ip_address, user_agent):
        session_id = str(uuid.uuid4())
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO sessions (session_id, user_id, ip_address, user_agent)
            VALUES (?, ?, ?, ?)
        ''', (session_id, user_id, ip_address, user_agent))
        self.conn.commit()
        return session_id
    
    def validate_session(self, session_id, ip_address):
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT s.*, u.* FROM sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.session_id = ? AND s.ip_address = ? AND s.is_active = 1
        ''', (session_id, ip_address))
        return cursor.fetchone()

db = Database()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Lapisan keamanan 1: Validasi sesi dasar
        session_id = request.cookies.get('session_id')
        if not session_id:
            return redirect('/login')
        
        # Lapisan keamanan 2: Validasi IP dan session
        user_data = db.validate_session(session_id, request.remote_addr)
        if not user_data:
            protect1.log_security_event("INVALID_SESSION", request.remote_addr, 
                                       request.user_agent.string, "Session tidak valid")
            return redirect('/login?msg=Session%20expired')
        
        # Lapisan keamanan 3: Rate limiting per user
        if not protect3.check_user_rate_limit(user_data[0]):
            protect3.log_security_event("RATE_LIMIT_EXCEEDED", request.remote_addr,
                                       request.user_agent.string, f"User ID: {user_data[0]}")
            return jsonify({"error": "Rate limit exceeded"}), 429
        
        # Lapisan keamanan 4: Behavioral analysis
        if not protect4.analyze_user_behavior(user_data[0], request.path, request.method):
            protect4.log_security_event("SUSPICIOUS_BEHAVIOR", request.remote_addr,
                                       request.user_agent.string, f"User ID: {user_data[0]}")
            return redirect('/login?msg=Suspicious%20activity%20detected')
        
        # Lapisan keamanan 5: Real-time threat detection
        threat_level = protect5.detect_threat(user_data[0], request.remote_addr, 
                                             request.user_agent.string)
        if threat_level > 7:
            protect5.log_security_event("HIGH_THREAT_DETECTED", request.remote_addr,
                                       request.user_agent.string, f"Threat level: {threat_level}")
            return redirect('/login?msg=Security%20threat%20detected')
        
        # Update last activity
        cursor = db.conn.cursor()
        cursor.execute('UPDATE sessions SET last_activity = ? WHERE session_id = ?',
                      (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), session_id))
        db.conn.commit()
        
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('key', '').strip()
        ip_address = request.remote_addr
        user_agent = request.user_agent.string
        
        # Lapisan keamanan 1: Validasi input dasar
        if not protect1.validate_input(username, password):
            protect1.log_security_event("INVALID_INPUT", ip_address, user_agent, 
                                       f"Username: {username}")
            return redirect('/login?msg=Invalid%20input')
        
        # Lapisan keamanan 2: Cek IP blacklist
        if protect2.is_ip_blacklisted(ip_address):
            protect2.log_security_event("BLACKLISTED_IP", ip_address, user_agent)
            time.sleep(2)  # Delay untuk slow down attacker
            return redirect('/login?msg=Access%20denied')
        
        # Lapisan keamanan 3: Rate limiting by IP
        if not protect3.check_ip_rate_limit(ip_address):
            protect3.log_security_event("IP_RATE_LIMIT", ip_address, user_agent)
            return redirect('/login?msg=Too%20many%20attempts')
        
        # Lapisan keamanan 4: Behavioral analysis pada login
        login_pattern = protect4.analyze_login_pattern(ip_address, username, user_agent)
        if login_pattern.get('suspicious', False):
            protect4.log_security_event("SUSPICIOUS_LOGIN_PATTERN", ip_address, user_agent,
                                       f"Pattern: {login_pattern}")
            return redirect('/login?msg=Suspicious%20login%20pattern')
        
        # Validasi user dari database
        user = db.validate_user(username, password)
        
        if user:
            # Lapisan keamanan 5: Real-time threat detection
            threat_score = protect5.detect_login_threat(ip_address, username, user_agent)
            if threat_score > 8:
                protect5.log_security_event("HIGH_THREAT_LOGIN", ip_address, user_agent,
                                           f"Threat score: {threat_score}")
                return redirect('/login?msg=Security%20alert%20-%20login%20blocked')
            
            # Buat session
            session_id = db.create_session(user[0], ip_address, user_agent)
            
            # Update last login
            cursor = db.conn.cursor()
            cursor.execute('UPDATE users SET last_login = ? WHERE id = ?',
                          (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), user[0]))
            db.conn.commit()
            
            # Log event keamanan
            db.log_security_event(user[0], "LOGIN_SUCCESS", ip_address, user_agent)
            
            # Set cookie
            response = make_response(redirect('/dashboard'))
            response.set_cookie('session_id', session_id, httponly=True, secure=True, 
                               max_age=86400)  # 24 jam
            response.set_cookie('user_id', str(user[0]), httponly=True)
            
            return response
        else:
            # Log failed attempt
            cursor = db.conn.cursor()
            cursor.execute('''
                INSERT INTO failed_logins (ip_address, username, user_agent)
                VALUES (?, ?, ?)
            ''', (ip_address, username, user_agent))
            db.conn.commit()
            
            # Lapisan keamanan: Tambahkan ke failed attempts counter
            protect1.add_failed_attempt(ip_address, username)
            
            db.log_security_event(None, "LOGIN_FAILED", ip_address, user_agent, 
                                 f"Username: {username}")
            return redirect('/login?msg=Invalid%20credentials')
    
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    # Get user data from session
    session_id = request.cookies.get('session_id')
    user_data = db.validate_session(session_id, request.remote_addr)
    
    if not user_data:
        return redirect('/login')
    
    # Prepare user info for dashboard
    user_info = {
        'username': user_data[7],  # username from users table
        'role': user_data[12],     # role from users table
        'expired': user_data[14]   # expiration_date from users table
    }
    
    # Calculate days remaining
    if user_data[14]:
        exp_date = datetime.strptime(user_data[14], '%Y-%m-%d %H:%M:%S')
        days_remaining = (exp_date - datetime.now()).days
        if days_remaining < 0:
            days_remaining = 0
    else:
        days_remaining = 30  # default
    
    user_info['daysRemaining'] = days_remaining
    
    return render_template('dashboard.html', user_info=user_info)

@app.route('/api/dashboard-data')
@login_required
def dashboard_data():
    session_id = request.cookies.get('session_id')
    user_data = db.validate_session(session_id, request.remote_addr)
    
    if not user_data:
        return jsonify({"error": "Unauthorized"}), 401
    
    # Calculate active sessions (as active senders)
    cursor = db.conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM sessions WHERE user_id = ? AND is_active = 1',
                  (user_data[0],))
    active_senders = cursor.fetchone()[0]
    
    # Calculate days remaining
    if user_data[14]:  # expiration_date
        exp_date = datetime.strptime(user_data[14], '%Y-%m-%d %H:%M:%S')
        days_remaining = (exp_date - datetime.now()).days
        if days_remaining < 0:
            days_remaining = 0
    else:
        days_remaining = 30
    
    return jsonify({
        "username": user_data[7],
        "role": user_data[12],
        "activeSenders": active_senders,
        "daysRemaining": days_remaining,
        "expired": user_data[14] if user_data[14] else "2024-12-31 23:59:59"
    })

@app.route('/logout')
def logout():
    session_id = request.cookies.get('session_id')
    if session_id:
        cursor = db.conn.cursor()
        cursor.execute('UPDATE sessions SET is_active = 0 WHERE session_id = ?',
                      (session_id,))
        db.conn.commit()
    
    response = make_response(redirect('/login'))
    response.delete_cookie('session_id')
    response.delete_cookie('user_id')
    return response

# API untuk tool media sosial
@app.route('/api/tools')
@login_required
def get_tools():
    tools = [
        {
            "id": 1,
            "title": "Instagram Tools",
            "description": "Kumpulan tool untuk Instagram",
            "image": "https://files.catbox.moe/hwxmr7.jpg",
            "tech": ["Download", "Auto", "Bot"],
            "link": "https://instagram.com",
            "category": "social"
        },
        {
            "id": 2,
            "title": "Telegram Tools",
            "description": "Tool untuk Telegram automation",
            "image": "https://files.catbox.moe/mlm6fk.jpg",
            "tech": ["Bot", "Scraper", "Auto"],
            "link": "https://telegram.org",
            "category": "social"
        },
        {
            "id": 3,
            "title": "YouTube Tools",
            "description": "Downloader dan converter YouTube",
            "image": "https://files.catbox.moe/il60dq.jpg",
            "tech": ["Download", "MP3", "HD"],
            "link": "https://youtube.com",
            "category": "video"
        },
        {
            "id": 4,
            "title": "TikTok Tools",
            "description": "Download video TikTok tanpa watermark",
            "image": "https://files.catbox.moe/d5d0j9.jpg",
            "tech": ["Download", "No WM", "HD"],
            "link": "https://tiktok.com",
            "category": "video"
        },
        {
            "id": 5,
            "title": "Facebook Tools",
            "description": "Tool untuk Facebook automation",
            "image": "https://files.catbox.moe/47f9r5.jpg",
            "tech": ["Auto", "Bot", "Scraper"],
            "link": "https://facebook.com",
            "category": "social"
        },
        {
            "id": 6,
            "title": "Twitter/X Tools",
            "description": "Tool untuk Twitter/X platform",
            "image": "https://files.catbox.moe/j1b3xn.jpg",
            "tech": ["Bot", "Auto", "API"],
            "link": "https://twitter.com",
            "category": "social"
        }
    ]
    return jsonify(tools)

# Redirect handler untuk tool
@app.route('/tool/<path:tool_name>')
@login_required
def tool_redirect(tool_name):
    # Validasi dan logging sebelum redirect
    session_id = request.cookies.get('session_id')
    user_data = db.validate_session(session_id, request.remote_addr)
    
    if user_data:
        db.log_security_event(user_data[0], "TOOL_ACCESS", request.remote_addr,
                             request.user_agent.string, f"Tool: {tool_name}")
    
    # Mapping tool ke URL
    tool_urls = {
        'instagram': 'https://instagram.com',
        'telegram': 'https://telegram.org',
        'youtube': 'https://youtube.com',
        'tiktok': 'https://tiktok.com',
        'facebook': 'https://facebook.com',
        'twitter': 'https://twitter.com',
        'whatsapp': 'https://web.whatsapp.com',
        'discord': 'https://discord.com'
    }
    
    url = tool_urls.get(tool_name.lower(), '/dashboard')
    return redirect(url)

@app.route('/api/weather')
@login_required
def get_weather():
    # Simulasi data cuaca
    import random
    return jsonify({
        "temperature": random.randint(20, 35),
        "humidity": random.randint(40, 80),
        "condition": random.choice(["Sunny", "Cloudy", "Rainy", "Partly Cloudy"]),
        "pressure": round(random.uniform(1000, 1020), 2)
    })

# Admin endpoint untuk monitoring
@app.route('/admin/security-logs')
@login_required
def security_logs():
    session_id = request.cookies.get('session_id')
    user_data = db.validate_session(session_id, request.remote_addr)
    
    if user_data and user_data[12] == 'admin':  # role = admin
        cursor = db.conn.cursor()
        cursor.execute('SELECT * FROM security_logs ORDER BY timestamp DESC LIMIT 100')
        logs = cursor.fetchall()
        
        log_list = []
        for log in logs:
            log_list.append({
                "id": log[0],
                "user_id": log[1],
                "action": log[2],
                "ip_address": log[3],
                "user_agent": log[4],
                "timestamp": log[5],
                "details": log[6]
            })
        
        return jsonify(log_list)
    
    return jsonify({"error": "Unauthorized"}), 403

# Cleanup old sessions (run in background)
def cleanup_sessions():
    while True:
        try:
            cursor = db.conn.cursor()
            # Hapus session yang tidak aktif lebih dari 24 jam
            cutoff = (datetime.now() - timedelta(hours=24)).strftime('%Y-%m-%d %H:%M:%S')
            cursor.execute('DELETE FROM sessions WHERE last_activity < ?', (cutoff,))
            
            # Hapus failed attempts lebih dari 1 jam
            cutoff_failed = (datetime.now() - timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S')
            cursor.execute('DELETE FROM failed_logins WHERE attempt_time < ?', (cutoff_failed,))
            
            db.conn.commit()
        except Exception as e:
            logger.error(f"Cleanup error: {e}")
        
        time.sleep(3600)  # Run every hour

# Start cleanup thread
cleanup_thread = threading.Thread(target=cleanup_sessions, daemon=True)
cleanup_thread.start()

if __name__ == '__main__':
    # Buat user admin default jika belum ada
    admin_user = db.get_user('admin')
    if not admin_user:
        db.create_user('admin', 'Admin@123!', 'admin@indictivecore.com')
        cursor = db.conn.cursor()
        cursor.execute("UPDATE users SET role = 'admin' WHERE username = 'admin'")
        db.conn.commit()
        logger.info("Admin user created")
    
    app.run(host='0.0.0.0', port=5000, debug=False)
