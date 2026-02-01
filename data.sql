-- File: data.sql
-- Database schema untuk IndictiveCore dengan 5 lapis keamanan

-- Tabel utama pengguna dengan enhanced security fields
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    email TEXT,
    phone TEXT,
    full_name TEXT,
    registration_ip TEXT,
    role TEXT DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP,
    last_password_change TIMESTAMP,
    failed_login_attempts INTEGER DEFAULT 0,
    account_locked_until TIMESTAMP,
    status TEXT DEFAULT 'active' CHECK(status IN ('active', 'locked', 'suspended', 'inactive')),
    expiration_date TIMESTAMP,
    mfa_secret TEXT,
    backup_codes TEXT, -- JSON array of backup codes
    security_question TEXT,
    security_answer_hash TEXT,
    security_level INTEGER DEFAULT 1 CHECK(security_level BETWEEN 1 AND 5),
    metadata TEXT, -- JSON metadata
    INDEX idx_username (username),
    INDEX idx_email (email),
    INDEX idx_status (status)
);

-- Tabel sesi dengan enhanced tracking
CREATE TABLE sessions (
    session_id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    ip_address TEXT NOT NULL,
    user_agent TEXT,
    device_fingerprint TEXT,
    login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    is_active INTEGER DEFAULT 1 CHECK(is_active IN (0, 1)),
    invalidated_at TIMESTAMP,
    invalidated_reason TEXT,
    geo_location TEXT, -- JSON dengan lokasi geografis
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id),
    INDEX idx_ip_address (ip_address),
    INDEX idx_expires_at (expires_at)
);

-- Tabel log keamanan komprehensif
CREATE TABLE security_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action_type TEXT NOT NULL CHECK(action_type IN (
        'LOGIN_SUCCESS', 'LOGIN_FAILED', 'LOGOUT', 'PASSWORD_CHANGE',
        'PROFILE_UPDATE', 'SESSION_CREATED', 'SESSION_DESTROYED',
        'SECURITY_SETTING_CHANGED', 'ADMIN_ACTION', 'API_CALL',
        'SUSPICIOUS_ACTIVITY', 'THREAT_DETECTED', 'RATE_LIMIT_HIT'
    )),
    severity INTEGER DEFAULT 1 CHECK(severity BETWEEN 1 AND 10),
    ip_address TEXT,
    user_agent TEXT,
    resource_path TEXT,
    request_method TEXT,
    parameters TEXT, -- JSON parameters
    result TEXT CHECK(result IN ('SUCCESS', 'FAILURE', 'BLOCKED', 'REDIRECTED')),
    details TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL,
    INDEX idx_action_type (action_type),
    INDEX idx_severity (severity),
    INDEX idx_timestamp (timestamp),
    INDEX idx_user_id (user_id)
);

-- Tabel blacklist IP dengan expiry
CREATE TABLE ip_blacklist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT UNIQUE NOT NULL,
    subnet_mask TEXT,
    reason TEXT NOT NULL,
    severity INTEGER DEFAULT 5 CHECK(severity BETWEEN 1 AND 10),
    created_by INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    is_active INTEGER DEFAULT 1 CHECK(is_active IN (0, 1)),
    notes TEXT,
    FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE SET NULL,
    INDEX idx_ip_address (ip_address),
    INDEX idx_expires_at (expires_at),
    INDEX idx_is_active (is_active)
);

-- Tabel failed login attempts dengan pattern detection
CREATE TABLE failed_logins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL,
    username TEXT,
    attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_agent TEXT,
    password_attempt TEXT, -- Hashed untuk pattern analysis
    country_code TEXT,
    is_proxy INTEGER DEFAULT 0 CHECK(is_proxy IN (0, 1)),
    INDEX idx_ip_address (ip_address),
    INDEX idx_attempt_time (attempt_time),
    INDEX idx_username (username)
);

-- Tabel whitelist IP untuk trusted sources
CREATE TABLE ip_whitelist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT UNIQUE NOT NULL,
    description TEXT,
    created_by INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    is_active INTEGER DEFAULT 1 CHECK(is_active IN (0, 1)),
    FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE SET NULL,
    INDEX idx_ip_address (ip_address)
);

-- Tabel rate limiting
CREATE TABLE rate_limits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    identifier TEXT NOT NULL, -- IP atau user_id
    request_type TEXT NOT NULL,
    request_count INTEGER DEFAULT 1,
    window_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    window_end TIMESTAMP,
    is_blocked INTEGER DEFAULT 0 CHECK(is_blocked IN (0, 1)),
    block_until TIMESTAMP,
    INDEX idx_identifier (identifier),
    INDEX idx_request_type (request_type),
    INDEX idx_window_start (window_start)
);

-- Tabel threat intelligence feeds
CREATE TABLE threat_intelligence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_type TEXT NOT NULL CHECK(threat_type IN (
        'IP', 'USER_AGENT', 'ASN', 'COUNTRY', 'PATTERN', 'BEHAVIOR'
    )),
    threat_value TEXT NOT NULL,
    source TEXT NOT NULL,
    severity INTEGER DEFAULT 5 CHECK(severity BETWEEN 1 AND 10),
    confidence REAL DEFAULT 1.0 CHECK(confidence BETWEEN 0.0 AND 1.0),
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP,
    expires_at TIMESTAMP,
    metadata TEXT, -- JSON metadata
    UNIQUE(threat_type, threat_value),
    INDEX idx_threat_type (threat_type),
    INDEX idx_severity (severity),
    INDEX idx_expires_at (expires_at)
);

-- Tabel behavioral profiles
CREATE TABLE behavioral_profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER UNIQUE NOT NULL,
    login_pattern TEXT, -- JSON pola login
    activity_pattern TEXT, -- JSON pola aktivitas
    device_whitelist TEXT, -- JSON daftar device
    location_whitelist TEXT, -- JSON lokasi yang diizinkan
    typical_request_times TEXT, -- JSON waktu khas request
    risk_score REAL DEFAULT 0.0,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

-- Tabel API keys untuk integrasi
CREATE TABLE api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    key_hash TEXT UNIQUE NOT NULL,
    key_name TEXT NOT NULL,
    permissions TEXT, -- JSON permissions
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    last_used TIMESTAMP,
    is_active INTEGER DEFAULT 1 CHECK(is_active IN (0, 1)),
    rate_limit_per_minute INTEGER DEFAULT 60,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id),
    INDEX idx_key_hash (key_hash)
);

-- Tabel backup dan recovery
CREATE TABLE backup_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    code_hash TEXT NOT NULL,
    used INTEGER DEFAULT 0 CHECK(used IN (0, 1)),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    used_at TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id),
    INDEX idx_code_hash (code_hash)
);

-- Tabel audit configuration
CREATE TABLE audit_config (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    config_key TEXT UNIQUE NOT NULL,
    config_value TEXT NOT NULL,
    description TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_by INTEGER,
    FOREIGN KEY (updated_by) REFERENCES users (id) ON DELETE SET NULL
);

-- Insert default audit configurations
INSERT INTO audit_config (config_key, config_value, description) VALUES
    ('retention_days', '365', 'Berapa hari log disimpan'),
    ('real_time_alert', 'true', 'Enable real-time alerts'),
    ('alert_email', 'admin@indictivecore.com', 'Email untuk alerts'),
    ('minimum_severity_log', '3', 'Minimum severity untuk logging'),
    ('enable_behavioral_analysis', 'true', 'Enable behavioral analysis');

-- Tabel geolocation cache
CREATE TABLE geo_cache (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT UNIQUE NOT NULL,
    country_code TEXT,
    country_name TEXT,
    region_name TEXT,
    city_name TEXT,
    isp TEXT,
    is_proxy INTEGER DEFAULT 0,
    is_tor INTEGER DEFAULT 0,
    is_vpn INTEGER DEFAULT 0,
    latitude REAL,
    longitude REAL,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_ip_address (ip_address),
    INDEX idx_country_code (country_code)
);

-- Trigger untuk automatic cleanup
CREATE TRIGGER cleanup_old_sessions
AFTER INSERT ON sessions
BEGIN
    DELETE FROM sessions 
    WHERE expires_at < datetime('now') 
    AND is_active = 1;
END;

CREATE TRIGGER update_user_last_login
AFTER INSERT ON security_logs
WHEN NEW.action_type = 'LOGIN_SUCCESS'
BEGIN
    UPDATE users 
    SET last_login = NEW.timestamp,
        failed_login_attempts = 0
    WHERE id = NEW.user_id;
END;

CREATE TRIGGER increment_failed_attempts
AFTER INSERT ON security_logs
WHEN NEW.action_type = 'LOGIN_FAILED' AND NEW.user_id IS NOT NULL
BEGIN
    UPDATE users 
    SET failed_login_attempts = failed_login_attempts + 1
    WHERE id = NEW.user_id;
    
    -- Lock account setelah 5 failed attempts
    UPDATE users 
    SET account_locked_until = datetime('now', '+30 minutes'),
        status = 'locked'
    WHERE id = NEW.user_id 
    AND failed_login_attempts >= 5;
END;

-- Insert default admin user (password: Admin@123!)
INSERT OR IGNORE INTO users (
    username, 
    password_hash, 
    salt, 
    email, 
    role, 
    security_level,
    expiration_date
) VALUES (
    'admin',
    -- bcrypt hash untuk 'Admin@123!'
    '$2b$12$LQv3c1yqBWVHxkd5x1eB.uWjfO8lJjC7c8nW8jZJQrK5vY1zX2c3d4',
    '$2b$12$LQv3c1yqBWVHxkd5x1eB.u',
    'admin@indictivecore.com',
    'admin',
    5,
    datetime('now', '+365 days')
);

-- Insert sample threat intelligence
INSERT OR IGNORE INTO threat_intelligence 
(threat_type, threat_value, source, severity, confidence) VALUES
('IP', '192.168.1.100', 'internal', 8, 0.9),
('USER_AGENT', 'Mozilla/5.0 zgrab/0.x', 'external', 7, 0.85),
('PATTERN', 'sql_injection_pattern', 'external', 9, 0.95),
('COUNTRY', 'KP', 'external', 6, 0.8), -- North Korea
('ASN', 'AS12345', 'external', 5, 0.7);

-- Insert default IP whitelist
INSERT OR IGNORE INTO ip_whitelist (ip_address, description) VALUES
('127.0.0.1', 'Localhost'),
('::1', 'IPv6 Localhost');

-- Buat view untuk security dashboard
CREATE VIEW security_dashboard AS
SELECT 
    date(timestamp) as log_date,
    action_type,
    severity,
    COUNT(*) as event_count,
    GROUP_CONCAT(DISTINCT ip_address) as affected_ips
FROM security_logs
WHERE timestamp > datetime('now', '-7 days')
GROUP BY date(timestamp), action_type, severity;

-- View untuk user activity
CREATE VIEW user_activity_summary AS
SELECT 
    u.username,
    u.role,
    COUNT(DISTINCT s.session_id) as active_sessions,
    COUNT(DISTINCT CASE WHEN sl.action_type = 'LOGIN_SUCCESS' THEN sl.id END) as successful_logins,
    COUNT(DISTINCT CASE WHEN sl.action_type = 'LOGIN_FAILED' THEN sl.id END) as failed_logins,
    MAX(sl.timestamp) as last_activity
FROM users u
LEFT JOIN sessions s ON u.id = s.user_id AND s.is_active = 1
LEFT JOIN security_logs sl ON u.id = sl.user_id AND sl.timestamp > datetime('now', '-1 day')
GROUP BY u.id, u.username, u.role;

COMMIT;
PRAGMA foreign_keys = ON;
