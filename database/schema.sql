-- TEAM STARTER SCHEMA — NOT A FINAL SCHEMA OR FINISHED DATABASE ASSIGNMENT.
-- Review names/types/relationships with all three students before coding.
-- Extend constraints, audit history, migrations and validations yourselves.
-- Dates stored as UTC ISO-8601 text. SQLite foreign keys enabled in code.

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    full_name TEXT NOT NULL,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    department TEXT,
    role TEXT NOT NULL DEFAULT 'EMPLOYEE',
    account_status TEXT NOT NULL DEFAULT 'Active',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    last_login_at TEXT
);

CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    asset_type TEXT NOT NULL,
    ip_address TEXT,
    operating_system TEXT,
    department TEXT,
    owner_id INTEGER NOT NULL REFERENCES users(id),
    location TEXT,
    criticality TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Active'
);

CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    reporter_id INTEGER NOT NULL REFERENCES users(id),
    affected_asset_id INTEGER REFERENCES assets(id),
    assigned_analyst_id INTEGER REFERENCES users(id),
    status TEXT NOT NULL DEFAULT 'Open',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    resolution_date TEXT
);

CREATE TABLE IF NOT EXISTS investigation_notes (
    id INTEGER PRIMARY KEY,
    incident_id INTEGER NOT NULL REFERENCES incidents(id),
    analyst_id INTEGER NOT NULL REFERENCES users(id),
    content TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS threats (
    id INTEGER PRIMARY KEY,
    threat_type TEXT NOT NULL,
    threat_value TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL,
    source TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    UNIQUE(threat_type, threat_value)
);

CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    action TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL,
    related_service TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INTEGER PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    cve_identifier TEXT,
    cvss_score REAL CHECK (cvss_score IS NULL OR (cvss_score >= 0 AND cvss_score <= 10)),
    severity TEXT NOT NULL,
    affected_asset_id INTEGER NOT NULL REFERENCES assets(id),
    discovery_source TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Open',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    resolution_date TEXT
);

CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    notification_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Unread',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    read_at TEXT
);

CREATE TABLE IF NOT EXISTS playbooks (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    incident_category TEXT NOT NULL,
    severity TEXT NOT NULL,
    created_by INTEGER NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS response_actions (
    id INTEGER PRIMARY KEY,
    playbook_id INTEGER NOT NULL REFERENCES playbooks(id),
    description TEXT NOT NULL,
    step_number INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'Pending',
    assigned_user_id INTEGER REFERENCES users(id),
    completion_date TEXT,
    UNIQUE(playbook_id, step_number)
);

-- NEXT: agree on CHECK constraints for roles, severities, account statuses,
-- incident/vulnerability state machines and delete policies. State transitions
-- require explicit service-layer logic; SQL enums alone are insufficient.
