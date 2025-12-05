-- Schema for CyberGrid controller (SQLite syntax)

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS user (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'operator',
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS microgridcomponent (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    component_type TEXT NOT NULL,
    firmware_version TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    criticality TEXT NOT NULL DEFAULT 'medium',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS telemetryrecord (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    component_id INTEGER NOT NULL,
    payload JSON NOT NULL,
    severity TEXT NOT NULL DEFAULT 'normal',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(component_id) REFERENCES microgridcomponent(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS securityevent (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    severity TEXT NOT NULL DEFAULT 'info',
    category TEXT NOT NULL,
    details TEXT NOT NULL,
    actor_id INTEGER,
    context JSON,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(actor_id) REFERENCES user(id)
);

CREATE TABLE IF NOT EXISTS patchstatus (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    component_id INTEGER NOT NULL,
    version TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    requested_by TEXT NOT NULL,
    notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(component_id) REFERENCES microgridcomponent(id) ON DELETE CASCADE
);

