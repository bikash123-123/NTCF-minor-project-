CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE threat_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_ip VARCHAR(45),
    destination_ip VARCHAR(45),
    threat_type VARCHAR(100),
    confidence FLOAT,
    severity VARCHAR(20),
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE detection_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_event_id INTEGER,
    prediction INTEGER,
    confidence FLOAT,
    label VARCHAR(30),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY(threat_event_id)
    REFERENCES threat_events(id)
);

CREATE TABLE firewall_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_event_id INTEGER,
    action VARCHAR(50),
    status VARCHAR(30),
    reason TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY(threat_event_id)
    REFERENCES threat_events(id)
);