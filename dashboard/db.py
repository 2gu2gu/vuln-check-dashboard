import sqlite3

from flask import current_app, g

SCHEMA = """
CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY,
    project TEXT NOT NULL DEFAULT 'general',
    name TEXT NOT NULL,
    url TEXT NOT NULL UNIQUE,
    note TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY,
    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    module_id TEXT NOT NULL,
    params TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL,
    error TEXT NOT NULL DEFAULT '',
    started_at TEXT NOT NULL,
    finished_at TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY,
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    module_id TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    location TEXT NOT NULL DEFAULT '',
    evidence TEXT NOT NULL DEFAULT '',
    recommendation TEXT NOT NULL DEFAULT '',
    technique TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'open',
    created_at TEXT NOT NULL,
    last_seen TEXT
);
CREATE TABLE IF NOT EXISTS points (
    id INTEGER PRIMARY KEY,
    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    method TEXT NOT NULL,
    url TEXT NOT NULL,
    param TEXT NOT NULL DEFAULT '',
    place TEXT NOT NULL DEFAULT 'path',
    sample TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT '',
    module_id TEXT NOT NULL DEFAULT '',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    UNIQUE (target_id, method, url, param, place)
);
CREATE TABLE IF NOT EXISTS exchanges (
    id INTEGER PRIMARY KEY,
    run_id INTEGER REFERENCES runs(id) ON DELETE CASCADE,
    target_id INTEGER REFERENCES targets(id) ON DELETE CASCADE,
    module_id TEXT NOT NULL DEFAULT '',
    method TEXT NOT NULL,
    url TEXT NOT NULL,
    req_headers TEXT NOT NULL DEFAULT '[]',
    req_body TEXT NOT NULL DEFAULT '',
    status INTEGER NOT NULL DEFAULT 0,
    resp_headers TEXT NOT NULL DEFAULT '[]',
    resp_body TEXT NOT NULL DEFAULT '',
    size INTEGER NOT NULL DEFAULT 0,
    ms INTEGER NOT NULL DEFAULT 0,
    error TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS exchanges_run ON exchanges(run_id);
CREATE TABLE IF NOT EXISTS tool_cache (
    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    module_id TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT,
    created_at TEXT NOT NULL,
    PRIMARY KEY (target_id, module_id, key)
);
CREATE TABLE IF NOT EXISTS point_checks (
    point_id INTEGER NOT NULL REFERENCES points(id) ON DELETE CASCADE,
    module_id TEXT NOT NULL,
    verdict TEXT NOT NULL,
    evidence TEXT NOT NULL DEFAULT '',
    checked_at TEXT NOT NULL,
    PRIMARY KEY (point_id, module_id)
);
"""

STATUSES = {"open": "미확인", "confirmed": "확인됨", "fixed": "조치됨", "false_positive": "오탐"}


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


# 먼저 만든 DB 에 없던 열 — (테이블, 열, 정의)
MIGRATIONS = [
    ("findings", "last_seen", "TEXT"),
    ("findings", "exchange_id", "INTEGER"),
    ("point_checks", "exchange_id", "INTEGER"),
    ("targets", "headers", "TEXT NOT NULL DEFAULT ''"),
    ("targets", "role", "TEXT NOT NULL DEFAULT ''"),
]


def init_db():
    db = get_db()
    db.executescript(SCHEMA)
    for table, col, ddl in MIGRATIONS:
        if col not in {r["name"] for r in db.execute(f"PRAGMA table_info({table})")}:
            db.execute(f"ALTER TABLE {table} ADD COLUMN {col} {ddl}")
    db.commit()
