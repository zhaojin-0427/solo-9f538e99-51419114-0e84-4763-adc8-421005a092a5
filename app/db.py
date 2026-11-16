"""SQLite access and the immutable file-registry schema."""

from __future__ import annotations

import os
import sqlite3
import threading

from flask import current_app, g

SCHEMA = r"""
CREATE TABLE IF NOT EXISTS files (
    id                TEXT PRIMARY KEY,
    kind              TEXT NOT NULL CHECK (kind IN ('raw', 'cleaned', 'summary')),
    original_filename TEXT NOT NULL,
    stored_name       TEXT NOT NULL UNIQUE,
    sha256            TEXT NOT NULL,
    size_bytes        INTEGER NOT NULL CHECK (size_bytes > 0),
    parent_id         TEXT REFERENCES files(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    created_at        TEXT NOT NULL,
    revoked_at        TEXT,
    revoked_by        TEXT,
    CHECK (
        (kind = 'raw' AND parent_id IS NULL)
        OR (kind IN ('cleaned', 'summary') AND parent_id IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS idx_files_parent_id ON files(parent_id);
CREATE INDEX IF NOT EXISTS idx_files_created_at ON files(created_at);

-- Append-only audit trail. Each register/revoke event is written in the same
-- transaction as the state change, so the AUTOINCREMENT order is a true
-- serialization order across processes. Tests and operators use this to prove
-- that no file was ever registered against an already-revoked parent.
CREATE TABLE IF NOT EXISTS events (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id TEXT NOT NULL,
    action  TEXT NOT NULL CHECK (action IN ('register', 'revoke')),
    at      TEXT NOT NULL,
    detail  TEXT
);

CREATE TRIGGER IF NOT EXISTS events_are_immutable
BEFORE UPDATE ON events
BEGIN
    SELECT RAISE(ABORT, 'audit events are append-only');
END;

CREATE TRIGGER IF NOT EXISTS events_cannot_be_deleted
BEFORE DELETE ON events
BEGIN
    SELECT RAISE(ABORT, 'audit events are append-only');
END;

-- A registered row may only change once: the transition from live to revoked.
-- Identity fields, the parent edge, and the original timestamp can never be
-- edited; a revocation can never be undone.
CREATE TRIGGER IF NOT EXISTS files_only_revoke_once
BEFORE UPDATE ON files
WHEN
       NEW.id                IS NOT OLD.id
    OR NEW.kind              IS NOT OLD.kind
    OR NEW.original_filename IS NOT OLD.original_filename
    OR NEW.stored_name       IS NOT OLD.stored_name
    OR NEW.sha256            IS NOT OLD.sha256
    OR NEW.size_bytes        IS NOT OLD.size_bytes
    OR NEW.parent_id         IS NOT OLD.parent_id
    OR NEW.created_at        IS NOT OLD.created_at
    OR OLD.revoked_at IS NOT NULL
    OR NEW.revoked_at IS NULL
BEGIN
    SELECT RAISE(ABORT, 'file identity, dependency and history are immutable');
END;

CREATE TRIGGER IF NOT EXISTS files_cannot_be_deleted
BEFORE DELETE ON files
BEGIN
    SELECT RAISE(ABORT, 'registered files cannot be deleted');
END;
"""


def connect(path: str) -> sqlite3.Connection:
    """Open a connection with settings suitable for serialized writers."""
    conn = sqlite3.connect(path, timeout=30.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 15000")
    conn.execute("PRAGMA synchronous = FULL")
    return conn


def init_database(database_path: str, storage_dir: str) -> None:
    """Create parent directories, data file and schema. Safe to call repeatedly.

    The expensive part (WAL setup + DDL) runs once per process; repeated calls
    are cheap. DDL is written to be idempotent, and a concurrent process may
    legitimately hold the database while we run, so a busy journal-mode switch
    is not fatal (WAL, once enabled, persists in the database file).
    """
    key = (os.path.abspath(database_path), os.path.abspath(storage_dir))
    with _init_lock:
        if key in _initialized:
            return
        target = os.path.dirname(database_path) if database_path else ""
        os.makedirs(target or ".", exist_ok=True)
        os.makedirs(storage_dir, exist_ok=True)
        os.makedirs(os.path.join(storage_dir, ".tmp"), exist_ok=True)
        os.makedirs(os.path.join(storage_dir, "files"), exist_ok=True)

        conn = connect(database_path)
        try:
            try:
                conn.execute("PRAGMA journal_mode = WAL")
            except sqlite3.OperationalError:
                pass
            conn.executescript(SCHEMA)
        finally:
            conn.close()
        _initialized.add(key)


_initialized: set[tuple[str, str]] = set()
_init_lock = threading.RLock()


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = connect(current_app.config["DATABASE_PATH"])
    return g.db


def close_db(_exc: BaseException | None = None) -> None:
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def get_file(conn: sqlite3.Connection, file_id: str) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
