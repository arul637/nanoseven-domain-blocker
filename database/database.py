"""SQLite persistence layer for Nano Blocker.

Every SQL statement in this module is parameterized.  No value coming from the
application is ever concatenated into a query string.

Connections are opened per-operation and protected by a lock, which keeps the
layer safe to call from Flask request threads AND the background scheduler
thread at the same time.
"""
from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

from config import Config

# Tables that are safe to use with the generic list helpers.
_LIST_TABLES = ("blacklist", "whitelist")


def utcnow_iso() -> str:
    """Return the current time as a UTC ISO-8601 string (second precision).

    All stored timestamps use this format so simple string comparison works
    for ordering and for temporary-block expiry checks.
    """
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Database:
    """Thin, parameterized wrapper around a SQLite database."""

    def __init__(self, path: str | None = None):
        self.path = path or Config.DB_PATH
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ helpers
    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _query(self, sql: str, params: tuple = ()) -> list[dict]:
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(sql, params).fetchall()
                return [dict(row) for row in rows]
            finally:
                conn.close()

    def _execute(self, sql: str, params: tuple = ()) -> int:
        with self._lock:
            conn = self._connect()
            try:
                cur = conn.execute(sql, params)
                conn.commit()
                return cur.lastrowid or 0
            finally:
                conn.close()

    # ------------------------------------------------------------------ schema
    def init_schema(self, schema_path: str | Path | None = None) -> None:
        path = Path(schema_path) if schema_path else Path(__file__).parent / "schema.sql"
        with self._lock:
            conn = self._connect()
            try:
                conn.executescript(path.read_text(encoding="utf-8"))
                conn.commit()
            finally:
                conn.close()

    # ------------------------------------------------------------------ admins
    def get_admin(self, username: str) -> dict | None:
        rows = self._query("SELECT * FROM admins WHERE username = ?", (username,))
        return rows[0] if rows else None

    def admin_count(self) -> int:
        rows = self._query("SELECT COUNT(*) AS n FROM admins")
        return int(rows[0]["n"])

    def create_admin(self, username: str, password_hash: str, created_at: str) -> int:
        return self._execute(
            "INSERT INTO admins (username, password_hash, created_at) VALUES (?, ?, ?)",
            (username, password_hash, created_at),
        )

    def update_admin_password(self, username: str, password_hash: str) -> None:
        self._execute(
            "UPDATE admins SET password_hash = ? WHERE username = ?",
            (password_hash, username),
        )

    # ------------------------------------------------------------------ domains
    def get_domains(self, search: str = "") -> list[dict]:
        if search:
            return self._query(
                "SELECT * FROM domains WHERE domain LIKE ? "
                "ORDER BY updated_at DESC, domain ASC",
                (f"%{search}%",),
            )
        return self._query("SELECT * FROM domains ORDER BY updated_at DESC, domain ASC")

    def get_domain(self, domain_id: int) -> dict | None:
        rows = self._query("SELECT * FROM domains WHERE id = ?", (domain_id,))
        return rows[0] if rows else None

    def get_domain_by_name(self, domain: str) -> dict | None:
        rows = self._query("SELECT * FROM domains WHERE domain = ?", (domain,))
        return rows[0] if rows else None

    def insert_domain(self, domain: str, method: str, reason: str, created_at: str) -> int:
        return self._execute(
            "INSERT INTO domains (domain, status, method, reason, created_at, updated_at) "
            "VALUES (?, 'blocked', ?, ?, ?, ?)",
            (domain, method, reason, created_at, created_at),
        )

    def reblock_domain(self, domain_id: int, method: str, reason: str, at: str) -> None:
        self._execute(
            "UPDATE domains SET status = 'blocked', method = ?, reason = ?, updated_at = ? "
            "WHERE id = ?",
            (method, reason, at, domain_id),
        )

    def set_domain_allowed(self, domain_id: int, at: str) -> None:
        self._execute(
            "UPDATE domains SET status = 'allowed', updated_at = ? WHERE id = ?",
            (at, domain_id),
        )

    def delete_domain(self, domain_id: int) -> None:
        self._execute("DELETE FROM domains WHERE id = ?", (domain_id,))

    def count_domains_by_status(self, status: str) -> int:
        rows = self._query("SELECT COUNT(*) AS n FROM domains WHERE status = ?", (status,))
        return int(rows[0]["n"])

    # ------------------------------------------------------------------ domain_ips
    def get_domain_ips(self, domain_id: int) -> list[dict]:
        return self._query(
            "SELECT * FROM domain_ips WHERE domain_id = ? ORDER BY ip_address",
            (domain_id,),
        )

    def get_ip_addresses(self, domain_id: int) -> list[str]:
        rows = self._query(
            "SELECT ip_address FROM domain_ips WHERE domain_id = ?", (domain_id,)
        )
        return [row["ip_address"] for row in rows]

    def replace_domain_ips(self, domain_id: int, ips: list[str], at: str) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute("DELETE FROM domain_ips WHERE domain_id = ?", (domain_id,))
                for ip in ips:
                    conn.execute(
                        "INSERT OR IGNORE INTO domain_ips (domain_id, ip_address, last_resolved) "
                        "VALUES (?, ?, ?)",
                        (domain_id, ip, at),
                    )
                conn.commit()
            finally:
                conn.close()

    def clear_domain_ips(self, domain_id: int) -> None:
        self._execute("DELETE FROM domain_ips WHERE domain_id = ?", (domain_id,))

    # ------------------------------------------------------------------ lists
    def get_list(self, table: str, search: str = "", enabled: bool | None = None) -> list[dict]:
        if table not in _LIST_TABLES:
            raise ValueError(f"Invalid list table: {table}")
        sql = f"SELECT * FROM {table} WHERE 1 = 1"  # table is validated above
        params: list = []
        if enabled is not None:
            sql += " AND enabled = ?"
            params.append(1 if enabled else 0)
        if search:
            sql += " AND value LIKE ?"
            params.append(f"%{search}%")
        sql += " ORDER BY created_at DESC, value ASC"
        return self._query(sql, tuple(params))

    def add_list_entry(self, table: str, value: str, value_type: str, reason: str, at: str) -> int:
        if table not in _LIST_TABLES:
            raise ValueError(f"Invalid list table: {table}")
        return self._execute(
            f"INSERT INTO {table} (value, value_type, reason, enabled, created_at) "
            "VALUES (?, ?, ?, 1, ?)",
            (value, value_type, reason, at),
        )

    def get_list_entry(self, table: str, entry_id: int) -> dict | None:
        if table not in _LIST_TABLES:
            raise ValueError(f"Invalid list table: {table}")
        rows = self._query(f"SELECT * FROM {table} WHERE id = ?", (entry_id,))
        return rows[0] if rows else None

    def find_list_entry(self, table: str, value: str) -> dict | None:
        if table not in _LIST_TABLES:
            raise ValueError(f"Invalid list table: {table}")
        rows = self._query(f"SELECT * FROM {table} WHERE value = ?", (value,))
        return rows[0] if rows else None

    def toggle_list_entry(self, table: str, entry_id: int) -> None:
        if table not in _LIST_TABLES:
            raise ValueError(f"Invalid list table: {table}")
        self._execute(
            f"UPDATE {table} SET enabled = 1 - enabled WHERE id = ?", (entry_id,)
        )

    def delete_list_entry(self, table: str, entry_id: int) -> None:
        if table not in _LIST_TABLES:
            raise ValueError(f"Invalid list table: {table}")
        self._execute(f"DELETE FROM {table} WHERE id = ?", (entry_id,))

    def count_list(self, table: str) -> int:
        if table not in _LIST_TABLES:
            raise ValueError(f"Invalid list table: {table}")
        rows = self._query(f"SELECT COUNT(*) AS n FROM {table}")
        return int(rows[0]["n"])

    def count_list_enabled(self, table: str) -> int:
        if table not in _LIST_TABLES:
            raise ValueError(f"Invalid list table: {table}")
        rows = self._query(f"SELECT COUNT(*) AS n FROM {table} WHERE enabled = 1")
        return int(rows[0]["n"])

    # ------------------------------------------------------------------ firewall_rules (app registry)
    def add_firewall_rule(self, identifier: str, action: str, direction: str,
                          source: str, destination: str, port: str,
                          protocol: str, comment: str, origin: str, at: str) -> int:
        return self._execute(
            "INSERT INTO firewall_rules (rule_identifier, action, direction, source, "
            "destination, port, protocol, comment, origin, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (identifier, action, direction, source, destination, port,
             protocol, comment, origin, at),
        )

    def firewall_rule_exists(self, identifier: str) -> bool:
        rows = self._query(
            "SELECT id FROM firewall_rules WHERE rule_identifier = ?", (identifier,)
        )
        return bool(rows)

    def get_firewall_rules(self) -> list[dict]:
        return self._query("SELECT * FROM firewall_rules ORDER BY created_at DESC, id DESC")

    def delete_firewall_rule_by_identifier(self, identifier: str) -> None:
        self._execute(
            "DELETE FROM firewall_rules WHERE rule_identifier = ?", (identifier,)
        )

    def count_firewall_rules(self) -> int:
        rows = self._query("SELECT COUNT(*) AS n FROM firewall_rules")
        return int(rows[0]["n"])

    # ------------------------------------------------------------------ temporary_blocks
    def add_temporary_block(self, target: str, target_type: str, reason: str,
                            created_at: str, expires_at: str) -> int:
        return self._execute(
            "INSERT INTO temporary_blocks (target, target_type, reason, created_at, "
            "expires_at, status) VALUES (?, ?, ?, ?, ?, 'active')",
            (target, target_type, reason, created_at, expires_at),
        )

    def get_temporary_blocks(self) -> list[dict]:
        return self._query(
            "SELECT * FROM temporary_blocks ORDER BY created_at DESC, id DESC"
        )

    def get_temporary_block(self, block_id: int) -> dict | None:
        rows = self._query("SELECT * FROM temporary_blocks WHERE id = ?", (block_id,))
        return rows[0] if rows else None

    def get_active_temporary_blocks(self) -> list[dict]:
        return self._query(
            "SELECT * FROM temporary_blocks WHERE status = 'active' "
            "ORDER BY expires_at ASC, id ASC"
        )

    def get_expired_temporary_blocks(self) -> list[dict]:
        """Active temporary blocks whose expiry time has already passed."""
        now = utcnow_iso()
        return self._query(
            "SELECT * FROM temporary_blocks WHERE status = 'active' AND expires_at <= ?",
            (now,),
        )

    def expire_temporary_block(self, block_id: int, at: str) -> None:
        self._execute(
            "UPDATE temporary_blocks SET status = 'expired', expires_at = ? WHERE id = ?",
            (at, block_id),
        )

    def count_temporary_active(self) -> int:
        rows = self._query("SELECT COUNT(*) AS n FROM temporary_blocks WHERE status = 'active'")
        return int(rows[0]["n"])

    # ------------------------------------------------------------------ logs
    def add_log(self, username: str, category: str, event_type: str, target: str,
                message: str, status: str, at: str) -> int:
        return self._execute(
            "INSERT INTO logs (username, category, event_type, target, message, status, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (username, category, event_type, target, message, status, at),
        )

    def get_logs(self, category: str = "", search: str = "", limit: int = 300) -> list[dict]:
        sql = "SELECT * FROM logs WHERE 1 = 1"
        params: list = []
        if category and category != "all":
            if category == "error":
                sql += " AND category = 'error'"
            else:
                sql += " AND category = ?"
                params.append(category)
        if search:
            sql += " AND (target LIKE ? OR message LIKE ? OR event_type LIKE ?)"
            pattern = f"%{search}%"
            params.extend([pattern, pattern, pattern])
        sql += " ORDER BY created_at DESC, id DESC LIMIT ?"
        params.append(int(limit))
        return self._query(sql, tuple(params))

    def get_recent_logs(self, limit: int = 20) -> list[dict]:
        return self._query(
            "SELECT * FROM logs ORDER BY created_at DESC, id DESC LIMIT ?", (limit,)
        )

    def clear_logs(self) -> None:
        self._execute("DELETE FROM logs")

    def count_logs(self) -> int:
        rows = self._query("SELECT COUNT(*) AS n FROM logs")
        return int(rows[0]["n"])


# ---------------------------------------------------------------------------
# Application-wide singleton + bootstrap helpers
# ---------------------------------------------------------------------------
db = Database(Config.DB_PATH)


def init_app() -> None:
    """Create data dirs, the schema and the default admin account (idempotent)."""
    Path(Config.DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    Path(Config.LOG_DIR).mkdir(parents=True, exist_ok=True)
    db.init_schema()

    from werkzeug.security import generate_password_hash

    if db.admin_count() == 0:
        db.create_admin(
            Config.DEFAULT_ADMIN_USER,
            generate_password_hash(Config.DEFAULT_ADMIN_PASSWORD),
            utcnow_iso(),
        )
