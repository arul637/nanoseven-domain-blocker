"""Audit logging for Nano Blocker.

Security events are written to two places:

* the ``logs`` table (shown in the Temporary Blocks & Logs view, filterable)
* ``logs/application.log`` (technical file log for debugging)

Detailed technical errors go to the file log only; the UI only ever sees the
friendly ``message``.
"""
from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from config import Config
from database import db, utcnow_iso

# Map an event type to the filter category shown in the UI.
CATEGORY_BY_EVENT = {
    "LOGIN": "auth",
    "LOGOUT": "auth",
    "LOGIN_FAILED": "auth",
    "PASSWORD_CHANGE": "auth",
    "BLOCK_DOMAIN": "domain",
    "UNBLOCK_DOMAIN": "domain",
    "IP_SYNC": "domain",
    "DNS_RELOAD": "dns",
    "ADD_UFW_RULE": "firewall",
    "DELETE_UFW_RULE": "firewall",
    "UFW_ENABLE": "firewall",
    "UFW_DISABLE": "firewall",
    "UFW_RELOAD": "firewall",
    "UFW_RESET": "firewall",
    "BLACKLIST_ADD": "blacklist",
    "BLACKLIST_REMOVE": "blacklist",
    "BLACKLIST_TOGGLE": "blacklist",
    "WHITELIST_ADD": "whitelist",
    "WHITELIST_REMOVE": "whitelist",
    "WHITELIST_TOGGLE": "whitelist",
    "TEMPORARY_BLOCK": "temporary",
    "TEMPORARY_BLOCK_EXPIRED": "temporary",
    "ERROR": "error",
}

# UI filter values that differ from the stored category.
VALID_CATEGORIES = {
    "all", "domain", "firewall", "blacklist", "whitelist",
    "temporary", "auth", "dns", "error",
}


class AuditLogger:
    """Logs events to both the database and the application file log."""

    def __init__(self):
        self._file_logger: logging.Logger | None = None

    def configure(self, log_file: str | None = None) -> None:
        log_file = log_file or Config.LOG_FILE
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)

        handler = RotatingFileHandler(
            log_file, maxBytes=2_000_000, backupCount=3, encoding="utf-8"
        )
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
            )
        )

        logger = logging.getLogger("nano_blocker.file")
        logger.setLevel(logging.INFO)
        logger.handlers.clear()
        logger.addHandler(handler)
        logger.propagate = False
        self._file_logger = logger

    def log_event(
        self,
        event_type: str,
        target: str = "",
        message: str = "",
        status: str = "SUCCESS",
        username: str = "system",
        category: str | None = None,
    ) -> None:
        category = category or CATEGORY_BY_EVENT.get(event_type, "system")
        if category not in VALID_CATEGORIES:
            category = "system"
        try:
            db.add_log(
                username, category, event_type, target, message, status, utcnow_iso()
            )
        except Exception:  # never let logging break a security operation
            pass
        if self._file_logger:
            self._file_logger.info("%s | %s | %s | %s | %s", username, event_type, target, status, message)

    def error(self, event_type: str, target: str, message: str,
              username: str = "system") -> None:
        self.log_event(event_type, target, message, "FAILED", username, "error")

    def clear(self) -> None:
        try:
            db.clear_logs()
        except Exception:
            pass
        if self._file_logger:
            self._file_logger.info("system | LOGS_CLEARED | - | SUCCESS | Log table cleared")


audit = AuditLogger()


def log_event(event_type: str, target: str = "", message: str = "",
              status: str = "SUCCESS", username: str = "system",
              category: str | None = None) -> None:
    audit.log_event(event_type, target, message, status, username, category)


def configure_logging() -> None:
    audit.configure()
