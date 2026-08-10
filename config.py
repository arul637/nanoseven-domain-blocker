"""Central configuration for Nano Blocker.

Everything the application needs to know about its environment lives here so
that no module hard-codes paths, tags or timeouts.  Values can be overridden
through environment variables (useful for the Linux lab deployment).
"""
from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent


class Config:
    """Runtime configuration for the Flask application and its services."""

    # ---- Flask -----------------------------------------------------------------
    SECRET_KEY = os.environ.get("IDB_SECRET_KEY", "nano-blocker-dev-key-change-me")
    DEBUG = os.environ.get("IDB_DEBUG", "0") == "1"
    HOST = os.environ.get("IDB_HOST", "127.0.0.1")
    PORT = int(os.environ.get("IDB_PORT", "5000"))
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"

    # ---- Paths ------------------------------------------------------------------
    DATA_DIR = os.environ.get("IDB_DATA_DIR", str(BASE_DIR / "data"))
    DB_PATH = os.environ.get("IDB_DB_PATH", str(BASE_DIR / "data" / "nano_blocker.db"))
    LOG_DIR = os.environ.get("IDB_LOG_DIR", str(BASE_DIR / "logs"))
    LOG_FILE = os.environ.get("IDB_LOG_FILE", str(BASE_DIR / "logs" / "application.log"))

    # ---- dnsmasq ----------------------------------------------------------------
    # The ONLY file this application writes to.  It never edits the user's main
    # dnsmasq configuration.
    DNSMASQ_CONF = os.environ.get(
        "IDB_DNSMASQ_CONF", "/etc/dnsmasq.d/intelligent-domain-blocker.conf"
    )
    DNS_SERVICE = os.environ.get("IDB_DNS_SERVICE", "dnsmasq")
    # Poisoned answer returned for blocked domains (0.0.0.0 or use '#' for NXDOMAIN).
    DNS_POISON_IP = os.environ.get("IDB_DNS_POISON_IP", "0.0.0.0")

    # ---- UFW ----------------------------------------------------------------------
    # Every UFW rule this application creates carries one of these comment tags.
    # The app only ever removes rules whose comment carries an IDB-* tag.
    TAG_DOMAIN = "IDB-DOMAIN-"
    TAG_TEMP = "IDB-TEMP-"
    TAG_IP = "IDB-IP-"
    TAG_USER = "IDB-USER-"

    # Commands are always run through sudo (narrowly scoped, see README).
    SUDO_PREFIX = ["sudo"]
    UFW_BIN = "ufw"
    COMMAND_TIMEOUT = 12

    # ---- Accounts ----------------------------------------------------------------
    DEFAULT_ADMIN_USER = os.environ.get("IDB_ADMIN_USER", "admin")
    DEFAULT_ADMIN_PASSWORD = os.environ.get("IDB_ADMIN_PASSWORD", "admin")

    # ---- Scheduler ----------------------------------------------------------------
    SCHEDULER_ENABLED = os.environ.get("IDB_SCHEDULER", "1") == "1"
    SCHEDULER_INTERVAL = int(os.environ.get("IDB_SCHEDULER_INTERVAL", "60"))
    RESOLVE_TIMEOUT = 5
