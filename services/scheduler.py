"""Lightweight background scheduler.

Periodically:
    * expires temporary blocks whose stored timestamp has passed
    * re-syncs resolved IPs for blocked domains (keeps UFW in line)
    * verifies the DNS config file is present (logged only when missing)

The thread is a daemon so it never prevents the app from shutting down, and a
module-level flag plus the Werkzeug reloader guard prevent duplicate threads
when Flask restarts during development.
"""
from __future__ import annotations

import os
import threading
import time

from config import Config
from services.domain_manager import domain_manager
from services.temporary_block_manager import temporary_block_manager
from services.dns_manager import dns
from services.logger import log_event

_started = False
_start_lock = threading.Lock()


def _run(app) -> None:
    with app.app_context():
        while True:
            time.sleep(Config.SCHEDULER_INTERVAL)
            try:
                expired = temporary_block_manager.check_expired()
                if expired:
                    log_event("TEMPORARY_BLOCK_EXPIRED", "-",
                              f"Scheduler expired {expired} temporary block(s).",
                              "SUCCESS", "system", "temporary")
            except Exception as exc:  # never let the loop die
                log_event("ERROR", "scheduler", f"Expiry check failed: {exc}",
                          "FAILED", "system", "error")
            try:
                domain_manager.sync_all_domain_ips("system")
            except Exception as exc:
                log_event("ERROR", "scheduler", f"IP sync failed: {exc}",
                          "FAILED", "system", "error")
            try:
                if not os.path.exists(dns.conf_path()):
                    log_event("DNS_RELOAD", dns.conf_path(),
                              "DNS config file is missing.", "FAILED", "system", "dns")
            except Exception:
                pass


def start_scheduler(app) -> None:
    """Start the background scheduler exactly once per process."""
    if not Config.SCHEDULER_ENABLED:
        return
    # Under the Flask dev reloader the module is imported twice; only let the
    # reloaded child process own the scheduler thread.
    if app.debug and os.environ.get("WERKZEUG_RUN_MAIN") != "true":
        return
    global _started
    with _start_lock:
        if _started:
            return
        _started = True
    thread = threading.Thread(target=_run, args=(app,), daemon=True, name="idb-scheduler")
    thread.start()
