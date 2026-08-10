"""Dashboard view + live status endpoints."""
from __future__ import annotations

from flask import Blueprint, jsonify, render_template, session

from database import db
from services.temporary_block_manager import temporary_block_manager as temp_blocks
from services.dns_manager import DNSUnavailableError, dns
from services.ufw_manager import UFWError, ufw
from routes.auth import login_required

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/")
@dashboard_bp.route("/dashboard")
@login_required
def index():
    return render_template("dashboard.html", page="dashboard", title="Dashboard")


@dashboard_bp.get("/api/dashboard/stats")
@login_required
def stats():
    # Lazy expiry so the dashboard reflects reality immediately.
    temp_blocks.check_expired()

    ufw_state = {"enabled": False, "status": "unavailable",
                 "default_incoming": "-", "default_outgoing": "-", "error": ""}
    live_rule_count = None
    try:
        ufw_state = {**ufw.status(), "error": ""}
        # Live count reflects rules added from the command line too; reconcile
        # the DB registry at the same time so it stays truthful.
        live_rules = ufw.rules()
        ufw.sync_registry(live_rules)
        live_rule_count = len(live_rules)
    except UFWError as exc:
        ufw_state["error"] = str(exc)

    try:
        dns_state = dns.service_status()
    except DNSUnavailableError:
        dns_state = "unavailable"

    data = {
        "counts": {
            "blocked_domains": db.count_domains_by_status("blocked"),
            "allowed_domains": db.count_domains_by_status("allowed"),
            "blacklist": db.count_list("blacklist"),
            "whitelist": db.count_list("whitelist"),
            # Prefer the live UFW ruleset; fall back to the app registry when
            # UFW is unavailable on this host.
            "ufw_rules": live_rule_count if live_rule_count is not None
                         else db.count_firewall_rules(),
            "temporary_active": db.count_temporary_active(),
            "logs": db.count_logs(),
        },
        "ufw": ufw_state,
        "dns": dns_state,
        "activity": db.get_recent_logs(12),
        "username": session.get("username", "admin"),
    }
    return jsonify(data)


@dashboard_bp.get("/api/dashboard/activity")
@login_required
def activity():
    return jsonify({"activity": db.get_recent_logs(25)})
