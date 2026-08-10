"""UFW Firewall view and JSON API (controlled, safe operations only)."""
from __future__ import annotations

from flask import Blueprint, jsonify, render_template, request, session

from database import db, utcnow_iso
from services import utils
from services.logger import log_event
from services.ufw_manager import UFWError, ufw
from routes.auth import login_required

firewall_bp = Blueprint("firewall", __name__)


@firewall_bp.get("/firewall")
@login_required
def page():
    return render_template("firewall.html", page="firewall", title="UFW Firewall")


@firewall_bp.get("/api/ufw/status")
@login_required
def ufw_status():
    try:
        status = ufw.status()
        return jsonify({"success": True, "status": status, "error": ""})
    except UFWError as exc:
        return jsonify({"success": True, "status": {
            "status": "unavailable", "enabled": False,
            "default_incoming": "-", "default_outgoing": "-",
        }, "error": str(exc)})


@firewall_bp.get("/api/ufw/rules")
@login_required
def ufw_rules():
    try:
        rules = ufw.rules()
        # Reconcile the DB registry with the live ruleset so rules added or
        # removed from the command line stay in sync with the dashboard count.
        ufw.sync_registry(rules)
        return jsonify({"success": True, "rules": rules})
    except UFWError as exc:
        return jsonify({"success": False, "message": str(exc)}), 500


@firewall_bp.post("/api/ufw/rules")
@login_required
def add_rule():
    data = request.get_json(silent=True) or {}
    username = session.get("username", "admin")

    action = (data.get("action") or "").strip().lower()
    direction = (data.get("direction") or "").strip().lower()
    source = (data.get("source") or "").strip()
    destination = (data.get("destination") or "").strip()
    port = (data.get("port") or "").strip()
    protocol = (data.get("protocol") or "any").strip().lower()
    comment = utils.safe_comment(data.get("comment", ""))

    if not utils.is_valid_action(action):
        return jsonify({"success": False, "message": "Action must be allow, deny or reject."}), 400
    if not utils.is_valid_direction(direction):
        return jsonify({"success": False, "message": "Direction must be incoming or outgoing."}), 400
    if source and not utils.is_valid_ip(source):
        return jsonify({"success": False, "message": "Invalid source IP address."}), 400
    if destination and not utils.is_valid_ip(destination):
        return jsonify({"success": False, "message": "Invalid destination IP address."}), 400
    if port and not utils.is_valid_port(port):
        return jsonify({"success": False, "message": "Invalid port (1-65535)."}), 400
    if not utils.is_valid_protocol(protocol):
        return jsonify({"success": False, "message": "Protocol must be tcp, udp or any."}), 400

    # Tag every app-created rule so we can identify it later.
    identifier = ufw.tag_user()
    final_comment = f"{comment} | {identifier}".strip(" |") if comment else identifier

    try:
        ufw.add_rule(action, direction, source, destination, port, protocol, final_comment)
    except UFWError as exc:
        log_event("ADD_UFW_RULE", destination or source or "-",
                  f"Failed to add rule: {exc}", "FAILED", username, "firewall")
        return jsonify({"success": False, "message": str(exc)}), 500

    db.add_firewall_rule(
        identifier, action, direction, source, destination, port, protocol,
        comment or identifier, "app", utcnow_iso(),
    )
    log_event("ADD_UFW_RULE", destination or source or "-",
              f"{action.upper()} {direction} rule added.", "SUCCESS", username, "firewall")
    return jsonify({"success": True, "message": "UFW rule added successfully."})


@firewall_bp.delete("/api/ufw/rules/<int:rule_number>")
@login_required
def delete_rule(rule_number: int):
    data = request.get_json(silent=True) or {}
    username = session.get("username", "admin")
    force = bool(data.get("force"))
    try:
        match = ufw.delete_rule(rule_number, force_manual=force)
        # Drop the DB registry entry for any app-created rule we just removed.
        tag = ufw.extract_identifier(match.get("comment", ""))
        if tag:
            db.delete_firewall_rule_by_identifier(tag)
        log_event("DELETE_UFW_RULE", match.get("to") or "-",
                  f"Deleted UFW rule #{rule_number}.", "SUCCESS", username, "firewall")
        return jsonify({"success": True, "message": "UFW rule deleted."})
    except UFWError as exc:
        return jsonify({"success": False, "message": str(exc)}), 400


@firewall_bp.post("/api/ufw/enable")
@login_required
def ufw_enable():
    username = session.get("username", "admin")
    try:
        status = ufw.enable()
        log_event("UFW_ENABLE", "-", "UFW enabled.", "SUCCESS", username, "firewall")
        return jsonify({"success": True, "message": "UFW enabled.", "status": status})
    except UFWError as exc:
        return jsonify({"success": False, "message": str(exc)}), 500


@firewall_bp.post("/api/ufw/disable")
@login_required
def ufw_disable():
    data = request.get_json(silent=True) or {}
    username = session.get("username", "admin")
    if not data.get("confirm"):
        return jsonify({"success": False,
                        "message": "Disabling UFW requires explicit confirmation."}), 400
    try:
        status = ufw.disable()
        log_event("UFW_DISABLE", "-", "UFW disabled.", "SUCCESS", username, "firewall")
        return jsonify({"success": True, "message": "UFW disabled.", "status": status})
    except UFWError as exc:
        return jsonify({"success": False, "message": str(exc)}), 500


@firewall_bp.post("/api/ufw/reload")
@login_required
def ufw_reload():
    username = session.get("username", "admin")
    try:
        ufw.reload()
        log_event("UFW_RELOAD", "-", "UFW reloaded.", "SUCCESS", username, "firewall")
        return jsonify({"success": True, "message": "UFW reloaded."})
    except UFWError as exc:
        return jsonify({"success": False, "message": str(exc)}), 500


@firewall_bp.post("/api/ufw/reset")
@login_required
def ufw_reset():
    data = request.get_json(silent=True) or {}
    username = session.get("username", "admin")
    if not data.get("confirm"):
        return jsonify({"success": False,
                        "message": "Resetting UFW requires explicit confirmation."}), 400
    try:
        ufw.reset()
        log_event("UFW_RESET", "-", "UFW ruleset reset (explicitly confirmed).",
                  "SUCCESS", username, "firewall")
        return jsonify({"success": True, "message": "UFW reset complete."})
    except UFWError as exc:
        return jsonify({"success": False, "message": str(exc)}), 500
