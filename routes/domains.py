"""Domain Blocking view and JSON API."""
from __future__ import annotations

from flask import Blueprint, jsonify, render_template, request, session

from services.domain_manager import domain_manager
from services import utils
from services.logger import log_event
from routes.auth import login_required

domains_bp = Blueprint("domains", __name__)


@domains_bp.get("/domains")
@login_required
def page():
    return render_template("domains.html", page="domains", title="Domain Blocking")


@domains_bp.get("/api/domains")
@login_required
def list_domains():
    search = (request.args.get("search") or "").strip()
    return jsonify({"success": True, "domains": domain_manager.list_domains(search)})


@domains_bp.get("/api/domains/<int:domain_id>")
@login_required
def domain_detail(domain_id: int):
    detail = domain_manager.detail(domain_id)
    if not detail:
        return jsonify({"success": False, "message": "Domain not found."}), 404
    return jsonify({"success": True, "domain": detail})


@domains_bp.post("/api/domains/block")
@login_required
def block_domain():
    data = request.get_json(silent=True) or {}
    username = session.get("username", "admin")
    try:
        result = domain_manager.block(
            domain=data.get("domain", ""),
            reason=data.get("reason", ""),
            method=data.get("method", "both"),
            username=username,
        )
        return jsonify({"success": True, "message": "Domain blocked successfully.",
                        "data": result})
    except utils.AppError as exc:
        log_event("BLOCK_DOMAIN", data.get("domain", ""), str(exc),
                  "FAILED", username, "error")
        return jsonify({"success": False, "message": str(exc)}), 400
    except Exception as exc:
        log_event("ERROR", data.get("domain", ""), f"Block failed: {exc}",
                  "FAILED", username, "error")
        return jsonify({"success": False, "message": "Unable to block domain."}), 500


@domains_bp.post("/api/domains/unblock")
@login_required
def unblock_domain():
    data = request.get_json(silent=True) or {}
    username = session.get("username", "admin")
    try:
        result = domain_manager.unblock(domain=data.get("domain", ""), username=username)
        return jsonify({"success": True, "message": "Domain unblocked successfully.",
                        "data": result})
    except utils.AppError as exc:
        log_event("UNBLOCK_DOMAIN", data.get("domain", ""), str(exc),
                  "FAILED", username, "error")
        return jsonify({"success": False, "message": str(exc)}), 400
    except Exception as exc:
        log_event("ERROR", data.get("domain", ""), f"Unblock failed: {exc}",
                  "FAILED", username, "error")
        return jsonify({"success": False, "message": "Unable to unblock domain."}), 500


@domains_bp.post("/api/domains/refresh")
@login_required
def refresh_domain():
    data = request.get_json(silent=True) or {}
    username = session.get("username", "admin")
    try:
        domain_id = int(data.get("id", 0))
    except (TypeError, ValueError):
        return jsonify({"success": False, "message": "Invalid domain id."}), 400
    try:
        result = domain_manager.refresh_ips(domain_id, username)
        return jsonify({"success": True, "message": "Domain IPs refreshed.",
                        "data": result})
    except utils.AppError as exc:
        return jsonify({"success": False, "message": str(exc)}), 404
    except Exception as exc:
        log_event("ERROR", data.get("domain", ""), f"IP refresh failed: {exc}",
                  "FAILED", username, "error")
        return jsonify({"success": False, "message": "Unable to refresh domain IPs."}), 500
