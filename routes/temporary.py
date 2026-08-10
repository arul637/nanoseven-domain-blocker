"""Temporary Blocks & Logs view and JSON API."""
from __future__ import annotations

import csv
import io

from flask import Blueprint, Response, jsonify, render_template, request, session

from database import db
from services.temporary_block_manager import temporary_block_manager as temp_blocks
from services import utils
from services.logger import log_event
from routes.auth import login_required

temporary_bp = Blueprint("temporary", __name__)


@temporary_bp.get("/temporary")
@login_required
def page():
    return render_template("temporary.html", page="temporary",
                           title="Temporary Blocks & Logs")


@temporary_bp.get("/api/temporary")
@login_required
def list_temporary():
    return jsonify({"success": True,
                    "blocks": temp_blocks.list()})


@temporary_bp.post("/api/temporary/block")
@login_required
def create_temporary():
    data = request.get_json(silent=True) or {}
    username = session.get("username", "admin")
    try:
        result = temp_blocks.create(
            target=data.get("target", ""),
            target_type=data.get("target_type", "domain"),
            duration_minutes=data.get("duration_minutes", 0),
            reason=data.get("reason", ""),
            username=username,
        )
        return jsonify({"success": True, "message": "Temporary block created.",
                        "data": result})
    except utils.AppError as exc:
        return jsonify({"success": False, "message": str(exc)}), 400
    except Exception as exc:
        log_event("ERROR", data.get("target", ""), f"Temporary block failed: {exc}",
                  "FAILED", username, "error")
        return jsonify({"success": False, "message": "Unable to create temporary block."}), 500


@temporary_bp.post("/api/temporary/<int:block_id>/expire")
@login_required
def expire_temporary(block_id: int):
    username = session.get("username", "admin")
    try:
        result = temp_blocks.expire(block_id, username)
        if result.get("already_expired"):
            return jsonify({"success": True, "message": "Temporary block was already expired."})
        return jsonify({"success": True, "message": "Temporary block expired and removed."})
    except utils.AppError as exc:
        return jsonify({"success": False, "message": str(exc)}), 404
    except Exception as exc:
        return jsonify({"success": False, "message": f"Operation failed: {exc}"}), 500


# ---------------------------------------------------------------------- logs
@temporary_bp.get("/api/logs")
@login_required
def get_logs():
    category = request.args.get("category", "all")
    search = (request.args.get("search") or "").strip()
    try:
        limit = min(int(request.args.get("limit", 300)), 2000)
    except (TypeError, ValueError):
        limit = 300
    return jsonify({"success": True, "logs": db.get_logs(category, search, limit)})


@temporary_bp.delete("/api/logs")
@login_required
def clear_logs():
    data = request.get_json(silent=True) or {}
    username = session.get("username", "admin")
    if not data.get("confirm"):
        return jsonify({"success": False,
                        "message": "Clearing logs requires explicit confirmation."}), 400
    from services.logger import audit
    audit.clear()  # clears the DB table and records the event in the file log
    log_event("LOGS_CLEARED", "-", "Security log table cleared.",
              "SUCCESS", username, "auth")
    return jsonify({"success": True, "message": "Logs cleared."})


@temporary_bp.get("/api/logs/export")
@login_required
def export_logs():
    rows = db.get_logs("", "", 5000)
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["timestamp", "user", "category", "event", "target", "status", "message"])
    for row in rows:
        writer.writerow([
            row["created_at"], row["username"], row["category"], row["event_type"],
            row["target"], row["status"], row["message"],
        ])
    csv_text = buffer.getvalue()
    return Response(
        csv_text,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=nano-blocker-logs.csv"},
    )
