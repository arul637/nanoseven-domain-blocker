"""Blacklist & Whitelist view and JSON API."""
from __future__ import annotations

from flask import Blueprint, jsonify, render_template, request, session

from services import blacklist_manager, utils, whitelist_manager
from routes.auth import login_required

lists_bp = Blueprint("lists", __name__)

_TAB_TO_MANAGER = {"blacklist": blacklist_manager, "whitelist": whitelist_manager}


def _manager(tab: str):
    manager = _TAB_TO_MANAGER.get(tab)
    if not manager:
        raise utils.ValidationError("Unknown list type.")
    return manager


@lists_bp.get("/lists")
@login_required
def page():
    return render_template("lists.html", page="lists", title="Blacklist & Whitelist")


@lists_bp.get("/api/lists/<tab>")
@login_required
def list_entries(tab: str):
    search = (request.args.get("search") or "").strip()
    return jsonify({"success": True, "tab": tab,
                    "entries": _manager(tab).list_entries(search)})


@lists_bp.post("/api/lists/<tab>")
@login_required
def add_entry(tab: str):
    data = request.get_json(silent=True) or {}
    username = session.get("username", "admin")
    try:
        result = _manager(tab).add(
            value=data.get("value", ""),
            value_type=data.get("value_type", "auto"),
            reason=data.get("reason", ""),
            username=username,
        )
        label = "blacklist" if tab == "blacklist" else "whitelist"
        return jsonify({"success": True,
                        "message": f"Added to {label}: {result['value']}."})
    except utils.AppError as exc:
        return jsonify({"success": False, "message": str(exc)}), 400
    except Exception as exc:
        return jsonify({"success": False, "message": f"Operation failed: {exc}"}), 500


@lists_bp.post("/api/lists/<tab>/<int:entry_id>/toggle")
@login_required
def toggle_entry(tab: str, entry_id: int):
    username = session.get("username", "admin")
    try:
        result = _manager(tab).toggle(entry_id, username)
        state = "enabled" if result["enabled"] else "disabled"
        return jsonify({"success": True, "message": f"Entry {state}.", "enabled": result["enabled"]})
    except utils.AppError as exc:
        return jsonify({"success": False, "message": str(exc)}), 404


@lists_bp.delete("/api/lists/<tab>/<int:entry_id>")
@login_required
def remove_entry(tab: str, entry_id: int):
    username = session.get("username", "admin")
    try:
        result = _manager(tab).remove(entry_id, username)
        label = "blacklist" if tab == "blacklist" else "whitelist"
        return jsonify({"success": True,
                        "message": f"Removed from {label}: {result['value']}."})
    except utils.AppError as exc:
        return jsonify({"success": False, "message": str(exc)}), 404
