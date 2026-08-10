"""Authentication: login, logout, password change and the login_required guard."""
from __future__ import annotations

from functools import wraps

from flask import (Blueprint, jsonify, redirect, render_template, request,
                   session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

from database import db
from services.logger import log_event

auth_bp = Blueprint("auth", __name__)


def login_required(view):
    """Require a valid session. JSON API requests get a 401; pages redirect."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            if request.path.startswith("/api/") or request.is_json:
                return jsonify({"success": False, "message": "Authentication required."}), 401
            return redirect(url_for("auth.login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("dashboard.index"))

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        admin = db.get_admin(username)
        if admin and check_password_hash(admin["password_hash"], password):
            session.clear()
            session["user_id"] = admin["id"]
            session["username"] = admin["username"]
            log_event("LOGIN", username, "Administrator logged in.",
                      "SUCCESS", username, "auth")
            next_url = request.args.get("next") or url_for("dashboard.index")
            if not next_url.startswith("/"):
                next_url = url_for("dashboard.index")
            return redirect(next_url)
        log_event("LOGIN_FAILED", username, "Login attempt failed.",
                  "FAILED", username, "auth")
        return render_template(
            "login.html", error="Invalid username or password."
        ), 401

    return render_template("login.html")


@auth_bp.route("/logout")
def logout():
    username = session.get("username", "admin")
    session.clear()
    log_event("LOGOUT", username, "Administrator logged out.",
              "SUCCESS", username, "auth")
    return redirect(url_for("auth.login"))


@auth_bp.route("/api/auth/password", methods=["POST"])
@login_required
def change_password():
    data = request.get_json(silent=True) or {}
    current = data.get("current_password", "") or ""
    new = data.get("new_password", "") or ""
    if len(new) < 6:
        return jsonify({"success": False,
                        "message": "New password must be at least 6 characters."}), 400
    admin = db.get_admin(session["username"])
    if not admin or not check_password_hash(admin["password_hash"], current):
        return jsonify({"success": False, "message": "Current password is incorrect."}), 400
    db.update_admin_password(admin["username"], generate_password_hash(new))
    log_event("PASSWORD_CHANGE", admin["username"], "Password changed.",
              "SUCCESS", session["username"], "auth")
    return jsonify({"success": True, "message": "Password updated successfully."})
