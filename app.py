"""Nano Blocker — Flask application entry point.

A dark cyber-security dashboard for domain blocking via DNS filtering
(dnsmasq) and IP-level enforcement (UFW), backed by SQLite.

Run:  python app.py   (binds to 127.0.0.1 by default)
"""
from __future__ import annotations

import os
import platform
import traceback

from flask import Flask, jsonify, render_template
from flask_wtf.csrf import CSRFError, CSRFProtect

from config import Config
from database import init_app as init_database
from services.logger import configure_logging, log_event
from services.scheduler import start_scheduler

from routes.auth import auth_bp
from routes.dashboard import dashboard_bp
from routes.domains import domains_bp
from routes.firewall import firewall_bp
from routes.lists import lists_bp
from routes.temporary import temporary_bp

app = Flask(__name__)
app.config.from_object(Config)

csrf = CSRFProtect(app)
configure_logging()
init_database()

app.register_blueprint(auth_bp)
app.register_blueprint(dashboard_bp)
app.register_blueprint(domains_bp)
app.register_blueprint(firewall_bp)
app.register_blueprint(lists_bp)
app.register_blueprint(temporary_bp)


# --------------------------------------------------------------------- globals
@app.context_processor
def inject_template_globals():
    return {
        "app_name": "Nano Blocker",
        "app_tagline": "DNS & UFW Domain Security",
        "is_linux": platform.system().lower() == "linux",
    }


# --------------------------------------------------------------------- errors
@app.errorhandler(401)
def unauthorized(_error):
    return render_template("error.html", code=401,
                           title="Unauthorized",
                           message="You need to log in to view this page."), 401


@app.errorhandler(400)
def bad_request(_error):
    if request_path_is_api():
        return jsonify({"success": False, "message": "Invalid request."}), 400
    return render_template("error.html", code=400, title="Bad Request",
                           message="The request could not be understood."), 400


@app.errorhandler(CSRFError)
def handle_csrf(_error):
    # A token from a previous session (e.g. taken from the login page) is
    # invalid after the session resets on login. Browsers using the UI always
    # read the fresh token from the page, so this mainly covers stale pages.
    if request_path_is_api():
        return jsonify({"success": False,
                        "message": "Your session token is invalid or expired. "
                                   "Reload the page and try again."}), 400
    return render_template("error.html", code=400, title="Session Expired",
                           message="Your session token is invalid or expired. "
                                   "Reload the page and sign in again."), 400


@app.errorhandler(403)
def forbidden(_error):
    return render_template("error.html", code=403, title="Forbidden",
                           message="You do not have permission to do that."), 403


@app.errorhandler(404)
def not_found(_error):
    if request_path_is_api():
        return jsonify({"success": False, "message": "Not found."}), 404
    return render_template("error.html", code=404, title="Page Not Found",
                           message="The page you are looking for does not exist."), 404


@app.errorhandler(405)
def method_not_allowed(_error):
    if request_path_is_api():
        return jsonify({"success": False, "message": "Method not allowed."}), 405
    return render_template("error.html", code=405, title="Method Not Allowed",
                           message="That request method is not supported here."), 405


@app.errorhandler(500)
def internal_error(error):
    # Log the real traceback to the file log; never show it in the UI.
    try:
        log_event("ERROR", "server", f"Unexpected error: {error}",
                  "FAILED", "system", "error")
        traceback.print_exc()
    except Exception:
        pass
    if request_path_is_api():
        return jsonify({"success": False,
                        "message": "An unexpected error occurred."}), 500
    return render_template("error.html", code=500, title="Server Error",
                           message="An unexpected error occurred. "
                                   "Check logs/application.log for details."), 500


@app.errorhandler(Exception)
def unhandled(error):
    return internal_error(error)


def request_path_is_api() -> bool:
    from flask import request
    return request.path.startswith("/api/")


# --------------------------------------------------------------------- boot
if __name__ == "__main__":
    start_scheduler(app)
    app.run(host=Config.HOST, port=Config.PORT, debug=Config.DEBUG)
else:
    # Support `flask run` / gunicorn too.
    if not os.environ.get("WERKZEUG_RUN_MAIN"):
        start_scheduler(app)
