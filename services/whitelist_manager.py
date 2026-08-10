"""Whitelist management.

The whitelist protects trusted domains from accidental blocking.  Blocking a
whitelisted value is refused (never silently overridden).
"""
from __future__ import annotations

from database import db, utcnow_iso
from services import utils
from services.logger import log_event


def _validate_value(value: str, value_type: str) -> tuple[str, str]:
    value = (value or "").strip().lower()
    if not value:
        raise utils.ValidationError("Value is required.")
    if value_type and value_type != "auto":
        if value_type not in ("domain", "ip"):
            raise utils.ValidationError("Invalid type.")
        if value_type == "domain" and not utils.is_valid_domain(value):
            raise utils.ValidationError("Invalid domain name.")
        if value_type == "ip" and not utils.is_valid_ip(value):
            raise utils.ValidationError("Invalid IP address.")
        return value, value_type
    detected = utils.classify_target(value)
    if not detected:
        raise utils.ValidationError("Value must be a valid domain or IP address.")
    return value, detected


def add(value: str, value_type: str = "auto", reason: str = "",
        username: str = "admin") -> dict:
    value, detected_type = _validate_value(value, value_type)
    reason = utils.safe_comment(reason)
    if db.find_list_entry("whitelist", value):
        raise utils.AppError("Value already exists in the whitelist.")
    entry_id = db.add_list_entry("whitelist", value, detected_type, reason, utcnow_iso())
    log_event(
        "WHITELIST_ADD", value,
        f"Added {detected_type.upper()} to whitelist{(' - ' + reason) if reason else ''}.",
        "SUCCESS", username, "whitelist",
    )
    return {"id": entry_id, "value": value, "value_type": detected_type}


def remove(entry_id: int, username: str = "admin") -> dict:
    entry = db.get_list_entry("whitelist", entry_id)
    if not entry:
        raise utils.NotFoundError("Whitelist entry not found.")
    db.delete_list_entry("whitelist", entry_id)
    log_event(
        "WHITELIST_REMOVE", entry["value"],
        "Removed from whitelist.", "SUCCESS", username, "whitelist",
    )
    return {"id": entry_id, "value": entry["value"]}


def toggle(entry_id: int, username: str = "admin") -> dict:
    entry = db.get_list_entry("whitelist", entry_id)
    if not entry:
        raise utils.NotFoundError("Whitelist entry not found.")
    db.toggle_list_entry("whitelist", entry_id)
    enabled = bool(db.get_list_entry("whitelist", entry_id)["enabled"])
    log_event(
        "WHITELIST_TOGGLE", entry["value"],
        "Whitelist entry " + ("enabled" if enabled else "disabled") + ".",
        "SUCCESS", username, "whitelist",
    )
    return {"id": entry_id, "enabled": enabled}


def is_whitelisted(value: str) -> dict | None:
    """Return the enabled whitelist entry for ``value``, if any."""
    entry = db.find_list_entry("whitelist", value)
    if entry and entry["enabled"]:
        return entry
    return None


def list_entries(search: str = "") -> list[dict]:
    return db.get_list("whitelist", search)
