"""Temporary domain/IP blocking with timestamp-based expiration.

Expiry is decided from the stored ``expires_at`` timestamp — never from an
in-memory timer — so temporary blocks survive application restarts.  The
scheduler (and every page load) calls :func:`check_expired` to enforce it.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from database import db, utcnow_iso
from services import utils, whitelist_manager
from services.dns_manager import DNSUnavailableError, dns
from services.domain_manager import DomainManager
from services.logger import log_event
from services.ufw_manager import UFWError, ufw

DURATION_PRESETS = {
    "5m": 5, "15m": 15, "30m": 30, "1h": 60, "6h": 360, "24h": 1440,
}


def _iso_plus_minutes(minutes: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(minutes=minutes)).isoformat(timespec="seconds")


class TemporaryBlockManager:
    """Creates and expires temporary blocks."""

    def create(self, target: str, target_type: str, duration_minutes: int,
               reason: str = "", username: str = "admin") -> dict:
        target = (target or "").strip().lower()
        if not target:
            raise utils.ValidationError("Target is required.")
        target_type = (target_type or "").strip().lower()

        if target_type not in ("domain", "ip"):
            raise utils.ValidationError("Target type must be 'domain' or 'ip'.")
        if target_type == "domain" and not utils.is_valid_domain(target):
            raise utils.ValidationError("Invalid domain name.")
        if target_type == "ip" and not utils.is_valid_ip(target):
            raise utils.ValidationError("Invalid IP address.")

        try:
            minutes = int(duration_minutes)
        except (TypeError, ValueError):
            raise utils.ValidationError("Duration must be a positive number of minutes.")
        if minutes < 1 or minutes > 60 * 24 * 30:
            raise utils.ValidationError("Duration must be between 1 minute and 30 days.")

        reason = utils.safe_comment(reason)

        if target_type == "domain" and whitelist_manager.is_whitelisted(target):
            raise utils.WhitelistConflictError(
                "This domain is currently whitelisted. "
                "Remove it from the whitelist before blocking."
            )

        created_at = utcnow_iso()
        expires_at = _iso_plus_minutes(minutes)
        block_id = db.add_temporary_block(target, target_type, reason, created_at, expires_at)

        warnings: list[str] = []
        applied = {"dns": False, "ufw": False}

        if target_type == "domain":
            try:
                dns.block_domain(target)
                dns.reload()
                applied["dns"] = True
            except DNSUnavailableError as exc:
                warnings.append(str(exc))
                log_event("ERROR", target, f"DNS temp block failed: {exc}",
                          "FAILED", username, "error")
            ips = DomainManager.resolve_ips(target)
            if not ips:
                warnings.append("Unable to resolve domain to any IP address.")
            for ip in ips:
                try:
                    ufw.add_deny_out_to(ip, ufw.tag_temp(target))
                    applied["ufw"] = True
                except UFWError as exc:
                    warnings.append(f"UFW rule for {ip}: {exc}")
        else:
            try:
                ufw.add_deny_out_to(target, ufw.tag_temp(target))
                applied["ufw"] = True
            except UFWError as exc:
                warnings.append(str(exc))

        message = f"Temporary {target_type.upper()} block created for {minutes} minute(s)."
        if warnings:
            message += " " + " ".join(warnings)
        log_event("TEMPORARY_BLOCK", target, message, "SUCCESS", username, "temporary")

        return {
            "id": block_id, "target": target, "target_type": target_type,
            "expires_at": expires_at, "applied": applied, "warnings": warnings,
        }

    def expire(self, block_id: int, username: str = "system") -> dict:
        block = db.get_temporary_block(block_id)
        if not block:
            raise utils.NotFoundError("Temporary block not found.")
        if block["status"] != "active":
            return {"success": True, "already_expired": True, "target": block["target"]}

        warnings: list[str] = []
        target = block["target"]

        # Another active block may still depend on the enforcement we are
        # about to remove — only tear down when this is the last one.
        others = [
            b for b in db.get_active_temporary_blocks()
            if b["id"] != block_id and b["target"] == target
        ]
        permanent_dns = (
            block["target_type"] == "domain"
            and not others
            and self._permanently_dns_blocked(target)
        )

        if block["target_type"] == "domain" and not others and not permanent_dns:
            try:
                if dns.unblock_domain(target):
                    dns.reload()
            except DNSUnavailableError as exc:
                warnings.append(str(exc))

        if not others:
            try:
                removed = ufw.delete_rules_for_comment(ufw.tag_temp(target))
                if removed:
                    log_event("DELETE_UFW_RULE", target,
                              f"Removed {removed} UFW rule(s) for expired temporary block.",
                              "SUCCESS", username, "firewall")
            except UFWError as exc:
                warnings.append(str(exc))

        db.expire_temporary_block(block_id, utcnow_iso())
        message = "Temporary block expired and enforcement removed."
        if warnings:
            message += " " + " ".join(warnings)
        log_event("TEMPORARY_BLOCK_EXPIRED", target, message, "SUCCESS", username, "temporary")
        return {"success": True, "target": target, "warnings": warnings}

    @staticmethod
    def _permanently_dns_blocked(domain: str) -> bool:
        row = db.get_domain_by_name(domain)
        return bool(row and row["status"] == "blocked" and row["method"] in ("dns", "both"))

    def check_expired(self) -> int:
        """Expire every active temporary block whose time has passed. Returns count."""
        count = 0
        for block in db.get_expired_temporary_blocks():
            try:
                self.expire(block["id"], "system")
                count += 1
            except Exception as exc:
                log_event("ERROR", block["target"], f"Auto-expiry failed: {exc}",
                          "FAILED", "system", "error")
        return count

    def list(self) -> list[dict]:
        self.check_expired()
        blocks = db.get_temporary_blocks()
        now = datetime.now(timezone.utc)
        for block in blocks:
            remaining_seconds = 0
            if block["status"] == "active":
                try:
                    expires = datetime.fromisoformat(block["expires_at"])
                    remaining_seconds = max(0, int((expires - now).total_seconds()))
                except ValueError:
                    remaining_seconds = 0
            block["remaining_seconds"] = remaining_seconds
        return blocks


temporary_block_manager = TemporaryBlockManager()
