"""Domain blocking orchestration.

Blocking flow (per the spec):
    validate domain -> check whitelist -> persist -> configure DNS filtering
    -> resolve IPv4/IPv6 -> store IPs -> apply UFW rules (if enabled)
    -> log -> report.

Unblocking reverses every step and only ever removes rules this app created
(identified by the ``IDB-DOMAIN-*`` comment tag).  The UFW ruleset is never
flushed.
"""
from __future__ import annotations

import socket
from datetime import datetime, timezone

from database import db, utcnow_iso
from services import utils, whitelist_manager
from services.dns_manager import DNSUnavailableError, dns
from services.logger import log_event
from services.ufw_manager import UFWError, ufw

VALID_METHODS = ("dns", "ufw", "both")


class DomainManager:
    """Coordinates DNS + UFW + database for domain-level blocking."""

    # ------------------------------------------------------------ resolution
    @staticmethod
    def resolve_ips(domain: str) -> list[str]:
        """Resolve a domain to a de-duplicated list of IPv4/IPv6 addresses."""
        ips: list[str] = []
        try:
            infos = socket.getaddrinfo(domain, None)
        except (socket.gaierror, OSError):
            return []
        for info in infos:
            family, _, _, _, sockaddr = info
            ip = sockaddr[0]
            if "%" in ip:
                ip = ip.split("%")[0]
            if family == socket.AF_INET and utils.is_valid_ipv4(ip):
                ips.append(ip)
            elif family == socket.AF_INET6 and utils.is_valid_ipv6(ip):
                ips.append(ip)
        return list(dict.fromkeys(ips))

    @staticmethod
    def _normalize_method(method: str) -> str:
        method = (method or "both").strip().lower()
        if method not in VALID_METHODS:
            raise utils.ValidationError("Invalid block method.")
        return method

    # ------------------------------------------------------------ block
    def block(self, domain: str, reason: str = "", method: str = "both",
              username: str = "admin") -> dict:
        domain = utils.normalize_domain(domain)
        if not domain or not utils.is_valid_domain(domain):
            raise utils.ValidationError(
                "Invalid domain name. Use a plain hostname such as example.com."
            )
        reason = utils.safe_comment(reason)
        method = self._normalize_method(method)

        existing = db.get_domain_by_name(domain)
        if existing and existing["status"] == "blocked":
            raise utils.AlreadyBlockedError("Domain is already blocked.")

        if whitelist_manager.is_whitelisted(domain):
            raise utils.WhitelistConflictError(
                "This domain is currently whitelisted. "
                "Remove it from the whitelist before blocking."
            )

        now = utcnow_iso()
        if existing:
            domain_id = existing["id"]
            db.reblock_domain(domain_id, method, reason, now)
        else:
            domain_id = db.insert_domain(domain, method, reason, now)

        warnings: list[str] = []
        applied = {"dns": False, "ufw": False}

        # 1. DNS filtering
        if method in ("dns", "both"):
            try:
                dns.block_domain(domain)
                dns.reload()
                applied["dns"] = True
                log_event("DNS_RELOAD", domain, "DNS block configured + dnsmasq reloaded.",
                          "SUCCESS", username, "dns")
            except DNSUnavailableError as exc:
                warnings.append(str(exc))
                log_event("ERROR", domain, f"DNS filtering unavailable: {exc}",
                          "FAILED", username, "error")

        # 2. Resolve + UFW rules
        ips: list[str] = []
        if method in ("ufw", "both"):
            ips = self.resolve_ips(domain)
            db.replace_domain_ips(domain_id, ips, now)
            if not ips:
                warnings.append("Unable to resolve domain to any IP address.")
                log_event("ERROR", domain, "Domain did not resolve to any IP address.",
                          "FAILED", username, "error")
            tag = ufw.tag_domain(domain)
            for ip in ips:
                try:
                    ufw.add_deny_out_to(ip, tag)
                    applied["ufw"] = True
                except UFWError as exc:
                    warnings.append(f"UFW rule for {ip}: {exc}")
                    log_event("ERROR", domain, f"UFW rule failed for {ip}: {exc}",
                              "FAILED", username, "error")
        else:
            # DNS-only: still refresh stored IPs for display/detail.
            ips = self.resolve_ips(domain)
            db.replace_domain_ips(domain_id, ips, now)

        message = f"Domain blocked via {method.upper()}."
        if warnings:
            message += " " + " ".join(warnings)
        log_event("BLOCK_DOMAIN", domain, message, "SUCCESS", username, "domain")

        return {
            "success": True,
            "domain": domain,
            "method": method,
            "ips": ips,
            "applied": applied,
            "warnings": warnings,
        }

    # ------------------------------------------------------------ unblock
    def unblock(self, domain: str, username: str = "admin") -> dict:
        domain = utils.normalize_domain(domain)
        if not domain:
            raise utils.ValidationError("Invalid domain name.")
        existing = db.get_domain_by_name(domain)

        # Discover what is actually enforced on the system right now.  This is
        # what makes unblocking survive a cleared database: the block may exist
        # only as a dnsmasq entry / IDB-tagged UFW rule left by a previous run.
        dns_blocked = self._system_dns_blocks(domain)
        ufw_tags = self._system_ufw_tags(domain)

        if not existing:
            if not dns_blocked and not ufw_tags:
                raise utils.NotBlockedError("Domain is not currently blocked.")
        elif existing["status"] != "blocked" and not dns_blocked and not ufw_tags:
            raise utils.NotBlockedError("Domain is not currently blocked.")

        warnings: list[str] = []

        # 1. DNS entries (skip any an active temporary block still relies on).
        if dns_blocked:
            try:
                changed = False
                for blocked in dns_blocked:
                    if not self._has_active_temp_dns(blocked) and dns.unblock_domain(blocked):
                        changed = True
                if changed:
                    dns.reload()
                    log_event("DNS_RELOAD", domain,
                              "DNS block removed + dnsmasq reloaded.",
                              "SUCCESS", username, "dns")
            except DNSUnavailableError as exc:
                warnings.append(str(exc))
                log_event("ERROR", domain, f"DNS unblock failed: {exc}",
                          "FAILED", username, "error")

        # 2. App-owned UFW rules for this domain (and any blocked parent).
        for tag in ufw_tags:
            try:
                removed = ufw.delete_rules_for_comment(tag)
                if removed:
                    log_event("DELETE_UFW_RULE", domain,
                              f"Removed {removed} UFW rule(s) for blocked domain.",
                              "SUCCESS", username, "firewall")
            except UFWError as exc:
                warnings.append(str(exc))
                log_event("ERROR", domain, f"UFW cleanup failed: {exc}",
                          "FAILED", username, "error")

        # 3. Keep the database consistent with reality.
        if existing:
            db.clear_domain_ips(existing["id"])
            db.set_domain_allowed(existing["id"], utcnow_iso())
        elif dns_blocked or ufw_tags:
            # No record, but the system was blocking it — record the unblock so
            # the domain shows as ALLOWED instead of disappearing from the app.
            # insert_domain defaults to 'blocked', so flip it to 'allowed'.
            domain_id = db.insert_domain(domain, "both",
                                         "Unblocked (system-level)", utcnow_iso())
            db.set_domain_allowed(domain_id, utcnow_iso())

        message = "Domain unblocked."
        if warnings:
            message += " " + " ".join(warnings)
        log_event("UNBLOCK_DOMAIN", domain, message, "SUCCESS", username, "domain")

        return {"success": True, "domain": domain, "warnings": warnings}

    @staticmethod
    def _domain_and_parents(domain: str) -> list[str]:
        """The domain plus each parent domain (``www.x.com`` -> ``x.com``)."""
        parts = domain.split(".")
        result = [domain]
        for i in range(1, len(parts) - 1):
            result.append(".".join(parts[i:]))
        return result

    def _system_dns_blocks(self, domain: str) -> list[str]:
        """DNS entries found on the system for this domain or a parent."""
        try:
            blocked = set(dns.blocked_domains())
        except (OSError, DNSUnavailableError):
            return []
        return sorted(d for d in self._domain_and_parents(domain) if d in blocked)

    def _system_ufw_tags(self, domain: str) -> set[str]:
        """App-owned UFW comment tags found live for this domain or a parent."""
        candidates = self._domain_and_parents(domain)
        tags = {ufw.tag_domain(d) for d in candidates}
        try:
            live = ufw.rules()
        except UFWError:
            return set()
        return {r["comment"] for r in live if r["comment"] in tags}

    @staticmethod
    def _has_active_temp_dns(domain: str) -> bool:
        """True if an active temporary block for this domain needs the DNS entry."""
        for block in db.get_active_temporary_blocks():
            if block["target"] == domain and block["target_type"] == "domain":
                return True
        return False

    # ------------------------------------------------------------ refresh IPs
    def refresh_ips(self, domain_id: int, username: str = "admin") -> dict:
        domain = db.get_domain(domain_id)
        if not domain:
            raise utils.NotFoundError("Domain not found.")
        current = self.resolve_ips(domain["domain"])
        stored = set(db.get_ip_addresses(domain_id))

        additions = sorted(set(current) - stored)
        removals = sorted(stored - set(current))
        warnings: list[str] = []

        if domain["status"] == "blocked" and domain["method"] in ("ufw", "both"):
            tag = ufw.tag_domain(domain["domain"])
            for ip in removals:
                try:
                    ufw.delete_rules_for_comment(tag, to_ip=ip)
                except UFWError as exc:
                    warnings.append(f"Could not remove obsolete rule for {ip}: {exc}")
            for ip in additions:
                try:
                    ufw.add_deny_out_to(ip, tag)
                except UFWError as exc:
                    warnings.append(f"Could not add rule for {ip}: {exc}")

        db.replace_domain_ips(domain_id, current, utcnow_iso())

        message = f"IP refresh: {len(current)} address(es)."
        if additions:
            message += f" Added {', '.join(additions)}."
        if removals:
            message += f" Removed {', '.join(removals)}."
        if warnings:
            message += " " + " ".join(warnings)
        log_event("IP_SYNC", domain["domain"], message, "SUCCESS", username, "domain")

        return {
            "success": True,
            "domain": domain["domain"],
            "ips": current,
            "added": additions,
            "removed": removals,
            "warnings": warnings,
        }

    # ------------------------------------------------------------ sync all
    def sync_all_domain_ips(self, username: str = "system") -> None:
        """Refresh IPs for every blocked domain (called by the scheduler)."""
        for domain in db.get_domains():
            if domain["status"] != "blocked":
                continue
            if domain["method"] not in ("ufw", "both"):
                continue
            try:
                self.refresh_ips(domain["id"], username)
            except Exception as exc:  # never let one domain break the loop
                log_event("ERROR", domain["domain"], f"IP sync failed: {exc}",
                          "FAILED", username, "error")

    # ------------------------------------------------------------ read
    def list_domains(self, search: str = "") -> list[dict]:
        rows = db.get_domains(search)
        out = []
        for row in rows:
            ips = db.get_ip_addresses(row["id"])
            row["ips"] = ips
            out.append(row)
        return out

    def detail(self, domain_id: int) -> dict | None:
        domain = db.get_domain(domain_id)
        if not domain:
            return None
        domain["ips"] = db.get_domain_ips(domain_id)
        return domain


domain_manager = DomainManager()
