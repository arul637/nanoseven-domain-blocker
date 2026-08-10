"""UFW firewall manager.

All system interaction goes through ``subprocess.run`` with an argument list —
never a shell string.  Every command has a timeout.  Every rule this
application creates carries an ``IDB-*`` comment tag so the app can later find
exactly the rules it owns and never touch unrelated ones.

UFW works on IPs, not domains.  Domain-level blocking is handled by the DNS
manager; this class enforces at the IP level.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass

from config import Config
from services import utils

# UFW action tokens we know how to parse.
_ACTION_RE = re.compile(r"\b(ALLOW|DENY|REJECT|LIMIT)\s+(IN|OUT)\s+(.*)$", re.I)

# An IDB-* tag embedded anywhere in a comment (e.g. "dev web | IDB-USER-ab12cd34").
# The slug may contain letters, digits and dashes; hex UUIDs are lowercase too.
_IDB_TAG_RE = re.compile(r"\bIDB-(?:DOMAIN|TEMP|IP|USER)-[A-Za-z0-9-]+", re.I)


class UFWError(Exception):
    """A UFW command failed or returned unexpected output."""


class UFWNotInstalledError(UFWError):
    """UFW (or sudo) is not available on this host."""


def _clean_output(text: str) -> str:
    # Strip ANSI escape sequences and trim trailing whitespace.
    text = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", text)
    return "\n".join(line for line in text.splitlines() if line.strip()).strip()


@dataclass
class UFWManager:
    """Thin, safe wrapper around the ``ufw`` command line tool."""

    def _cmd(self, args: list[str], timeout: int | None = None) -> subprocess.CompletedProcess:
        timeout = timeout or Config.COMMAND_TIMEOUT
        if os.name == "nt":
            raise UFWNotInstalledError("UFW is not installed on this platform.")
        if not shutil.which(Config.UFW_BIN):
            raise UFWNotInstalledError("UFW is not installed.")
        command = [*Config.SUDO_PREFIX, Config.UFW_BIN, *args]
        try:
            return subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                input="",  # never leave a prompt hanging on stdin
            )
        except FileNotFoundError:
            raise UFWNotInstalledError("sudo or ufw is not available.")
        except subprocess.TimeoutExpired:
            raise UFWError("UFW command timed out.")

    def _ok(self, process: subprocess.CompletedProcess) -> str:
        if process.returncode != 0:
            raise UFWError(_clean_output(process.stderr) or "UFW command failed.")
        return _clean_output(process.stdout)

    # ------------------------------------------------------------------ tags
    @staticmethod
    def tag_domain(domain: str) -> str:
        return f"{Config.TAG_DOMAIN}{utils.tag_slug(domain)}"

    @staticmethod
    def tag_temp(target: str) -> str:
        return f"{Config.TAG_TEMP}{utils.tag_slug(target)}"

    @staticmethod
    def tag_ip(ip: str) -> str:
        return f"{Config.TAG_IP}{utils.tag_slug(ip)}"

    @staticmethod
    def tag_user() -> str:
        import uuid
        return f"{Config.TAG_USER}{uuid.uuid4().hex[:8]}"

    @staticmethod
    def _is_app_tag(comment: str) -> bool:
        # The tag may follow a user-supplied comment ("dev web | IDB-USER-xxxx"),
        # so a startswith() check is not enough — search the whole comment.
        return bool(_IDB_TAG_RE.search(comment or ""))

    @staticmethod
    def extract_identifier(comment: str) -> str:
        """Pull the full IDB-* identifier out of a rule comment, if any.

        ``"dev web | IDB-USER-ab12cd34"`` -> ``"IDB-USER-ab12cd34"``.
        Returns "" when the comment carries no IDB tag.
        """
        match = _IDB_TAG_RE.search(comment or "")
        return match.group(0) if match else ""

    # ------------------------------------------------------------------ status
    def status(self) -> dict:
        """Return {'status', 'enabled', 'default_incoming', 'default_outgoing'}."""
        process = self._cmd(["status", "verbose"])
        text = self._ok(process)
        enabled = bool(re.search(r"^Status:\s*active", text, re.M | re.I))
        incoming = outgoing = "allow"
        match = re.search(
            r"Default:\s*(\w+)\s*\(incoming\),\s*(\w+)\s*\(outgoing\)", text, re.I
        )
        if match:
            incoming, outgoing = match.group(1).upper(), match.group(2).upper()
        return {
            "status": "active" if enabled else "inactive",
            "enabled": enabled,
            "default_incoming": incoming,
            "default_outgoing": outgoing,
        }

    # ------------------------------------------------------------------ rules
    def rules(self) -> list[dict]:
        """Parse ``ufw status numbered`` into a list of rule dicts."""
        process = self._cmd(["status", "numbered"])
        text = self._ok(process)
        rules: list[dict] = []
        for raw in text.splitlines():
            line = raw.strip()
            header = re.match(r"^\[\s*(\d+)\]\s+(.*)$", line)
            if not header:
                continue
            number = int(header.group(1))
            rest = header.group(2)
            raw_comment = ""
            if "#" in rest:
                rest, _, raw_comment = rest.partition("#")
            rest = rest.strip()

            action_match = _ACTION_RE.search(rest)
            if not action_match:
                continue
            to_part = rest[: action_match.start()].strip()
            action = action_match.group(1).upper()
            direction = action_match.group(2).lower()
            from_part = action_match.group(3).strip()

            is_v6 = "(v6)" in to_part or "(v6)" in from_part
            to_clean = re.sub(r"\s*\(v6\)", "", to_part).strip()
            from_clean = re.sub(r"\s*\(v6\)", "", from_part).strip()
            raw_comment = raw_comment.strip()

            port, protocol = self._parse_port_protocol(to_clean)
            rules.append(
                {
                    "number": number,
                    "to": to_clean,
                    "action": action,
                    "direction": direction,
                    "from": from_clean,
                    "port": port,
                    "protocol": protocol,
                    "comment": raw_comment,
                    "origin": "app" if self._is_app_tag(raw_comment) else "manual",
                    "is_v6": is_v6,
                }
            )
        return rules

    @staticmethod
    def _parse_port_protocol(to_field: str) -> tuple[str, str]:
        if not to_field or to_field.lower().startswith("anywhere"):
            return "", ""
        match = re.match(r"^(\d+(?::\d+)?)/(tcp|udp)$", to_field, re.I)
        if match:
            return match.group(1), match.group(2).lower()
        if re.match(r"^\d+(?::\d+)?$", to_field):
            return to_field, "any"
        return "", ""

    # ------------------------------------------------------------------ create
    def add_rule(self, action: str, direction: str, source: str = "",
                 destination: str = "", port: str = "", protocol: str = "",
                 comment: str = "") -> None:
        args: list[str] = [action]
        args.append("in" if direction in ("in", "incoming") else "out")
        if source:
            args += ["from", source]
        args += ["to", destination or "any"]
        if port:
            args += ["port", str(port)]
        if protocol and protocol.lower() in ("tcp", "udp"):
            args += ["proto", protocol.lower()]
        if comment:
            args += ["comment", comment]
        self._ok(self._cmd(args))

    def add_deny_out_to(self, ip: str, comment: str) -> None:
        self._ok(self._cmd(["deny", "out", "to", ip, "comment", comment]))

    # ------------------------------------------------------------------ delete
    def delete_rule(self, rule_number: int, *, force_manual: bool = False) -> dict:
        """Delete a numbered rule.  Manual rules require explicit force.

        ``--force`` is passed so UFW can never silently abort on an interactive
        confirmation prompt, and the deletion is verified afterwards — a
        returncode of 0 alone is not proof the rule actually went away.
        """
        rules = self.rules()
        match = next((r for r in rules if r["number"] == rule_number), None)
        if match is None:
            raise UFWError("Rule no longer exists.")
        if match["origin"] != "app" and not force_manual:
            raise UFWError(
                "This rule was not created by Nano Blocker. Deleting it requires "
                "explicit confirmation."
            )
        self._ok(self._cmd(["--force", "delete", str(rule_number)]))
        if self._rule_still_present(match):
            raise UFWError(
                f"UFW did not delete rule #{rule_number}. It may need sudo "
                "privileges or a reload."
            )
        return match

    def _rule_still_present(self, match: dict) -> bool:
        """True if an identical rule still exists anywhere after deletion.

        Searches the whole ruleset rather than only the old number slot, so a
        renumber race that deletes the wrong rule is caught too.
        """
        for rule in self.rules():
            if rule["comment"] != match["comment"]:
                continue
            if rule["to"] != match["to"] or rule["from"] != match["from"]:
                continue
            if rule["action"] != match["action"] or rule["direction"] != match["direction"]:
                continue
            return True
        return False

    def delete_rules_for_comment(self, comment: str, to_ip: str | None = None) -> int:
        """Delete every app-owned rule carrying ``comment`` (optionally to one IP).

        Re-queries after each deletion because UFW renumbers its rules.
        """
        removed = 0
        while True:
            candidates = [
                r for r in self.rules() if r["comment"] == comment
            ]
            if to_ip is not None:
                candidates = [r for r in candidates if self._to_matches(r, to_ip)]
            if not candidates:
                break
            highest = max(candidates, key=lambda r: r["number"])
            self._ok(self._cmd(["--force", "delete", str(highest["number"])]))
            removed += 1
        return removed

    @staticmethod
    def _to_matches(rule: dict, ip: str) -> bool:
        # UFW renders OUTBOUND rules with the destination address in the "From"
        # column (Anywhere DENY OUT 203.0.113.7), so look at the right field.
        target = rule["from"] if rule["direction"] == "out" else rule["to"]
        if "/" in target:
            target = target.split("/")[0]
        return target == ip

    # ------------------------------------------------------------------ controls
    def enable(self) -> dict:
        self._ok(self._cmd(["--force", "enable"]))
        return self.status()

    def disable(self) -> dict:
        self._ok(self._cmd(["--force", "disable"]))
        return self.status()

    def reload(self) -> None:
        self._ok(self._cmd(["reload"]))

    def reset(self) -> None:
        # Only ever called from an explicitly confirmed user action.
        self._ok(self._cmd(["--force", "reset"]))

    # ------------------------------------------------------------------ sync
    def sync_registry(self, live: list[dict] | None = None) -> dict:
        """Reconcile the ``firewall_rules`` DB registry with the live ruleset.

        Keeps the dashboard count and rule registry truthful even when rules are
        added or removed from the command line:
          * app-owned IDB-tagged rules found live but missing from the DB are
            inserted (they may have been created externally, e.g. by setup or a
            manual ``ufw`` command);
          * registry rows whose identifier no longer exists live are dropped.
        Returns ``{"added": n, "removed": n}``.  Never touches manual rules.
        """
        from database import db, utcnow_iso

        live = live if live is not None else self.rules()
        added = removed = 0
        live_ids: set[str] = set()

        for rule in live:
            if rule["origin"] != "app":
                continue
            identifier = self.extract_identifier(rule["comment"])
            if not identifier:
                continue
            live_ids.add(identifier)
            if not db.firewall_rule_exists(identifier):
                db.add_firewall_rule(
                    identifier,
                    rule["action"].lower(),
                    rule["direction"],
                    rule["from"],
                    rule["to"],
                    rule["port"],
                    rule["protocol"],
                    rule["comment"],
                    "app",
                    utcnow_iso(),
                )
                added += 1

        for row in db.get_firewall_rules():
            if row["origin"] == "app" and row["rule_identifier"] not in live_ids:
                db.delete_firewall_rule_by_identifier(row["rule_identifier"])
                removed += 1

        return {"added": added, "removed": removed}


# Application-wide instance.
ufw = UFWManager()
