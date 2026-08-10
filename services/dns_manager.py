"""DNS filtering manager (dnsmasq).

Blocked domains are turned into ``address=/<domain>/0.0.0.0`` entries inside a
dedicated application file (``/etc/dnsmasq.d/intelligent-domain-blocker.conf``).
The user's main dnsmasq configuration is never overwritten.

dnsmasq's ``address=/domain/ip`` directive matches the domain AND all of its
subdomains, which gives us subdomain blocking for free.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

from config import Config


class DNSUnavailableError(Exception):
    """dnsmasq / systemctl is not available or a command failed."""


class DNSManager:
    """Safe management of the application's dnsmasq config file."""

    # ------------------------------------------------------------- systemctl
    def _service_cmd(self, args: list[str], timeout: int = 12) -> subprocess.CompletedProcess:
        if os.name == "nt":
            raise DNSUnavailableError(
                "DNS filtering (dnsmasq) is not available on this platform."
            )
        if not shutil.which("systemctl"):
            raise DNSUnavailableError("systemctl is not available.")
        command = [*Config.SUDO_PREFIX, "systemctl", *args]
        try:
            return subprocess.run(
                command, capture_output=True, text=True, timeout=timeout, input=""
            )
        except FileNotFoundError:
            raise DNSUnavailableError("Cannot run systemctl (missing sudo?).")
        except subprocess.TimeoutExpired:
            raise DNSUnavailableError("DNS service command timed out.")

    def service_status(self) -> str:
        """Return 'running', 'stopped' or 'unavailable'."""
        if os.name == "nt":
            return "unavailable"
        try:
            process = self._service_cmd(["is-active", Config.DNS_SERVICE], timeout=8)
            if process.returncode == 0:
                return "running"
        except DNSUnavailableError:
            return "unavailable"
        return "stopped"

    # ------------------------------------------------------------- config file
    def conf_path(self) -> str:
        return Config.DNSMASQ_CONF

    def _read_lines(self) -> list[str]:
        path = Path(self.conf_path())
        if not path.exists():
            return []
        try:
            return path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return []

    def _write_lines(self, lines: list[str]) -> None:
        path = Path(self.conf_path())
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            content = "\n".join(lines).strip() + "\n" if lines else ""
            path.write_text(content, encoding="utf-8")
        except OSError as exc:
            raise DNSUnavailableError(f"Cannot write DNS config: {exc}")

    @staticmethod
    def _entry(domain: str) -> str:
        return f"address=/{domain}/{Config.DNS_POISON_IP}"

    @staticmethod
    def _matches(line: str, domain: str) -> bool:
        return re.match(rf"^address=/{re.escape(domain)}/[^\s/]+$", line) is not None

    def block_domain(self, domain: str) -> bool:
        """Add a poisoned DNS entry for ``domain``. Returns True if changed."""
        lines = self._read_lines()
        if self._entry(domain) in lines:
            return False
        lines = [line for line in lines if not self._matches(line, domain)]
        lines.append(self._entry(domain))
        self._write_lines(lines)
        return True

    def unblock_domain(self, domain: str) -> bool:
        """Remove the poisoned entry for ``domain``. Returns True if changed."""
        lines = self._read_lines()
        kept = [line for line in lines if not self._matches(line, domain)]
        if len(kept) == len(lines):
            return False
        self._write_lines(kept)
        return True

    def blocked_domains(self) -> list[str]:
        """List domains currently poisoned in the config file."""
        result: list[str] = []
        for line in self._read_lines():
            match = re.match(r"^address=/([^/]+)/", line)
            if match:
                result.append(match.group(1))
        return result

    # ------------------------------------------------------------- reload
    def reload(self) -> None:
        """Reload dnsmasq, falling back to restart if reload is unsupported."""
        try:
            process = self._service_cmd(["reload", Config.DNS_SERVICE])
            if process.returncode == 0:
                return
        except DNSUnavailableError:
            raise
        process = self._service_cmd(["restart", Config.DNS_SERVICE])
        if process.returncode != 0:
            raise DNSUnavailableError(
                (process.stderr or process.stdout or "Failed to reload dnsmasq.").strip()
            )


# Application-wide instance.
dns = DNSManager()
