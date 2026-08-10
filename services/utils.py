"""Validation helpers and application exceptions.

Every value that will reach a system command or the database is validated
before use.  Nothing in this module ever executes a command.

No function here constructs a shell string.  Validation rejects shell
operators and injection fragments outright.
"""
from __future__ import annotations

import ipaddress
import re

# ---------------------------------------------------------------------------
# Exceptions raised by the service layer.  Routes translate these into
# friendly HTTP responses (never raw tracebacks).
# ---------------------------------------------------------------------------
class AppError(Exception):
    """Base class for expected, user-facing errors."""


class ValidationError(AppError):
    """Input did not pass validation."""


class AlreadyBlockedError(AppError):
    """Domain is already blocked."""


class NotBlockedError(AppError):
    """Domain is not currently blocked."""


class WhitelistConflictError(AppError):
    """Operation conflicts with an enabled whitelist entry."""


class NotFoundError(AppError):
    """Requested record does not exist."""


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}$"
)

# Characters that are never acceptable in user-supplied values.
FORBIDDEN_CHARS = set(";&|`$<>\"'\\\n\r\x00#=")


def normalize_domain(value: str) -> str | None:
    """Return a lowercase, dot-stripped domain, or None if unusable."""
    if not isinstance(value, str):
        return None
    value = value.strip().lower().rstrip(".")
    if not value:
        return None
    # URLs / email-style values are not domains.
    if "://" in value or "@" in value or "/" in value:
        return None
    return value


def is_valid_domain(value: str) -> bool:
    """True if value is a syntactically valid hostname (no shell metachars)."""
    domain = normalize_domain(value)
    if not domain:
        return False
    if any(c in FORBIDDEN_CHARS for c in domain):
        return False
    if " " in domain or ".." in domain:
        return False
    return bool(DOMAIN_RE.match(domain))


def is_valid_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value.strip())
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def is_valid_ipv6(value: str) -> bool:
    try:
        # Strip a possible zone index (e.g. fe80::1%eth0) before validating.
        ipaddress.IPv6Address(value.strip().split("%")[0])
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def is_valid_ip(value: str) -> bool:
    return is_valid_ipv4(value) or is_valid_ipv6(value)


def classify_target(value: str) -> str | None:
    """Return 'ip' or 'domain' for a value, or None if it is neither."""
    if is_valid_ip(value):
        return "ip"
    if is_valid_domain(value):
        return "domain"
    return None


def is_valid_port(value) -> bool:
    try:
        port = int(value)
        return 1 <= port <= 65535
    except (TypeError, ValueError):
        return False


def is_valid_protocol(value: str) -> bool:
    return isinstance(value, str) and value.strip().lower() in ("tcp", "udp", "any")


def is_valid_action(value: str) -> bool:
    return isinstance(value, str) and value.strip().lower() in ("allow", "deny", "reject")


def is_valid_direction(value: str) -> bool:
    return (
        isinstance(value, str)
        and value.strip().lower() in ("in", "out", "incoming", "outgoing")
    )


def safe_comment(value) -> str:
    """Sanitize a free-text comment for storage and UFW output parsing."""
    if not value:
        return ""
    cleaned = "".join(ch for ch in str(value) if ch not in FORBIDDEN_CHARS)
    return " ".join(cleaned.split())[:120]


def tag_slug(value: str) -> str:
    """Turn a domain/IP into the slug used inside UFW comment tags.

    ``example.com`` -> ``example-com``, ``192.168.1.100`` -> ``192-168-1-100``.
    """
    return re.sub(r"[^A-Za-z0-9]", "-", value)
