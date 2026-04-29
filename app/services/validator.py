import re
import socket
import ipaddress
from app.config import settings
from app.errors import InvalidTargetError, DisallowedTargetError

_LABEL_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?$")

_LOOPBACK_V4 = ipaddress.ip_network("127.0.0.0/8")
_LINK_LOCAL   = ipaddress.ip_network("169.254.0.0/16")
_LOOPBACK_V6  = ipaddress.ip_network("::1/128")
_RFC1918 = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


def _check_policy(ip_str: str, original: str) -> None:
    """Raise DisallowedTargetError if ip_str is in a blocked range."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return

    if addr in _LOOPBACK_V4 or addr in _LOOPBACK_V6:
        raise DisallowedTargetError(
            f"Scanning loopback addresses is not permitted", target=original
        )
    if addr in _LINK_LOCAL:
        raise DisallowedTargetError(
            f"Scanning link-local addresses is not permitted", target=original
        )
    if settings.BLOCK_PRIVATE_RANGES:
        for net in _RFC1918:
            if addr in net:
                raise DisallowedTargetError(
                    f"Scanning private (RFC 1918) addresses is not permitted", target=original
                )


def _is_valid_hostname(target: str) -> bool:
    if len(target) > 253:
        return False
    labels = target.rstrip(".").split(".")
    for label in labels:
        if not label or len(label) > 63:
            return False
        if not _LABEL_RE.match(label):
            return False
    return True


def _is_ip(target: str) -> bool:
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, target)
            return True
        except OSError:
            pass
    return False


def validate_target_structural(target: str) -> str:
    """Structural checks only — no policy. Used for GET endpoints."""
    target = target.strip()

    if not target:
        raise InvalidTargetError("Target must not be empty", target=target)

    if target.startswith("-"):
        raise InvalidTargetError(
            "Target starts with a hyphen, which is not permitted", target=target
        )

    for scheme in ("http://", "https://", "ftp://"):
        if target.lower().startswith(scheme):
            raise InvalidTargetError(
                "Target must not include a URI scheme (http://, https://, etc.)", target=target
            )

    if _is_ip(target):
        return target.lower()

    if _is_valid_hostname(target):
        return target.lower()

    raise InvalidTargetError(f"'{target}' is not a valid IP address or hostname", target=target)


def validate_target(target: str) -> str:
    """Full validation: structural + policy. Used for POST /scans."""
    normalised = validate_target_structural(target)

    if _is_ip(normalised):
        _check_policy(normalised, normalised)
        return normalised

    # Hostname — run policy check on string literal first (catches "localhost")
    if normalised == "localhost":
        raise DisallowedTargetError("Scanning localhost is not permitted", target=normalised)

    # If BLOCK_PRIVATE_RANGES is enabled, also resolve and check every address
    if settings.BLOCK_PRIVATE_RANGES:
        try:
            addrs = socket.getaddrinfo(normalised, None)
            for addr_info in addrs:
                _check_policy(addr_info[4][0], normalised)
        except socket.gaierror:
            pass  # unresolvable — let nmap handle it; fail-open is correct for internal tool

    return normalised
