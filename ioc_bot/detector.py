import ipaddress
from urllib.parse import urlparse


def detect_indicator_type(value: str) -> str:
    """Classify an indicator string as an IP address, hash, domain, or unknown."""

    value = value.strip().lower()

    # Full URLs are accepted: strip the scheme/path and classify the host.
    if "://" in value:
        value = urlparse(value).netloc

    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass  # not an IP - fall through to the next check

    if len(value) in (32, 40, 64) and all(c in "0123456789abcdef" for c in value):
        return "hash"

    if all(c in "abcdefghijklmnopqrstuvwxyz0123456789.-" for c in value) and "." in value:
        return "domain"

    return "unknown"