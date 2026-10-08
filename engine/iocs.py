"""IOC data model, validation and normalization.

Supported indicator types: ipv4, domain, url, sha256.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,}$"
)
URL_RE = re.compile(r"^https?://[^\s/$.?#].[^\s]*$", re.IGNORECASE)

IOC_TYPES = ("ipv4", "domain", "url", "sha256")


@dataclass
class IOC:
    """A single normalized indicator of compromise."""

    value: str
    ioc_type: str
    feed: str
    first_seen: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


def normalize_value(value: str, ioc_type: str) -> str:
    """Canonicalize an indicator value (lowercase domains/URLs, strip noise)."""
    v = value.strip()
    if ioc_type in ("domain", "url"):
        v = v.lower()
    if ioc_type == "domain":
        v = v.rstrip(".")
    if ioc_type == "url":
        v = v.rstrip("/")
    return v


def classify(value: str) -> str | None:
    """Guess the IOC type of a raw string, or None if it is not an IOC."""
    v = value.strip()
    if SHA256_RE.match(v):
        return "sha256"
    try:
        ip = ipaddress.ip_address(v)
        if isinstance(ip, ipaddress.IPv4Address):
            return "ipv4"
        return None  # IPv6 not tracked by this engine
    except ValueError:
        pass
    if URL_RE.match(v):
        return "url"
    if DOMAIN_RE.match(v):
        return "domain"
    return None


def valid_for_type(value: str, ioc_type: str) -> bool:
    """Check that a raw value is well-formed for the given indicator type."""
    v = value.strip()
    if ioc_type == "sha256":
        return bool(SHA256_RE.match(v))
    if ioc_type == "ipv4":
        try:
            return isinstance(ipaddress.ip_address(v), ipaddress.IPv4Address)
        except ValueError:
            return False
    if ioc_type == "url":
        return bool(URL_RE.match(v))
    if ioc_type == "domain":
        return bool(DOMAIN_RE.match(v))
    return False


def make_ioc(value: str, feed: str, ioc_type: str | None = None) -> IOC | None:
    """Build a normalized IOC, or None when the value is not a valid indicator.

    The value is always validated — even when the type is given explicitly —
    because feed data is not always clean.
    """
    t = ioc_type or classify(value)
    if t is None or t not in IOC_TYPES:
        return None
    if not valid_for_type(value, t):
        return None
    return IOC(value=normalize_value(value, t), ioc_type=t, feed=feed)
