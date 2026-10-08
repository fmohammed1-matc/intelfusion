"""Synthetic demo fixtures.

All values below are deliberately fake (RFC 5737 documentation IP ranges and
the reserved .example TLD) so the offline demo can never be confused with
real threat intelligence.
"""
from __future__ import annotations

# (value, ioc_type) — the demo log generator plants hits for these.
DEMO_IOCS: list[tuple[str, str]] = [
    ("203.0.113.45", "ipv4"),
    ("198.51.100.23", "ipv4"),
    ("192.0.2.88", "ipv4"),
    ("evil-update.example", "domain"),
    ("secure-login-verify.example", "domain"),
    ("cdn-payloads.example", "domain"),
    ("http://evil-update.example/payload.bin", "url"),
    ("https://secure-login-verify.example/login?session=x7q2", "url"),
    (
        "a3f5c8d21e47b90f6c2d48e1a5b73c96d04e7f2a1b5c83d94e6f70a12b34c56d7",
        "sha256",
    ),
    (
        "7c9e1b4a5d2f48630e1a7c5b94d62f380e4a6d1c93b5f70a82e4d6c1b35a97e03",
        "sha256",
    ),
]

# Approximate geo used only to draw demo arcs on the dashboard globe.
DEMO_GEO: dict[str, dict] = {
    "203.0.113.45": {"country": "Russia", "lat": 55.75, "lon": 37.61},
    "198.51.100.23": {"country": "Brazil", "lat": -23.55, "lon": -46.63},
    "192.0.2.88": {"country": "Netherlands", "lat": 52.37, "lon": 4.89},
    "evil-update.example": {"country": "Russia", "lat": 55.75, "lon": 37.61},
    "secure-login-verify.example": {"country": "Nigeria", "lat": 9.08, "lon": 8.67},
    "cdn-payloads.example": {"country": "Netherlands", "lat": 52.37, "lon": 4.89},
    "http://evil-update.example/payload.bin": {
        "country": "Russia",
        "lat": 55.75,
        "lon": 37.61,
    },
    "https://secure-login-verify.example/login?session=x7q2": {
        "country": "Nigeria",
        "lat": 9.08,
        "lon": 8.67,
    },
}

# "Home" SOC location the arcs converge on.
HOME_BASE = {"label": "Madison, WI", "lat": 43.07, "lon": -89.40}


def _domain_of(value: str, ioc_type: str) -> str | None:
    if ioc_type == "domain":
        return value
    if ioc_type == "url":
        host = value.split("://", 1)[-1].split("/", 1)[0].split("@")[-1]
        return host.split(":", 1)[0].lower()
    return None


def geo_for_ioc(value: str, ioc_type: str) -> dict | None:
    """Return demo geo for an IOC value, falling back to its domain for URLs."""
    if value in DEMO_GEO:
        return DEMO_GEO[value]
    domain = _domain_of(value, ioc_type)
    if domain and domain in DEMO_GEO:
        return DEMO_GEO[domain]
    return None
