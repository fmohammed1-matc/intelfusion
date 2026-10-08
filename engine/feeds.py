"""OSINT threat-feed fetchers.

Defensive use only: these functions *read* public blocklists maintained by
the security community. They never probe, scan or attack anything.

- URLhaus (abuse.ch) ............ no API key required
- AlienVault OTX ................ API key required (skipped gracefully if absent)
- AbuseIPDB ..................... API key required (skipped gracefully if absent)
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

import requests

from .iocs import IOC, make_ioc

log = logging.getLogger(__name__)
TIMEOUT = 25
USER_AGENT = "IntelFusion/1.0 (defensive threat-intel research; contact: admin)"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class FeedResult:
    """Outcome of one feed fetch: iocs + status ('ok' | 'skipped' | 'error')."""

    def __init__(
        self,
        feed: str,
        iocs: list[IOC] | None = None,
        status: str = "ok",
        error: str | None = None,
    ):
        self.feed = feed
        self.iocs = iocs or []
        self.status = status
        self.error = error
        self.fetched_at = _now()


def _get(url: str, headers: dict | None = None) -> requests.Response:
    hdrs = {"User-Agent": USER_AGENT}
    if headers:
        hdrs.update(headers)
    resp = requests.get(url, headers=hdrs, timeout=TIMEOUT)
    resp.raise_for_status()
    return resp


def fetch_urlhaus() -> FeedResult:
    """Recent malware URLs + payload hashes from URLhaus (no key needed)."""
    url = "https://urlhaus.abuse.ch/downloads/json_recent/"
    try:
        data = _get(url).json()  # dict keyed by URLhaus ID
        iocs: list[IOC] = []
        for entry in data.values():
            if not isinstance(entry, dict):
                continue
            url_val = entry.get("url")
            sha_val = entry.get("sha256")
            if url_val:
                ioc = make_ioc(url_val, "urlhaus", "url")
                if ioc:
                    iocs.append(ioc)
            if sha_val:
                ioc = make_ioc(sha_val, "urlhaus", "sha256")
                if ioc:
                    iocs.append(ioc)
        return FeedResult("urlhaus", iocs)
    except Exception as exc:  # network down, format change, etc.
        log.warning("urlhaus fetch failed: %s", exc)
        return FeedResult("urlhaus", [], status="error", error=str(exc))


_OTX_TYPE_MAP = {
    "IPv4": "ipv4",
    "domain": "domain",
    "hostname": "domain",
    "URL": "url",
    "FileHash-SHA256": "sha256",
}


def fetch_otx(api_key: str | None = None, limit: int = 20) -> FeedResult:
    """Indicators from subscribed AlienVault OTX pulses (key required)."""
    if not api_key:
        return FeedResult("otx", [], status="skipped",
                          error="no API key configured")
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    try:
        data = _get(url, {"X-OTX-API-KEY": api_key}).json()
        iocs: list[IOC] = []
        for pulse in data.get("results", [])[:limit]:
            for ind in pulse.get("indicators", []):
                ioc_type = _OTX_TYPE_MAP.get(ind.get("type", ""))
                if not ioc_type:
                    continue
                ioc = make_ioc(str(ind.get("indicator", "")), "otx", ioc_type)
                if ioc:
                    iocs.append(ioc)
        return FeedResult("otx", iocs)
    except Exception as exc:
        log.warning("otx fetch failed: %s", exc)
        return FeedResult("otx", [], status="error", error=str(exc))


def fetch_abuseipdb(api_key: str | None = None, limit: int = 1000) -> FeedResult:
    """AbuseIPDB blacklist (key required)."""
    if not api_key:
        return FeedResult("abuseipdb", [], status="skipped",
                          error="no API key configured")
    url = "https://api.abuseipdb.com/api/v2/blacklist"
    try:
        data = _get(
            url,
            {"Key": api_key, "Accept": "application/json"},
        ).json()
        iocs: list[IOC] = []
        for entry in data.get("data", [])[:limit]:
            ip = entry.get("ipAddress")
            if ip:
                ioc = make_ioc(ip, "abuseipdb", "ipv4")
                if ioc:
                    iocs.append(ioc)
        return FeedResult("abuseipdb", iocs)
    except Exception as exc:
        log.warning("abuseipdb fetch failed: %s", exc)
        return FeedResult("abuseipdb", [], status="error", error=str(exc))


def fetch_all(otx_key: str | None = None,
              abuseipdb_key: str | None = None) -> list[FeedResult]:
    """Fetch every configured feed, never raising on a single feed's failure."""
    return [
        fetch_urlhaus(),
        fetch_otx(otx_key),
        fetch_abuseipdb(abuseipdb_key),
    ]
