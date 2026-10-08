"""Correlation engine: match stored IOCs against local log files.

For every log line, every known IOC is tested with a boundary-aware regex.
Matches become severity-scored, deduplicated alerts carrying the exact
evidence (log file + line, IOC, reporting feeds).
"""
from __future__ import annotations

import hashlib
import logging
import re
from datetime import datetime, timezone
from pathlib import Path

from .store import Store

log = logging.getLogger(__name__)

# Base severity per feed; cross-feed corroboration adds confidence.
FEED_BASE_SCORE = {
    "urlhaus": 70,
    "otx": 60,
    "abuseipdb": 60,
    "demo-fixture": 50,
}
# High-fidelity indicator types score higher (a SHA256 hit is rarely noise).
TYPE_BONUS = {"sha256": 15, "url": 10, "domain": 5, "ipv4": 0}
CROSS_FEED_BONUS = 10
MAX_LINE_LEN = 600


def severity_for(ioc_type: str, feeds: list[str]) -> int:
    """0-100 severity: strongest feed base + type bonus + cross-feed bonus."""
    base = max((FEED_BASE_SCORE.get(f, 40) for f in feeds), default=40)
    bonus = TYPE_BONUS.get(ioc_type, 0)
    cross = CROSS_FEED_BONUS * max(0, len(set(feeds)) - 1)
    return min(100, base + bonus + min(cross, 20))


def level_for(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def _pattern(ioc_type: str, value: str) -> re.Pattern:
    """Boundary-aware regex so 'evil.example' doesn't match 'notevil.example'."""
    esc = re.escape(value)
    if ioc_type in ("domain", "ipv4"):
        # allow a leading dot (subdomains) but not partial-word matches
        return re.compile(r"(?<![A-Za-z0-9-])" + esc + r"(?![A-Za-z0-9-])")
    if ioc_type == "sha256":
        return re.compile(r"(?<![0-9a-fA-F])" + esc + r"(?![0-9a-fA-F])")
    return re.compile(esc)  # urls: substring match is fine


def _dedupe_key(ioc_value: str, log_file: str, line: str) -> str:
    h = hashlib.sha1(
        f"{ioc_value}|{log_file}|{line.strip()}".encode("utf-8", "ignore")
    ).hexdigest()
    return h


def correlate(store: Store, log_files: list[str | Path]) -> list[dict]:
    """Scan log files; insert new alerts; return the *new* alerts only."""
    iocs = store.get_iocs()
    if not iocs:
        log.info("no IOCs in database; nothing to correlate")
        return []

    compiled = [(_pattern(i["ioc_type"], i["value"]), i) for i in iocs]
    new_alerts: list[dict] = []

    for log_file in log_files:
        path = Path(log_file)
        if not path.is_file():
            log.warning("log file not found, skipping: %s", path)
            continue
        try:
            with path.open("r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    line = line.rstrip("\n")
                    if not line.strip():
                        continue
                    for rx, ioc in compiled:
                        if not rx.search(line):
                            continue
                        feeds = store.feeds_for_value(ioc["value"])
                        score = severity_for(ioc["ioc_type"], feeds)
                        alert = {
                            "ioc_value": ioc["value"],
                            "ioc_type": ioc["ioc_type"],
                            "feeds": ",".join(feeds),
                            "severity": score,
                            "level": level_for(score),
                            "log_file": str(path),
                            "log_line": line[:MAX_LINE_LEN],
                            "matched_at": datetime.now(timezone.utc).isoformat(),
                            "dedupe_key": _dedupe_key(
                                ioc["value"], str(path), line
                            ),
                        }
                        if store.insert_alert(alert):
                            new_alerts.append(alert)
        except OSError as exc:
            log.warning("could not read %s: %s", path, exc)

    log.info("correlation complete: %d new alert(s)", len(new_alerts))
    return new_alerts
