"""Tests for the SQLite store: IOC upserts, feed runs, alert dedupe."""
import pytest

from engine.iocs import make_ioc
from engine.store import Store


@pytest.fixture
def store(tmp_path):
    s = Store(tmp_path / "test.db")
    yield s
    s.close()


def _ioc(value, feed="urlhaus", t=None):
    return make_ioc(value, feed, t)


def test_upsert_iocs_dedupes(store):
    iocs = [_ioc("evil.example"), _ioc("evil.example"), _ioc("203.0.113.45", t="ipv4")]
    assert store.upsert_iocs(iocs) == 2  # duplicate ignored
    assert store.upsert_iocs(iocs) == 0  # all already present
    assert len(store.get_iocs()) == 2


def test_same_value_different_feed_is_distinct(store):
    assert store.upsert_iocs([_ioc("evil.example", "urlhaus")]) == 1
    assert store.upsert_iocs([_ioc("evil.example", "otx")]) == 1
    assert store.feeds_for_value("evil.example") == ["otx", "urlhaus"]


def test_ioc_count_by_feed(store):
    store.upsert_iocs([_ioc("a.example"), _ioc("b.example"), _ioc("1.2.3.4", t="ipv4")])
    counts = store.ioc_count_by_feed()
    assert counts == {"urlhaus": 3}


def test_record_and_get_feed_runs(store):
    store.record_feed_run("urlhaus", "2026-01-01T00:00:00+00:00", 42, status="ok")
    store.record_feed_run("otx", "2026-01-01T00:00:00+00:00", 0,
                          status="skipped", error="no API key")
    runs = {r["feed"]: r for r in store.get_feed_runs()}
    assert runs["urlhaus"]["ioc_count"] == 42
    assert runs["otx"]["status"] == "skipped"


def _alert():
    return {
        "ioc_value": "evil.example",
        "ioc_type": "domain",
        "feeds": "urlhaus",
        "severity": 75,
        "level": "high",
        "log_file": "/var/log/auth.log",
        "log_line": "Failed password from evil.example",
        "matched_at": "2026-01-01T00:00:00+00:00",
        "dedupe_key": "abc123",
    }


def test_insert_alert_dedupes(store):
    assert store.insert_alert(_alert()) is True
    assert store.insert_alert(_alert()) is False  # same dedupe_key
    assert store.alert_count() == 1


def test_get_alerts_newest_first(store):
    a1 = _alert(); a1["dedupe_key"] = "k1"; a1["matched_at"] = "2026-01-01T00:00:00+00:00"
    a2 = _alert(); a2["dedupe_key"] = "k2"; a2["matched_at"] = "2026-01-02T00:00:00+00:00"
    store.insert_alert(a1)
    store.insert_alert(a2)
    alerts = store.get_alerts()
    assert alerts[0]["dedupe_key"] == "k2"
    assert store.get_alert(alerts[0]["id"])["dedupe_key"] == "k2"
    assert store.get_alert(99999) is None
