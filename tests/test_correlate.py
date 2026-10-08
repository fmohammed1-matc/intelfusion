"""Tests for the correlation engine with synthetic logs + fixture IOCs."""
import pytest

from engine.correlate import correlate, level_for, severity_for
from engine.fixtures import DEMO_IOCS
from engine.iocs import make_ioc
from engine.store import Store


@pytest.fixture
def seeded_store(tmp_path):
    s = Store(tmp_path / "test.db")
    iocs = [make_ioc(v, "demo-fixture", t) for v, t in DEMO_IOCS]
    s.upsert_iocs([i for i in iocs if i])
    yield s
    s.close()


def _write(path, lines):
    path.write_text("\n".join(lines) + "\n")
    return str(path)


def test_correlate_finds_planted_hits(seeded_store, tmp_path):
    logf = _write(tmp_path / "auth.log", [
        "Oct  7 10:00:00 web sshd[1]: Accepted publickey for alice from 10.0.0.12",
        "Oct  7 10:01:00 web sshd[2]: Failed password for root from 203.0.113.45 port 51234 ssh2",
        "Oct  7 10:02:00 web sshd[3]: dns query evil-update.example from 10.0.0.5",
    ])
    new_alerts = correlate(seeded_store, [logf])
    values = {a["ioc_value"] for a in new_alerts}
    assert "203.0.113.45" in values
    assert "evil-update.example" in values
    assert len(new_alerts) == 2  # benign line produces nothing


def test_correlate_dedupes_on_rerun(seeded_store, tmp_path):
    logf = _write(tmp_path / "auth.log", [
        "Failed password for root from 203.0.113.45 port 51234 ssh2",
    ])
    assert len(correlate(seeded_store, [logf])) == 1
    assert correlate(seeded_store, [logf]) == []  # second run: deduped


def test_domain_boundary_avoids_partial_match(seeded_store, tmp_path):
    # 'notevil-update.example' must NOT match the 'evil-update.example' IOC
    logf = _write(tmp_path / "x.log", [
        "connection to notevil-update.example established",
    ])
    assert correlate(seeded_store, [logf]) == []


def test_subdomain_of_malicious_domain_matches(seeded_store, tmp_path):
    logf = _write(tmp_path / "x.log", [
        "dns query a.evil-update.example from 10.0.0.5",
    ])
    alerts = correlate(seeded_store, [logf])
    assert len(alerts) == 1
    assert alerts[0]["ioc_value"] == "evil-update.example"


def test_missing_log_file_is_skipped(seeded_store):
    assert correlate(seeded_store, ["/nonexistent/file.log"]) == []


def test_alert_carries_evidence(seeded_store, tmp_path):
    logf = _write(tmp_path / "fw.log", [
        "DROP OUTBOUND url=http://evil-update.example/payload.bin src=10.0.0.9",
    ])
    alerts = correlate(seeded_store, [logf])
    # the line matches both the URL IOC and the domain IOC inside it
    assert {a["ioc_type"] for a in alerts} == {"url", "domain"}
    url_alert = next(a for a in alerts if a["ioc_type"] == "url")
    assert url_alert["ioc_value"] == "http://evil-update.example/payload.bin"
    assert "demo-fixture" in url_alert["feeds"]
    assert url_alert["log_file"] == logf
    assert "payload.bin" in url_alert["log_line"]
    assert 0 < url_alert["severity"] <= 100


def test_severity_scoring():
    # sha256 from urlhaus outranks a single-feed ipv4
    assert severity_for("sha256", ["urlhaus"]) > severity_for("ipv4", ["demo-fixture"])
    # cross-feed corroboration raises the score
    single = severity_for("domain", ["urlhaus"])
    multi = severity_for("domain", ["urlhaus", "otx"])
    assert multi > single
    assert severity_for("ipv4", ["no-such-feed"]) == 40  # unknown feed default


def test_level_bands():
    assert level_for(95) == "critical"
    assert level_for(80) == "critical"
    assert level_for(79) == "high"
    assert level_for(60) == "high"
    assert level_for(59) == "medium"
    assert level_for(40) == "medium"
    assert level_for(39) == "low"
