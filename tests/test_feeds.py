"""Feed fetcher tests — all network calls are mocked; never hits real APIs."""
from unittest.mock import patch

from engine import feeds

SHA = "b" * 64


class _Resp:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


def _mock_get(payload=None, exc=None):
    def _get(*a, **k):
        if exc:
            raise exc
        return _Resp(payload)
    return _get


def test_urlhaus_parses_urls_and_hashes():
    payload = {
        "1": {"url": "http://evil.example/payload.exe", "sha256": SHA},
        "2": {"url": "not a url", "sha256": None},
    }
    with patch.object(feeds.requests, "get", _mock_get(payload)):
        res = feeds.fetch_urlhaus()
    assert res.status == "ok"
    values = {i.value for i in res.iocs}
    assert "http://evil.example/payload.exe" in values
    assert SHA in values
    assert len(res.iocs) == 2  # invalid entry skipped


def test_urlhaus_network_failure_is_graceful():
    with patch.object(feeds.requests, "get", _mock_get(exc=ConnectionError("down"))):
        res = feeds.fetch_urlhaus()
    assert res.status == "error"
    assert res.iocs == []
    assert "down" in res.error


def test_otx_skipped_without_key():
    res = feeds.fetch_otx(api_key=None)
    assert res.status == "skipped"
    assert res.iocs == []


def test_otx_parses_indicators():
    payload = {"results": [{
        "indicators": [
            {"type": "IPv4", "indicator": "203.0.113.99"},
            {"type": "domain", "indicator": "Bad-Example.COM"},
            {"type": "URL", "indicator": "https://bad-example.com/x"},
            {"type": "FileHash-SHA256", "indicator": SHA},
            {"type": "YARA", "indicator": "rule x {}"},  # unsupported -> skipped
        ]
    }]}
    with patch.object(feeds.requests, "get", _mock_get(payload)):
        res = feeds.fetch_otx(api_key="fake-key")
    assert res.status == "ok"
    by_type = {i.ioc_type: i.value for i in res.iocs}
    assert by_type["ipv4"] == "203.0.113.99"
    assert by_type["domain"] == "bad-example.com"  # normalized lowercase
    assert by_type["url"] == "https://bad-example.com/x"
    assert by_type["sha256"] == SHA


def test_abuseipdb_skipped_without_key():
    res = feeds.fetch_abuseipdb(api_key=None)
    assert res.status == "skipped"


def test_abuseipdb_parses_blacklist():
    payload = {"data": [{"ipAddress": "198.51.100.77"}, {"ipAddress": "not-an-ip"}]}
    with patch.object(feeds.requests, "get", _mock_get(payload)):
        res = feeds.fetch_abuseipdb(api_key="fake-key")
    assert res.status == "ok"
    assert [i.value for i in res.iocs] == ["198.51.100.77"]


def test_fetch_all_never_raises():
    # urlhaus will fail (mocked), keyed feeds skip gracefully
    with patch.object(feeds.requests, "get", _mock_get(exc=TimeoutError())):
        results = feeds.fetch_all(otx_key=None, abuseipdb_key=None)
    assert [r.feed for r in results] == ["urlhaus", "otx", "abuseipdb"]
    assert results[0].status == "error"
    assert results[1].status == "skipped"
    assert results[2].status == "skipped"
