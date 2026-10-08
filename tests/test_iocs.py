"""Tests for IOC validation, classification and normalization."""
from engine.iocs import IOC, classify, make_ioc, normalize_value

SHA = "a" * 64


def test_classify_ipv4():
    assert classify("203.0.113.45") == "ipv4"


def test_classify_rejects_ipv6():
    assert classify("2001:db8::1") is None


def test_classify_domain():
    assert classify("evil-update.example") == "domain"


def test_classify_url():
    assert classify("http://evil-update.example/payload.bin") == "url"


def test_classify_sha256():
    assert classify(SHA) == "sha256"


def test_classify_rejects_garbage():
    assert classify("not an ioc!!!") is None
    assert classify("") is None
    assert classify("abc") is None  # too short for sha, no TLD for domain


def test_normalize_lowercases_domains_and_urls():
    assert normalize_value("EVIL-UPDATE.EXAMPLE", "domain") == "evil-update.example"
    assert normalize_value("HTTP://EVIL.EXAMPLE/X/", "url") == "http://evil.example/x"


def test_normalize_strips_trailing_dot_and_slash():
    assert normalize_value("evil.example.", "domain") == "evil.example"
    assert normalize_value("203.0.113.45 ", "ipv4") == "203.0.113.45"


def test_make_ioc_builds_dataclass():
    ioc = make_ioc("EVIL.EXAMPLE", "urlhaus")
    assert isinstance(ioc, IOC)
    assert ioc.value == "evil.example"
    assert ioc.ioc_type == "domain"
    assert ioc.feed == "urlhaus"
    assert ioc.first_seen  # timestamp populated


def test_make_ioc_rejects_invalid():
    assert make_ioc("hello world", "urlhaus") is None


def test_make_ioc_explicit_type():
    ioc = make_ioc("203.0.113.45", "abuseipdb", "ipv4")
    assert ioc is not None and ioc.ioc_type == "ipv4"
