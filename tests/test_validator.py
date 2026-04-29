import pytest
from unittest.mock import patch
from app.errors import InvalidTargetError, DisallowedTargetError
from app.services.validator import validate_target, validate_target_structural


# --- Valid structural inputs ---

def test_valid_hostname():
    assert validate_target("scanme.nmap.org") == "scanme.nmap.org"

def test_valid_ipv4():
    assert validate_target("45.33.32.156") == "45.33.32.156"

def test_valid_ipv6():
    result = validate_target("2001:db8::1")
    assert result == "2001:db8::1"

def test_hostname_normalised_lowercase():
    assert validate_target("ScanMe.Nmap.Org") == "scanme.nmap.org"


# --- Invalid structural inputs ---

def test_empty_string():
    with pytest.raises(InvalidTargetError):
        validate_target("")

def test_whitespace_only():
    with pytest.raises(InvalidTargetError):
        validate_target("   ")

def test_hyphen_prefix_double():
    with pytest.raises(InvalidTargetError) as exc_info:
        validate_target("--script=malicious")
    assert exc_info.value.target == "--script=malicious"

def test_hyphen_prefix_single():
    with pytest.raises(InvalidTargetError):
        validate_target("-sV")

def test_uri_scheme_http():
    with pytest.raises(InvalidTargetError):
        validate_target("http://example.com")

def test_uri_scheme_https():
    with pytest.raises(InvalidTargetError):
        validate_target("https://example.com")

def test_uri_scheme_ftp():
    with pytest.raises(InvalidTargetError):
        validate_target("ftp://example.com")

def test_hostname_label_too_long():
    with pytest.raises(InvalidTargetError):
        validate_target("a" * 64 + ".com")

def test_hostname_total_too_long():
    label = "a" * 63
    long_host = ".".join([label] * 5)  # > 253 chars
    with pytest.raises(InvalidTargetError):
        validate_target(long_host)

def test_hostname_invalid_chars():
    with pytest.raises(InvalidTargetError):
        validate_target("bad_host!.com")

def test_hostname_label_starts_with_hyphen():
    with pytest.raises(InvalidTargetError):
        validate_target("-bad.com")


# --- Policy: always blocked ---

def test_localhost_string():
    with pytest.raises(DisallowedTargetError):
        validate_target("localhost")

def test_loopback_ipv4():
    with pytest.raises(DisallowedTargetError):
        validate_target("127.0.0.1")

def test_loopback_ipv4_other():
    with pytest.raises(DisallowedTargetError):
        validate_target("127.0.0.2")

def test_loopback_ipv6():
    with pytest.raises(DisallowedTargetError):
        validate_target("::1")

def test_link_local():
    with pytest.raises(DisallowedTargetError):
        validate_target("169.254.1.1")


# --- Policy: RFC 1918 controlled by BLOCK_PRIVATE_RANGES ---

def test_private_range_allowed_by_default(monkeypatch):
    monkeypatch.setattr("app.services.validator.settings.BLOCK_PRIVATE_RANGES", False)
    assert validate_target("10.0.0.1") == "10.0.0.1"

def test_private_10_blocked_when_enabled(monkeypatch):
    monkeypatch.setattr("app.services.validator.settings.BLOCK_PRIVATE_RANGES", True)
    with pytest.raises(DisallowedTargetError):
        validate_target("10.0.0.1")

def test_private_172_blocked_when_enabled(monkeypatch):
    monkeypatch.setattr("app.services.validator.settings.BLOCK_PRIVATE_RANGES", True)
    with pytest.raises(DisallowedTargetError):
        validate_target("172.16.0.1")

def test_private_192_blocked_when_enabled(monkeypatch):
    monkeypatch.setattr("app.services.validator.settings.BLOCK_PRIVATE_RANGES", True)
    with pytest.raises(DisallowedTargetError):
        validate_target("192.168.1.1")

def test_private_allowed_when_disabled(monkeypatch):
    monkeypatch.setattr("app.services.validator.settings.BLOCK_PRIVATE_RANGES", False)
    assert validate_target("192.168.1.1") == "192.168.1.1"


# --- Structural-only validator used by GET endpoints ---

def test_structural_valid():
    assert validate_target_structural("example.com") == "example.com"

def test_structural_allows_private_ip():
    assert validate_target_structural("10.0.0.1") == "10.0.0.1"

def test_structural_rejects_hyphen():
    with pytest.raises(InvalidTargetError):
        validate_target_structural("--flag")
