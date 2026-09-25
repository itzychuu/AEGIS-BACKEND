import socket
import pytest
from unittest.mock import patch, MagicMock

from cyber_analysis.dns import DNSAnalyzer


def test_dns_analysis_successful_resolution():
    """Test DNS analyzer with mocked socket.getaddrinfo returning IPv4 and IPv6 records."""
    analyzer = DNSAnalyzer(timeout=1.0)
    fake_addr_info = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:2800:220:1:248:1893:25c8:1946", 0)),
    ]

    with patch("socket.getaddrinfo", return_value=fake_addr_info):
        res = analyzer.analyze("https://example.com")

    assert res.available is True
    assert res.status == "success"
    assert res.data["hostname"] == "example.com"
    assert "93.184.216.34" in res.data["a_records"]
    assert len(res.data["aaaa_records"]) == 1
    assert res.execution_time_ms >= 0.0


def test_dns_analysis_direct_ip_host():
    """Test DNS analyzer detects direct IP host signal."""
    analyzer = DNSAnalyzer(timeout=1.0)
    fake_addr_info = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
    ]

    with patch("socket.getaddrinfo", return_value=fake_addr_info):
        res = analyzer.analyze("http://93.184.216.34/login")

    assert res.available is True
    assert res.data["is_direct_ip"] is True
    assert len(res.signals) == 1
    assert res.signals[0].type == "direct_ip_host"


def test_dns_analysis_resolution_failure():
    """Test DNS analyzer handles gaierror gracefully without crashing."""
    analyzer = DNSAnalyzer(timeout=1.0)

    with patch("socket.getaddrinfo", side_effect=socket.gaierror("Name or service not known")):
        res = analyzer.analyze("https://nonexistent-domain-12345.com")

    assert res.available is False
    assert res.status == "error"
    assert len(res.errors) == 1
    assert len(res.signals) == 1
    assert res.signals[0].type == "dns_resolution_failure"


def test_dns_analysis_timeout():
    """Test DNS analyzer handles socket timeout gracefully."""
    analyzer = DNSAnalyzer(timeout=0.1)

    with patch("socket.getaddrinfo", side_effect=socket.timeout("timed out")):
        res = analyzer.analyze("https://slow-dns.com")

    assert res.available is False
    assert res.status == "timeout"
    assert "timed out" in res.errors[0]


def test_dns_analysis_ssrf_blocked():
    """Test DNS analyzer blocks restricted internal hostnames."""
    analyzer = DNSAnalyzer()
    res = analyzer.analyze("http://127.0.0.1/admin")

    assert res.available is False
    assert res.status == "ssrf_blocked"
    assert "restricted" in res.errors[0]
