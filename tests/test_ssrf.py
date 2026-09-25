import pytest
from cyber_analysis.ssrf import (
    is_ip_restricted,
    is_hostname_restricted,
    validate_url_ssrf,
)


def test_restricted_ips():
    """Test SSRF IP validation for loopback, private, and metadata IPs."""
    restricted_ips = [
        "127.0.0.1",
        "127.0.0.2",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "0.0.0.0",
        "::1",
    ]
    for ip in restricted_ips:
        assert is_ip_restricted(ip) is True, f"IP {ip} should be restricted"

    public_ips = [
        "93.184.216.34",  # example.com
        "8.8.8.8",         # Google DNS
        "1.1.1.1",         # Cloudflare DNS
        "142.250.190.46",  # Google
    ]
    for ip in public_ips:
        assert is_ip_restricted(ip) is False, f"IP {ip} should be allowed"


def test_restricted_hostnames():
    """Test SSRF hostname validation for local and internal hostnames."""
    restricted_hostnames = [
        "localhost",
        "loopback",
        "169.254.169.254",
        "server.local",
        "admin.internal",
        "router.lan",
        "test.home",
    ]
    for host in restricted_hostnames:
        assert is_hostname_restricted(host) is True, f"Hostname {host} should be restricted"

    public_hostnames = [
        "google.com",
        "example.com",
        "github.com",
        "wikipedia.org",
    ]
    for host in public_hostnames:
        assert is_hostname_restricted(host) is False, f"Hostname {host} should be allowed"


def test_validate_url_ssrf():
    """Test validate_url_ssrf for safe and dangerous URLs without real network calls."""
    is_safe, host, err = validate_url_ssrf("http://127.0.0.1/admin", resolve_dns=False)
    assert is_safe is False
    assert "restricted" in err

    is_safe, host, err = validate_url_ssrf("http://169.254.169.254/latest/meta-data/", resolve_dns=False)
    assert is_safe is False

    is_safe, host, err = validate_url_ssrf("https://example.com", resolve_dns=False)
    assert is_safe is True
    assert host == "example.com"
    assert err is None
