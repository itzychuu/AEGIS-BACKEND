import socket
import ipaddress
from urllib.parse import urlparse
from typing import Tuple, Optional, List

RESTRICTED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),      # Loopback
    ipaddress.ip_network("10.0.0.0/8"),       # Private IPv4 Class A
    ipaddress.ip_network("172.16.0.0/12"),    # Private IPv4 Class B
    ipaddress.ip_network("192.168.0.0/16"),   # Private IPv4 Class C
    ipaddress.ip_network("169.254.0.0/16"),   # Link-Local / Cloud Metadata
    ipaddress.ip_network("0.0.0.0/8"),        # Current network / Default
    ipaddress.ip_network("100.64.0.0/10"),    # Carrier-grade NAT
    ipaddress.ip_network("192.0.2.0/24"),     # TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"),  # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),   # TEST-NET-3
    ipaddress.ip_network("::1/128"),          # IPv6 Loopback
    ipaddress.ip_network("fc00::/7"),         # IPv6 Unique Local
    ipaddress.ip_network("fe80::/10"),        # IPv6 Link-Local
]

RESTRICTED_HOSTNAMES = {
    "localhost",
    "loopback",
    "metadata.google.internal",
    "169.254.169.254",
}

RESTRICTED_TLDS_SUFFIXES = (
    ".local",
    ".internal",
    ".lan",
    ".home",
    ".invalid",
    ".localhost",
)


def is_ip_restricted(ip_str: str) -> bool:
    """Check if an IP address string belongs to a loopback, private, or restricted range."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # If invalid IP, treat as restricted/unsafe

    if ip_obj.is_loopback or ip_obj.is_private or ip_obj.is_link_local or ip_obj.is_reserved or ip_obj.is_unspecified:
        return True

    for net in RESTRICTED_NETWORKS:
        if ip_obj in net:
            return True

    return False


def is_hostname_restricted(hostname: str) -> bool:
    """Check if a hostname string matches restricted internal patterns."""
    if not hostname:
        return True

    h = hostname.lower().strip(".")
    if h in RESTRICTED_HOSTNAMES:
        return True

    if any(h.endswith(suffix) for suffix in RESTRICTED_TLDS_SUFFIXES):
        return True

    # If hostname is an IP string directly, check IP restrictions
    try:
        ipaddress.ip_address(h)
        return is_ip_restricted(h)
    except ValueError:
        pass

    return False


def validate_url_ssrf(url: str, resolve_dns: bool = True) -> Tuple[bool, str, Optional[str]]:
    """Validate a URL against SSRF attacks (checking hostname and resolved IP addresses).

    Args:
        url: The input URL string.
        resolve_dns: Whether to resolve hostname via DNS to verify target IP address.

    Returns:
        Tuple of (is_safe: bool, hostname: str, error_message: Optional[str])
    """
    if not url or not isinstance(url, str):
        return False, "", "URL is empty or invalid"

    try:
        parsed = urlparse(url if "://" in url else "https://" + url)
        hostname = (parsed.hostname or "").lower().strip(".")
    except Exception as e:
        return False, "", f"Failed to parse URL: {str(e)}"

    if not hostname:
        return False, "", "URL contains no valid hostname"

    if is_hostname_restricted(hostname):
        return False, hostname, f"Destination hostname '{hostname}' is restricted (SSRF protection)"

    if resolve_dns:
        try:
            addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            resolved_ips = list(set(info[4][0] for info in addr_info if info[4]))

            if not resolved_ips:
                return False, hostname, f"DNS resolution failed for hostname '{hostname}'"

            for ip in resolved_ips:
                if is_ip_restricted(ip):
                    return False, hostname, f"Hostname '{hostname}' resolved to restricted IP '{ip}' (SSRF protection)"
        except socket.gaierror as e:
            # Resolution failure will be handled gracefully by the DNS analyzer
            pass
        except Exception as e:
            return False, hostname, f"SSRF DNS check error: {str(e)}"

    return True, hostname, None
