import os
import re
import time
import socket
from urllib.parse import urlparse
from typing import Dict, Any, List, Optional

from cyber_analysis.models import AnalyzerResult, SecuritySignal, SecuritySeverity
from cyber_analysis.ssrf import validate_url_ssrf, is_hostname_restricted

DEFAULT_DNS_TIMEOUT = 3.0


class DNSAnalyzer:
    """Defensive DNS analyzer for inspecting domain resolution, A/AAAA records, and IP signals."""

    def __init__(self, timeout: Optional[float] = None):
        self.timeout = (
            timeout
            if timeout is not None
            else float(os.getenv("AEGIS_DNS_TIMEOUT", str(DEFAULT_DNS_TIMEOUT)))
        )

    def analyze(self, url: str) -> AnalyzerResult:
        start_time = time.perf_counter()

        if not url or not isinstance(url, str):
            return AnalyzerResult(
                available=False,
                status="error",
                errors=["URL must be a non-empty string"],
                execution_time_ms=0.0,
            )

        try:
            parsed = urlparse(url if "://" in url else "https://" + url)
            hostname = (parsed.hostname or "").lower().strip(".")
        except Exception as e:
            return AnalyzerResult(
                available=False,
                status="error",
                errors=[f"Failed to parse URL hostname: {str(e)}"],
                execution_time_ms=round((time.perf_counter() - start_time) * 1000, 2),
            )

        if not hostname:
            return AnalyzerResult(
                available=False,
                status="error",
                errors=["URL contains no valid hostname"],
                execution_time_ms=round((time.perf_counter() - start_time) * 1000, 2),
            )

        # SSRF Protection Check
        if is_hostname_restricted(hostname):
            return AnalyzerResult(
                available=False,
                status="ssrf_blocked",
                errors=[f"Hostname '{hostname}' is restricted (SSRF protection)"],
                execution_time_ms=round((time.perf_counter() - start_time) * 1000, 2),
            )

        signals: List[SecuritySignal] = []
        is_direct_ip = bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", hostname))

        if is_direct_ip:
            signals.append(
                SecuritySignal(
                    source="dns",
                    type="direct_ip_host",
                    severity=SecuritySeverity.MEDIUM,
                    description=f"URL uses a raw IP address ({hostname}) as host instead of a domain name",
                    data={"ip": hostname},
                )
            )

        a_records: List[str] = []
        aaaa_records: List[str] = []
        resolved = False
        error_msg: Optional[str] = None

        old_timeout = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(self.timeout)
            addr_info = socket.getaddrinfo(
                hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM
            )
            for family, _, _, _, sockaddr in addr_info:
                ip_addr = sockaddr[0]
                if family == socket.AF_INET and ip_addr not in a_records:
                    a_records.append(ip_addr)
                elif family == socket.AF_INET6 and ip_addr not in aaaa_records:
                    aaaa_records.append(ip_addr)

            resolved = len(a_records) > 0 or len(aaaa_records) > 0
        except socket.timeout:
            error_msg = f"DNS resolution timed out after {self.timeout}s"
        except socket.gaierror as e:
            error_msg = f"DNS resolution failed: {str(e)}"
            signals.append(
                SecuritySignal(
                    source="dns",
                    type="dns_resolution_failure",
                    severity=SecuritySeverity.INFO,
                    description=f"Hostname '{hostname}' could not be resolved via DNS",
                    data={"hostname": hostname, "error": str(e)},
                )
            )
        except Exception as e:
            error_msg = f"Unexpected DNS error: {str(e)}"
        finally:
            socket.setdefaulttimeout(old_timeout)

        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

        if error_msg and not resolved:
            status_str = "timeout" if "timed out" in error_msg else "error"
            return AnalyzerResult(
                available=False,
                status=status_str,
                data={"hostname": hostname, "resolved": False},
                signals=signals,
                errors=[error_msg],
                execution_time_ms=elapsed_ms,
            )

        return AnalyzerResult(
            available=True,
            status="success",
            data={
                "hostname": hostname,
                "resolved": resolved,
                "a_records": a_records,
                "aaaa_records": aaaa_records,
                "is_direct_ip": is_direct_ip,
            },
            signals=signals,
            errors=[],
            execution_time_ms=elapsed_ms,
        )
