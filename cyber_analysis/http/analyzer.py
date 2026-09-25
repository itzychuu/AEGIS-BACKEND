import os
import time
import socket
import urllib.request
import urllib.error
from urllib.parse import urlparse
from typing import Dict, Any, List, Optional

from cyber_analysis.models import AnalyzerResult, SecuritySignal, SecuritySeverity
from cyber_analysis.ssrf import validate_url_ssrf

DEFAULT_HTTP_TIMEOUT = 5.0
DEFAULT_MAX_RESPONSE_BYTES = 102400  # 100 KB limit
DEFAULT_USER_AGENT = "AegisSecurityScanner/1.0"


class HTTPAnalyzer:
    """Safe, read-only HTTP analyzer for inspecting target URL headers, status code, and HTTP signals."""

    def __init__(
        self,
        timeout: Optional[float] = None,
        max_bytes: Optional[int] = None,
        user_agent: Optional[str] = None,
    ):
        self.timeout = (
            timeout
            if timeout is not None
            else float(os.getenv("AEGIS_HTTP_TIMEOUT", str(DEFAULT_HTTP_TIMEOUT)))
        )
        self.max_bytes = (
            max_bytes
            if max_bytes is not None
            else int(os.getenv("AEGIS_MAX_RESPONSE_BYTES", str(DEFAULT_MAX_RESPONSE_BYTES)))
        )
        self.user_agent = user_agent or DEFAULT_USER_AGENT

    def analyze(self, url: str) -> AnalyzerResult:
        start_time = time.perf_counter()

        if not url or not isinstance(url, str):
            return AnalyzerResult(
                available=False,
                status="error",
                errors=["URL must be a non-empty string"],
                execution_time_ms=0.0,
            )

        # SSRF Validation Check
        is_safe, hostname, ssrf_err = validate_url_ssrf(url)
        if not is_safe:
            return AnalyzerResult(
                available=False,
                status="ssrf_blocked",
                errors=[ssrf_err or "Destination IP or hostname is restricted (SSRF protection)"],
                execution_time_ms=round((time.perf_counter() - start_time) * 1000, 2),
            )

        target_url = url if "://" in url else "https://" + url
        parsed = urlparse(target_url)
        signals: List[SecuritySignal] = []

        if parsed.scheme == "http":
            signals.append(
                SecuritySignal(
                    source="http",
                    type="plain_http",
                    severity=SecuritySeverity.LOW,
                    description="Target URL uses unencrypted HTTP protocol",
                    data={"scheme": "http"},
                )
            )

        req = urllib.request.Request(
            target_url,
            headers={"User-Agent": self.user_agent, "Accept": "*/*"},
            method="GET",
        )

        status_code: Optional[int] = None
        final_url: str = target_url
        content_type: str = ""
        server_header: str = ""
        response_size: int = 0
        error_msg: Optional[str] = None

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                status_code = response.getcode()
                final_url = response.geturl()
                content_type = response.headers.get("Content-Type", "")
                server_header = response.headers.get("Server", "")

                body_chunk = response.read(self.max_bytes)
                response_size = len(body_chunk)

        except urllib.error.HTTPError as e:
            status_code = e.code
            final_url = e.geturl() or target_url
            content_type = e.headers.get("Content-Type", "") if e.headers else ""
            server_header = e.headers.get("Server", "") if e.headers else ""
            signals.append(
                SecuritySignal(
                    source="http",
                    type="http_status_error",
                    severity=SecuritySeverity.INFO,
                    description=f"HTTP request returned status code {status_code}",
                    data={"status_code": status_code},
                )
            )
        except urllib.error.URLError as e:
            if isinstance(e.reason, (socket.timeout, TimeoutError)):
                error_msg = f"HTTP connection timed out after {self.timeout}s"
            else:
                error_msg = f"HTTP connection error: {str(e.reason)}"
        except (socket.timeout, TimeoutError):
            error_msg = f"HTTP connection timed out after {self.timeout}s"
        except Exception as e:
            error_msg = f"Unexpected HTTP error: {str(e)}"

        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

        if error_msg and status_code is None:
            status_str = "timeout" if "timed out" in error_msg.lower() else "error"
            return AnalyzerResult(
                available=False,
                status=status_str,
                data={"url": target_url},
                signals=signals,
                errors=[error_msg],
                execution_time_ms=elapsed_ms,
            )

        return AnalyzerResult(
            available=True,
            status="success",
            data={
                "status_code": status_code,
                "final_url": final_url,
                "content_type": content_type,
                "server": server_header,
                "response_size_bytes": response_size,
                "scheme": parsed.scheme,
            },
            signals=signals,
            errors=[],
            execution_time_ms=elapsed_ms,
        )
