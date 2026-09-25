import os
import time
import urllib.request
import urllib.error
from urllib.parse import urlparse, urljoin
from typing import Dict, Any, List, Optional, Set

from cyber_analysis.models import AnalyzerResult, SecuritySignal, SecuritySeverity
from cyber_analysis.ssrf import validate_url_ssrf

DEFAULT_MAX_REDIRECTS = 5
DEFAULT_REDIRECT_TIMEOUT = 5.0


class HTTPNoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Custom handler to catch redirect responses without automatically following them."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # Stop automatic redirect following


class RedirectAnalyzer:
    """Defensive redirect analyzer for step-by-step redirect chain tracking and downgrade detection."""

    def __init__(
        self,
        max_redirects: Optional[int] = None,
        timeout: Optional[float] = None,
        user_agent: str = "AegisSecurityScanner/1.0",
    ):
        self.max_redirects = (
            max_redirects
            if max_redirects is not None
            else int(os.getenv("AEGIS_MAX_REDIRECTS", str(DEFAULT_MAX_REDIRECTS)))
        )
        self.timeout = (
            timeout
            if timeout is not None
            else float(os.getenv("AEGIS_REDIRECT_TIMEOUT", str(DEFAULT_REDIRECT_TIMEOUT)))
        )
        self.user_agent = user_agent

    def analyze(self, url: str) -> AnalyzerResult:
        start_time = time.perf_counter()

        if not url or not isinstance(url, str):
            return AnalyzerResult(
                available=False,
                status="error",
                errors=["URL must be a non-empty string"],
                execution_time_ms=0.0,
            )

        current_url = url if "://" in url else "https://" + url
        original_url = current_url
        redirect_chain: List[str] = [current_url]
        visited_urls: Set[str] = {current_url}
        signals: List[SecuritySignal] = []

        opener = urllib.request.build_opener(HTTPNoRedirectHandler)

        redirect_count = 0
        hostname_changes = 0
        scheme_changes = 0
        previous_hostname = (urlparse(current_url).hostname or "").lower()
        previous_scheme = urlparse(current_url).scheme.lower()
        error_msg: Optional[str] = None

        while redirect_count < self.max_redirects:
            # SSRF check at EACH hop
            is_safe, hostname, ssrf_err = validate_url_ssrf(current_url)
            if not is_safe:
                signals.append(
                    SecuritySignal(
                        source="redirect",
                        type="ssrf_redirect_blocked",
                        severity=SecuritySeverity.HIGH,
                        description=f"Redirect chain attempted to access restricted endpoint: {ssrf_err}",
                        data={"url": current_url, "error": ssrf_err},
                    )
                )
                error_msg = f"Redirect blocked by SSRF protection at hop {redirect_count}: {ssrf_err}"
                break

            req = urllib.request.Request(
                current_url,
                headers={"User-Agent": self.user_agent, "Accept": "*/*"},
                method="HEAD",
            )

            try:
                with opener.open(req, timeout=self.timeout) as resp:
                    # 200 OK or non-redirect status -> end of chain
                    break
            except urllib.error.HTTPError as e:
                if e.code in (301, 302, 303, 307, 308):
                    location = e.headers.get("Location")
                    if not location:
                        break

                    next_url = urljoin(current_url, location)

                    # Loop detection
                    if next_url in visited_urls:
                        signals.append(
                            SecuritySignal(
                                source="redirect",
                                type="redirect_loop_detected",
                                severity=SecuritySeverity.MEDIUM,
                                description="Redirect chain encountered a circular redirect loop",
                                data={"loop_url": next_url},
                            )
                        )
                        break

                    redirect_count += 1
                    redirect_chain.append(next_url)
                    visited_urls.add(next_url)

                    next_parsed = urlparse(next_url)
                    next_hostname = (next_parsed.hostname or "").lower()
                    next_scheme = next_parsed.scheme.lower()

                    if next_hostname != previous_hostname:
                        hostname_changes += 1

                    if previous_scheme == "https" and next_scheme == "http":
                        scheme_changes += 1
                        signals.append(
                            SecuritySignal(
                                source="redirect",
                                type="https_to_http_downgrade",
                                severity=SecuritySeverity.HIGH,
                                description=f"HTTPS to HTTP downgrade detected during redirect to {next_url}",
                                data={"from": current_url, "to": next_url},
                            )
                        )

                    previous_hostname = next_hostname
                    previous_scheme = next_scheme
                    current_url = next_url
                else:
                    break
            except Exception as e:
                error_msg = f"Redirect inspection error at hop {redirect_count}: {str(e)}"
                break

        if redirect_count > 3:
            signals.append(
                SecuritySignal(
                    source="redirect",
                    type="excessive_redirects",
                    severity=SecuritySeverity.MEDIUM,
                    description=f"URL performed an excessive number of redirects ({redirect_count})",
                    data={"redirect_count": redirect_count},
                )
            )

        if hostname_changes > 1:
            signals.append(
                SecuritySignal(
                    source="redirect",
                    type="cross_domain_redirect",
                    severity=SecuritySeverity.INFO,
                    description=f"URL redirected across {hostname_changes} different hostnames",
                    data={"hostname_changes": hostname_changes},
                )
            )

        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

        return AnalyzerResult(
            available=error_msg is None or redirect_count > 0,
            status="success" if not error_msg else "error",
            data={
                "original_url": original_url,
                "final_url": current_url,
                "redirect_count": redirect_count,
                "redirect_chain": redirect_chain,
                "hostname_changes": hostname_changes,
                "scheme_changes": scheme_changes,
            },
            signals=signals,
            errors=[error_msg] if error_msg else [],
            execution_time_ms=elapsed_ms,
        )
