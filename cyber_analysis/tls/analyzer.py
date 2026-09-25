import os
import ssl
import time
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import Dict, Any, List, Optional

from cyber_analysis.models import AnalyzerResult, SecuritySignal, SecuritySeverity
from cyber_analysis.ssrf import validate_url_ssrf

DEFAULT_TLS_TIMEOUT = 4.0


class TLSAnalyzer:
    """Defensive TLS analyzer for inspecting HTTPS server certificates, expiration, and hostname verification."""

    def __init__(self, timeout: Optional[float] = None):
        self.timeout = (
            timeout
            if timeout is not None
            else float(os.getenv("AEGIS_TLS_TIMEOUT", str(DEFAULT_TLS_TIMEOUT)))
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

        target_url = url if "://" in url else "https://" + url
        parsed = urlparse(target_url)

        if parsed.scheme == "http":
            return AnalyzerResult(
                available=True,
                status="not_applicable",
                data={"scheme": "http", "tls_enabled": False},
                signals=[
                    SecuritySignal(
                        source="tls",
                        type="plain_http_no_tls",
                        severity=SecuritySeverity.LOW,
                        description="Target URL uses plain HTTP without TLS encryption",
                        data={},
                    )
                ],
                execution_time_ms=round((time.perf_counter() - start_time) * 1000, 2),
            )

        # SSRF Validation Check
        is_safe, hostname, ssrf_err = validate_url_ssrf(target_url)
        if not is_safe:
            return AnalyzerResult(
                available=False,
                status="ssrf_blocked",
                errors=[ssrf_err or "Destination IP or hostname is restricted (SSRF protection)"],
                execution_time_ms=round((time.perf_counter() - start_time) * 1000, 2),
            )

        port = parsed.port or 443
        signals: List[SecuritySignal] = []
        errors: List[str] = []

        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        tls_version: Optional[str] = None
        cert_data: Dict[str, Any] = {}
        hostname_verified: bool = False

        try:
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as sslsock:
                    tls_version = sslsock.version()
                    cert = sslsock.getpeercert()
                    hostname_verified = True

                    if cert:
                        subject_dict = dict(x[0] for x in cert.get("subject", []))
                        issuer_dict = dict(x[0] for x in cert.get("issuer", []))
                        not_before_str = cert.get("notBefore", "")
                        not_after_str = cert.get("notAfter", "")

                        days_until_expiry: Optional[int] = None
                        if not_after_str:
                            try:
                                exp_date = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                                days_until_expiry = (exp_date - datetime.now(timezone.utc).replace(tzinfo=None)).days
                            except Exception:
                                pass

                        cert_data = {
                            "subject": subject_dict.get("commonName") or str(subject_dict),
                            "issuer": issuer_dict.get("organizationName") or str(issuer_dict),
                            "not_before": not_before_str,
                            "not_after": not_after_str,
                            "days_until_expiry": days_until_expiry,
                        }

                        if days_until_expiry is not None:
                            if days_until_expiry < 0:
                                signals.append(
                                    SecuritySignal(
                                        source="tls",
                                        type="certificate_expired",
                                        severity=SecuritySeverity.HIGH,
                                        description=f"TLS certificate for {hostname} has expired ({abs(days_until_expiry)} days ago)",
                                        data={"days_until_expiry": days_until_expiry},
                                    )
                                )
                            elif days_until_expiry < 14:
                                signals.append(
                                    SecuritySignal(
                                        source="tls",
                                        type="certificate_expiring_soon",
                                        severity=SecuritySeverity.MEDIUM,
                                        description=f"TLS certificate for {hostname} expires soon (in {days_until_expiry} days)",
                                        data={"days_until_expiry": days_until_expiry},
                                    )
                                )

        except ssl.SSLCertVerificationError as e:
            errors.append(f"TLS certificate verification failed: {str(e)}")
            signals.append(
                SecuritySignal(
                    source="tls",
                    type="certificate_verification_failed",
                    severity=SecuritySeverity.HIGH,
                    description=f"TLS certificate verification failed for {hostname}",
                    data={"error": str(e)},
                )
            )
        except (ssl.SSLError, socket.error, socket.timeout) as e:
            err_type = "timeout" if isinstance(e, socket.timeout) else "error"
            errors.append(f"TLS connection error: {str(e)}")
            signals.append(
                SecuritySignal(
                    source="tls",
                    type="tls_connection_failed",
                    severity=SecuritySeverity.MEDIUM,
                    description=f"Could not establish TLS connection to {hostname}:{port}",
                    data={"error": str(e)},
                )
            )
        except Exception as e:
            errors.append(f"Unexpected TLS error: {str(e)}")

        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

        if errors and not tls_version:
            status_str = "timeout" if any("timeout" in err.lower() for err in errors) else "error"
            return AnalyzerResult(
                available=False,
                status=status_str,
                data={"hostname": hostname, "port": port},
                signals=signals,
                errors=errors,
                execution_time_ms=elapsed_ms,
            )

        return AnalyzerResult(
            available=True,
            status="success",
            data={
                "hostname": hostname,
                "port": port,
                "tls_version": tls_version,
                "hostname_verified": hostname_verified,
                "certificate": cert_data,
            },
            signals=signals,
            errors=errors,
            execution_time_ms=elapsed_ms,
        )
