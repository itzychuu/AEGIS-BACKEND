import ssl
import socket
import pytest
from unittest.mock import patch, MagicMock

from cyber_analysis.tls import TLSAnalyzer


def test_tls_analysis_not_applicable_for_http():
    """Test TLS analyzer returns not_applicable for plain HTTP URLs."""
    analyzer = TLSAnalyzer()
    res = analyzer.analyze("http://example.com")

    assert res.available is True
    assert res.status == "not_applicable"
    assert len(res.signals) == 1
    assert res.signals[0].type == "plain_http_no_tls"


def test_tls_analysis_success():
    """Test TLS analyzer with mocked SSL socket returning valid cert."""
    analyzer = TLSAnalyzer(timeout=1.0)
    mock_sslsock = MagicMock()
    mock_sslsock.version.return_value = "TLSv1.3"
    mock_sslsock.getpeercert.return_value = {
        "subject": ((("commonName", "example.com"),),),
        "issuer": ((("organizationName", "DigiCert Inc"),),),
        "notBefore": "Jan 01 00:00:00 2026 GMT",
        "notAfter": "Dec 31 23:59:59 2026 GMT",
    }

    mock_sock = MagicMock()
    mock_ctx = MagicMock()
    mock_ctx.wrap_socket.return_value.__enter__.return_value = mock_sslsock

    with patch("cyber_analysis.tls.analyzer.validate_url_ssrf", return_value=(True, "example.com", None)):
        with patch("socket.create_connection", return_value=mock_sock):
            with patch("ssl.create_default_context", return_value=mock_ctx):
                res = analyzer.analyze("https://example.com")

    assert res.available is True
    assert res.status == "success"
    assert res.data["tls_version"] == "TLSv1.3"
    assert res.data["hostname_verified"] is True
    assert res.data["certificate"]["subject"] == "example.com"
    assert res.data["certificate"]["issuer"] == "DigiCert Inc"


def test_tls_analysis_expired_cert_signal():
    """Test TLS analyzer emits certificate_expired signal for past expiration date."""
    analyzer = TLSAnalyzer(timeout=1.0)
    mock_sslsock = MagicMock()
    mock_sslsock.version.return_value = "TLSv1.2"
    mock_sslsock.getpeercert.return_value = {
        "subject": ((("commonName", "expired.com"),),),
        "issuer": ((("organizationName", "Test CA"),),),
        "notBefore": "Jan 01 00:00:00 2020 GMT",
        "notAfter": "Jan 01 00:00:00 2021 GMT",  # Expired
    }

    mock_sock = MagicMock()
    mock_ctx = MagicMock()
    mock_ctx.wrap_socket.return_value.__enter__.return_value = mock_sslsock

    with patch("cyber_analysis.tls.analyzer.validate_url_ssrf", return_value=(True, "expired.com", None)):
        with patch("socket.create_connection", return_value=mock_sock):
            with patch("ssl.create_default_context", return_value=mock_ctx):
                res = analyzer.analyze("https://expired.com")

    assert res.available is True
    assert len(res.signals) == 1
    assert res.signals[0].type == "certificate_expired"


def test_tls_analysis_verification_error():
    """Test TLS analyzer handles SSLCertVerificationError gracefully."""
    analyzer = TLSAnalyzer(timeout=1.0)
    cert_err = ssl.SSLCertVerificationError("certificate verify failed: self-signed certificate")

    mock_sock = MagicMock()
    mock_ctx = MagicMock()
    mock_ctx.wrap_socket.side_effect = cert_err

    with patch("cyber_analysis.tls.analyzer.validate_url_ssrf", return_value=(True, "self-signed.com", None)):
        with patch("socket.create_connection", return_value=mock_sock):
            with patch("ssl.create_default_context", return_value=mock_ctx):
                res = analyzer.analyze("https://self-signed.com")

    assert res.available is False
    assert res.status == "error"
    assert len(res.signals) == 1
    assert res.signals[0].type == "certificate_verification_failed"


def test_tls_analysis_ssrf_blocked():
    """Test TLS analyzer blocks restricted destinations."""
    analyzer = TLSAnalyzer()
    res = analyzer.analyze("https://127.0.0.1:8443")

    assert res.available is False
    assert res.status == "ssrf_blocked"
