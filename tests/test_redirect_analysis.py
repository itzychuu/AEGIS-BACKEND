import urllib.error
import pytest
from unittest.mock import patch, MagicMock

from cyber_analysis.redirects import RedirectAnalyzer


def test_redirect_analysis_zero_redirects():
    """Test redirect analyzer when target returns 200 without redirects."""
    analyzer = RedirectAnalyzer(max_redirects=5)
    mock_resp = MagicMock()

    with patch("cyber_analysis.redirects.analyzer.validate_url_ssrf", return_value=(True, "example.com", None)):
        with patch("urllib.request.build_opener") as mock_builder:
            mock_opener = MagicMock()
            mock_opener.open.return_value.__enter__.return_value = mock_resp
            mock_builder.return_value = mock_opener

            res = analyzer.analyze("https://example.com")

    assert res.available is True
    assert res.data["redirect_count"] == 0
    assert res.data["final_url"] == "https://example.com"
    assert len(res.signals) == 0


def test_redirect_analysis_chain_and_downgrade():
    """Test redirect analyzer tracks redirect chain and detects HTTPS -> HTTP downgrade."""
    analyzer = RedirectAnalyzer(max_redirects=5)

    err_302 = urllib.error.HTTPError(
        url="https://site1.com",
        code=302,
        msg="Found",
        hdrs={"Location": "http://site2.com/login"},  # Downgrade to HTTP
        fp=None
    )
    mock_resp_200 = MagicMock()

    def mock_open(req, timeout=None):
        if req.full_url == "https://site1.com":
            raise err_302
        return mock_resp_200

    with patch("cyber_analysis.redirects.analyzer.validate_url_ssrf", return_value=(True, "site1.com", None)):
        with patch("urllib.request.build_opener") as mock_builder:
            mock_opener = MagicMock()
            mock_opener.open.side_effect = mock_open
            mock_builder.return_value = mock_opener

            res = analyzer.analyze("https://site1.com")

    assert res.available is True
    assert res.data["redirect_count"] == 1
    assert res.data["final_url"] == "http://site2.com/login"
    assert res.data["hostname_changes"] == 1
    assert res.data["scheme_changes"] == 1

    # Emits downgrade signal
    downgrade_signals = [s for s in res.signals if s.type == "https_to_http_downgrade"]
    assert len(downgrade_signals) == 1


def test_redirect_analysis_loop_detection():
    """Test redirect analyzer detects circular redirect loop."""
    analyzer = RedirectAnalyzer(max_redirects=5)

    err_loop = urllib.error.HTTPError(
        url="https://loop.com/a",
        code=301,
        msg="Moved Permanently",
        hdrs={"Location": "https://loop.com/a"},  # Loop to self
        fp=None
    )

    with patch("cyber_analysis.redirects.analyzer.validate_url_ssrf", return_value=(True, "loop.com", None)):
        with patch("urllib.request.build_opener") as mock_builder:
            mock_opener = MagicMock()
            mock_opener.open.side_effect = err_loop
            mock_builder.return_value = mock_opener

            res = analyzer.analyze("https://loop.com/a")

    loop_signals = [s for s in res.signals if s.type == "redirect_loop_detected"]
    assert len(loop_signals) == 1


def test_redirect_analysis_ssrf_blocked_in_chain():
    """Test redirect analyzer blocks redirecting to internal/restricted destination."""
    analyzer = RedirectAnalyzer(max_redirects=5)

    err_ssrf_redirect = urllib.error.HTTPError(
        url="https://public-site.com",
        code=302,
        msg="Found",
        hdrs={"Location": "http://169.254.169.254/latest/meta-data/"},  # Dangerous SSRF redirect
        fp=None
    )

    # First hop safe, second hop blocked by SSRF
    def mock_ssrf_check(url):
        if "169.254" in url:
            return False, "169.254.169.254", "Restricted IP"
        return True, "public-site.com", None

    with patch("cyber_analysis.redirects.analyzer.validate_url_ssrf", side_effect=mock_ssrf_check):
        with patch("urllib.request.build_opener") as mock_builder:
            mock_opener = MagicMock()
            mock_opener.open.side_effect = err_ssrf_redirect
            mock_builder.return_value = mock_opener

            res = analyzer.analyze("https://public-site.com")

    blocked_signals = [s for s in res.signals if s.type == "ssrf_redirect_blocked"]
    assert len(blocked_signals) == 1
