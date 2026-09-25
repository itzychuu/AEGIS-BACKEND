import socket
import urllib.error
import pytest
from unittest.mock import patch, MagicMock

from cyber_analysis.http import HTTPAnalyzer


def test_http_analysis_success():
    """Test HTTP analyzer on successful 200 response."""
    analyzer = HTTPAnalyzer(timeout=1.0)
    mock_resp = MagicMock()
    mock_resp.__enter__.return_value = mock_resp
    mock_resp.getcode.return_value = 200
    mock_resp.geturl.return_value = "https://example.com/"
    mock_resp.headers = {"Content-Type": "text/html", "Server": "ECS"}
    mock_resp.read.return_value = b"<html>Test</html>"

    with patch("cyber_analysis.http.analyzer.validate_url_ssrf", return_value=(True, "example.com", None)):
        with patch("urllib.request.urlopen", return_value=mock_resp):
            res = analyzer.analyze("https://example.com")

    assert res.available is True
    assert res.status == "success"
    assert res.data["status_code"] == 200
    assert res.data["content_type"] == "text/html"
    assert res.data["response_size_bytes"] == len(b"<html>Test</html>")


def test_http_analysis_plain_http_signal():
    """Test HTTP analyzer emits plain_http signal for unencrypted URLs."""
    analyzer = HTTPAnalyzer(timeout=1.0)
    mock_resp = MagicMock()
    mock_resp.__enter__.return_value = mock_resp
    mock_resp.getcode.return_value = 200
    mock_resp.geturl.return_value = "http://example.com/"
    mock_resp.headers = {}
    mock_resp.read.return_value = b"OK"

    with patch("cyber_analysis.http.analyzer.validate_url_ssrf", return_value=(True, "example.com", None)):
        with patch("urllib.request.urlopen", return_value=mock_resp):
            res = analyzer.analyze("http://example.com")

    assert res.available is True
    assert len(res.signals) == 1
    assert res.signals[0].type == "plain_http"


def test_http_analysis_404_error():
    """Test HTTP analyzer handles 404 HTTPError cleanly."""
    analyzer = HTTPAnalyzer(timeout=1.0)
    http_err = urllib.error.HTTPError(
        url="https://example.com/notfound",
        code=404,
        msg="Not Found",
        hdrs={},
        fp=None
    )

    with patch("cyber_analysis.http.analyzer.validate_url_ssrf", return_value=(True, "example.com", None)):
        with patch("urllib.request.urlopen", side_effect=http_err):
            res = analyzer.analyze("https://example.com/notfound")

    assert res.available is True
    assert res.data["status_code"] == 404
    assert len(res.signals) == 1
    assert res.signals[0].type == "http_status_error"


def test_http_analysis_timeout():
    """Test HTTP analyzer handles connection timeout."""
    analyzer = HTTPAnalyzer(timeout=0.1)
    timeout_err = socket.timeout("timed out")

    with patch("cyber_analysis.http.analyzer.validate_url_ssrf", return_value=(True, "example.com", None)):
        with patch("urllib.request.urlopen", side_effect=timeout_err):
            res = analyzer.analyze("https://slow-site.com")

    assert res.available is False
    assert res.status == "timeout"
    assert "timed out" in res.errors[0]


def test_http_analysis_ssrf_blocked():
    """Test HTTP analyzer blocks restricted internal destinations."""
    analyzer = HTTPAnalyzer()
    res = analyzer.analyze("http://169.254.169.254/latest/meta-data/")

    assert res.available is False
    assert res.status == "ssrf_blocked"
