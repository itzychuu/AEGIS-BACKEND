import pytest
from local_ai.parser import extract_json_str, parse_ai_response
from local_ai.models import AIStatus, AIAnalysisResult
from local_ai.config import AIConfig


def test_extract_json_str_raw_and_markdown():
    """1. Test extract_json_str handles plain JSON and markdown codeblocks."""
    plain_json = '{"summary": "test"}'
    assert extract_json_str(plain_json) == '{"summary": "test"}'

    markdown_json = "Here is the result:\n```json\n{\n  \"summary\": \"test\"\n}\n```\nHope that helps!"
    extracted = extract_json_str(markdown_json)
    assert extracted.startswith("{") and extracted.endswith("}")
    assert '"summary": "test"' in extracted


def test_parse_ai_response_valid():
    """2. Test parse_ai_response on valid JSON input."""
    raw = """{
        "summary": "Valid test summary",
        "risk_assessment": "Low risk supported by evidence",
        "key_findings": ["Finding 1", "Finding 2"],
        "supporting_signals": ["ml_probability"],
        "conflicting_signals": [],
        "uncertainties": ["No threat intel"]
    }"""

    res = parse_ai_response(raw, "ollama", "qwen3:4b-instruct", 150.0)

    assert isinstance(res, AIAnalysisResult)
    assert res.available is True
    assert res.status == AIStatus.SUCCESS
    assert res.provider == "ollama"
    assert res.model == "qwen3:4b-instruct"
    assert res.summary == "Valid test summary"
    assert len(res.key_findings) == 2
    assert res.latency_ms == 150.0


def test_parse_ai_response_malformed_json():
    """3. Test parse_ai_response handles malformed JSON without crashing."""
    raw = "NOT_VALID_JSON_AT_ALL {{{{"
    res = parse_ai_response(raw, "ollama", "qwen3:4b-instruct", 50.0)

    assert res.available is False
    assert res.status == AIStatus.INVALID_RESPONSE
    assert "Failed to parse" in res.error


def test_parse_ai_response_sanitization_and_limits():
    """4. Test string length truncation and findings capping."""
    cfg = AIConfig(max_findings=2, max_text_length=10)
    raw = """{
        "summary": "This summary is way too long for the cap",
        "key_findings": ["F1", "F2", "F3", "F4"]
    }"""

    res = parse_ai_response(raw, "fake", "fake-model", 10.0, config=cfg)

    assert res.available is True
    assert len(res.summary) == 10
    assert len(res.key_findings) == 2  # Capped at max_findings
