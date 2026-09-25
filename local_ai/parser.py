import re
import json
from typing import Dict, Any, List, Optional

from local_ai.models import AIAnalysisResult, AIStatus
from local_ai.config import AIConfig
from local_ai.exceptions import AIParserError


def extract_json_str(raw_text: str) -> str:
    """Extract valid JSON substring from raw model output text."""
    if not raw_text or not isinstance(raw_text, str):
        raise AIParserError("Raw model text is empty or non-string")

    text = raw_text.strip()

    # Match markdown code block ```json ... ```
    code_block_match = re.search(r"```(?:json)?\s*(\{[\s\S]*?\})\s*```", text, re.IGNORECASE)
    if code_block_match:
        return code_block_match.group(1).strip()

    # Match outermost JSON object braces
    brace_match = re.search(r"(\{[\s\S]*\})", text)
    if brace_match:
        return brace_match.group(1).strip()

    return text


def parse_ai_response(
    raw_text: str,
    provider_name: str,
    model_name: str,
    latency_ms: float,
    config: Optional[AIConfig] = None,
) -> AIAnalysisResult:
    """Parse, validate, and sanitize raw LLM completion output into typed AIAnalysisResult."""
    cfg = config or AIConfig()

    try:
        json_str = extract_json_str(raw_text)
        data = json.loads(json_str)

        if not isinstance(data, dict):
            raise AIParserError(f"Expected JSON object, got {type(data).__name__}")

        def sanitize_str(val: Any, max_len: int) -> str:
            if not val:
                return ""
            s = str(val).strip()
            return s[:max_len]

        def sanitize_list(val: Any, max_items: int, max_len: int) -> List[str]:
            if not isinstance(val, list):
                return []
            res: List[str] = []
            for item in val[:max_items]:
                if item:
                    res.append(str(item).strip()[:max_len])
            return res

        summary = sanitize_str(data.get("summary"), cfg.max_text_length)
        risk_assessment = sanitize_str(data.get("risk_assessment"), cfg.max_text_length)

        key_findings = sanitize_list(data.get("key_findings"), cfg.max_findings, cfg.max_text_length)
        supporting_signals = sanitize_list(data.get("supporting_signals"), cfg.max_findings, cfg.max_text_length)
        conflicting_signals = sanitize_list(data.get("conflicting_signals"), cfg.max_findings, cfg.max_text_length)
        uncertainties = sanitize_list(data.get("uncertainties"), cfg.max_findings, cfg.max_text_length)

        return AIAnalysisResult(
            available=True,
            status=AIStatus.SUCCESS,
            provider=provider_name,
            model=model_name,
            summary=summary,
            risk_assessment=risk_assessment,
            key_findings=key_findings,
            supporting_signals=supporting_signals,
            conflicting_signals=conflicting_signals,
            uncertainties=uncertainties,
            latency_ms=round(latency_ms, 2),
            error=None,
        )

    except Exception as e:
        return AIAnalysisResult(
            available=False,
            status=AIStatus.INVALID_RESPONSE,
            provider=provider_name,
            model=model_name,
            latency_ms=round(latency_ms, 2),
            error=f"Failed to parse AI response JSON: {str(e)}",
        )
