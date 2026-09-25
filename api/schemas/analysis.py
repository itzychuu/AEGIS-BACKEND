import os
from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field, field_validator


MAX_URL_LENGTH_DEFAULT = 8192


def get_max_url_length() -> int:
    try:
        return int(os.getenv("AEGIS_MAX_URL_LENGTH", str(MAX_URL_LENGTH_DEFAULT)))
    except ValueError:
        return MAX_URL_LENGTH_DEFAULT


class ClassificationEnum(str, Enum):
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    CRITICAL = "CRITICAL"


class AnalyzeRequest(BaseModel):
    url: str = Field(
        ...,
        description="The URL string to analyze for phishing threats.",
        min_length=1,
    )

    @field_validator("url")
    @classmethod
    def validate_url_string(cls, v: str) -> str:
        if not isinstance(v, str):
            raise ValueError("URL must be a string")
        stripped = v.strip()
        if not stripped:
            raise ValueError("URL string cannot be empty or whitespace-only")
        
        max_len = get_max_url_length()
        if len(stripped) > max_len:
            raise ValueError(f"URL length exceeds maximum allowed length of {max_len} characters")

        # Reject control characters or invalid multiline strings
        if any(ord(c) < 32 for c in stripped):
            raise ValueError("URL contains invalid control characters")

        return stripped


class AnalyzeResponse(BaseModel):
    url: str = Field(..., description="Canonicalized URL analyzed")
    classification: ClassificationEnum = Field(..., description="Final risk classification (SAFE, SUSPICIOUS, CRITICAL)")
    risk_score: int = Field(..., ge=0, le=100, description="Risk score between 0 and 100")
    reasons: List[str] = Field(default_factory=list, description="List of human-readable security risk factors")
    signals: Dict[str, Any] = Field(default_factory=dict, description="Raw feature signals from ML and cybersecurity modules")
    ai: Optional[Dict[str, Any]] = Field(default=None, description="Optional local AI advisory analysis result")
    model_version: str = Field(..., description="Active XGBoost model version")
    cached: bool = Field(..., description="Whether the result was retrieved from Trust Cache")
    analysis_time_ms: float = Field(..., description="Total analysis duration in milliseconds")
