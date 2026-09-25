from typing import Dict, Any
from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: str = Field(default="ok", description="Health status of service")
    service: str = Field(default="aegis-backend", description="Service identifier")
    version: str = Field(default="1.0.0", description="Backend version")


class ReadinessChecks(BaseModel):
    ml_model: str = Field(..., description="ML model readiness (ready/not_ready)")
    cyber_analysis: str = Field(..., description="Cybersecurity orchestrator readiness (ready/disabled)")
    local_ai: str = Field(..., description="Local AI status (available/unavailable/disabled/model_not_found)")


class ReadinessResponse(BaseModel):
    status: str = Field(..., description="Overall service readiness (ready/degraded/not_ready)")
    checks: ReadinessChecks = Field(..., description="Subsystem readiness breakdown")
