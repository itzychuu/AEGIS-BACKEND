import os
from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass, field

from .exceptions import DecisionError

DEFAULT_SAFE_THRESHOLD = 30
DEFAULT_CRITICAL_THRESHOLD = 80


@dataclass
class DecisionConfig:
    """Centralized, configurable decision thresholds for classification."""
    safe_threshold: int = field(
        default_factory=lambda: int(
            os.getenv("AEGIS_SAFE_THRESHOLD", str(DEFAULT_SAFE_THRESHOLD))
        )
    )
    critical_threshold: int = field(
        default_factory=lambda: int(
            os.getenv("AEGIS_CRITICAL_THRESHOLD", str(DEFAULT_CRITICAL_THRESHOLD))
        )
    )

    def __post_init__(self):
        if not (0 <= self.safe_threshold < self.critical_threshold <= 100):
            raise ValueError(
                f"Invalid decision thresholds: safe_threshold ({self.safe_threshold}) "
                f"must be less than critical_threshold ({self.critical_threshold}) "
                f"and both within range [0, 100]."
            )


def classify_risk(
    risk_score: int, config: Optional[DecisionConfig] = None
) -> str:
    """Classify a 0-100 risk score into SAFE, SUSPICIOUS, or CRITICAL.

    Args:
        risk_score: Calculated risk score (0-100).
        config: Optional DecisionConfig for custom thresholds.

    Returns:
        One of exact strings: 'SAFE', 'SUSPICIOUS', 'CRITICAL'.

    Raises:
        DecisionError: If risk_score is invalid or not between 0 and 100.
    """
    if not isinstance(risk_score, (int, float)) or isinstance(risk_score, bool):
        raise DecisionError(
            f"risk_score must be a numeric integer, got {type(risk_score).__name__}"
        )

    if not (0 <= risk_score <= 100):
        raise DecisionError(
            f"risk_score must be between 0 and 100 inclusive, got {risk_score}"
        )

    cfg = config or DecisionConfig()

    if risk_score < cfg.safe_threshold:
        return "SAFE"
    elif risk_score < cfg.critical_threshold:
        return "SUSPICIOUS"
    else:
        return "CRITICAL"


def generate_reasons(
    classification: str,
    risk_score: int,
    ml_result: Dict[str, Any],
    security_signals: Optional[Union[List[Any], Dict[str, Any]]] = None,
) -> List[str]:
    """Generate human-readable, evidence-backed explanation strings based on analysis signals."""
    reasons: List[str] = []

    # 1. Base ML reason
    if classification == "SAFE":
        reasons.append("Low phishing probability from the ML model.")
    elif classification == "SUSPICIOUS":
        reasons.append("The ML model indicates a moderate phishing risk.")
    elif classification == "CRITICAL":
        reasons.append("The ML model indicates a high phishing risk.")

    # 2. Add explicit descriptions from cybersecurity signals if present
    if security_signals:
        signal_list: List[Any] = []
        if isinstance(security_signals, list):
            signal_list = security_signals
        elif isinstance(security_signals, dict) and "signals" in security_signals:
            signal_list = security_signals.get("signals", [])

        for sig in signal_list:
            desc = None
            if hasattr(sig, "description"):
                desc = sig.description
            elif isinstance(sig, dict):
                desc = sig.get("description")

            if desc and desc not in reasons:
                reasons.append(desc)

    return reasons
