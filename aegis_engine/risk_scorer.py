import math
from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass, field

from .exceptions import RiskScoringError

SIGNAL_WEIGHTS = {
    "known_malicious_match": 50,
    "allowlisted_domain": -30,
    "certificate_verification_failed": 25,
    "hostname_mismatch": 25,
    "certificate_expired": 20,
    "direct_ip_host": 15,
    "https_to_http_downgrade": 15,
    "excessive_redirects": 10,
    "plain_http": 5,
}


@dataclass
class RiskScoreResult:
    """Internal representation of calculated risk score and evidence."""
    score: int
    source: str = "ml_plus_cybersec"
    details: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not (0 <= self.score <= 100):
            raise ValueError(f"Risk score must be between 0 and 100, got {self.score}")


def calculate_risk_score(
    ml_result: Dict[str, Any],
    security_signals: Optional[Union[List[Any], Dict[str, Any]]] = None,
) -> RiskScoreResult:
    """Calculate normalized risk score (0-100) combining ML probability and security signals.

    Args:
        ml_result: Output dictionary from Phase 1 predict_url().
        security_signals: List of SecuritySignal objects or dict of signals from Phase 3 cyber analysis.

    Returns:
        RiskScoreResult containing integer risk score (0-100) and evidence details.

    Raises:
        RiskScoringError: If ml_result is invalid, missing probability, or NaN/Inf.
    """
    if not isinstance(ml_result, dict):
        raise RiskScoringError(
            f"Expected ml_result to be a dict, got {type(ml_result).__name__}"
        )

    if "probability" not in ml_result:
        raise RiskScoringError("ml_result dictionary is missing 'probability' field")

    raw_prob = ml_result["probability"]

    if not isinstance(raw_prob, (int, float)) or isinstance(raw_prob, bool):
        raise RiskScoringError(
            f"ML probability must be a numeric float, got {type(raw_prob).__name__}"
        )

    if math.isnan(raw_prob) or math.isinf(raw_prob):
        raise RiskScoringError(f"Invalid ML probability value: {raw_prob}")

    clamped_prob = max(0.0, min(1.0, float(raw_prob)))
    base_score = round(clamped_prob * 100)

    signal_adjustment = 0
    signal_list: List[Any] = []

    if security_signals:
        if isinstance(security_signals, list):
            signal_list = security_signals
        elif isinstance(security_signals, dict) and "signals" in security_signals:
            signal_list = security_signals.get("signals", [])

        for sig in signal_list:
            sig_type = None
            if hasattr(sig, "type"):
                sig_type = sig.type
            elif isinstance(sig, dict):
                sig_type = sig.get("type")

            if sig_type and sig_type in SIGNAL_WEIGHTS:
                signal_adjustment += SIGNAL_WEIGHTS[sig_type]

    final_score = base_score + signal_adjustment
    final_score = max(0, min(100, final_score))

    details = {
        "ml_probability": ml_result.get("probability"),
        "ml_prediction": ml_result.get("prediction"),
        "ml_label": ml_result.get("label"),
        "base_ml_score": base_score,
        "signal_adjustment": signal_adjustment,
        "signal_count": len(signal_list),
    }

    if security_signals:
        details["security_signals"] = [
            s.to_dict() if hasattr(s, "to_dict") else s for s in signal_list
        ]

    return RiskScoreResult(score=final_score, source="ml_plus_cybersec", details=details)
