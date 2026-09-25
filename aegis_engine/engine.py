import os
import time
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, asdict

from ml_model import predict_url, normalize_url, MODEL_VERSION
from ml_model.exceptions import InvalidURLError
from cache import MemoryCache
from cyber_analysis import CyberOrchestrator, CyberAnalysisResult
from local_ai import LocalAIAnalyzer, AIAnalysisResult
from .risk_scorer import calculate_risk_score
from .decision_engine import DecisionConfig, classify_risk, generate_reasons
from .exceptions import EngineError


@dataclass
class AnalysisResult:
    """Standard contract for Aegis Engine analysis output."""
    url: str
    classification: str
    risk_score: int
    cached: bool
    reasons: List[str]
    signals: Dict[str, Any]
    model_version: str
    analysis_time_ms: float
    ai: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert result object to dictionary."""
        return asdict(self)


class AegisEngine:
    """Central orchestration engine for AEGIS phishing prevention analysis."""

    def __init__(
        self,
        cache: Optional[MemoryCache] = None,
        decision_config: Optional[DecisionConfig] = None,
        predictor_fn: Optional[Callable[[str], Dict[str, Any]]] = None,
        cyber_orchestrator: Optional[CyberOrchestrator] = None,
        enable_cyber_analysis: Optional[bool] = None,
        ai_analyzer: Optional[LocalAIAnalyzer] = None,
        enable_ai: Optional[bool] = None,
    ):
        self.cache = cache if cache is not None else MemoryCache()
        self.decision_config = decision_config or DecisionConfig()
        self.predictor_fn = predictor_fn or predict_url
        self.cyber_orchestrator = cyber_orchestrator or CyberOrchestrator()

        if enable_cyber_analysis is not None:
            self.enable_cyber_analysis = enable_cyber_analysis
        elif cyber_orchestrator is not None:
            self.enable_cyber_analysis = True
        else:
            self.enable_cyber_analysis = (
                os.getenv("AEGIS_CYBER_ANALYSIS_ENABLED", "false").lower() == "true"
            )

        self.ai_analyzer = ai_analyzer or LocalAIAnalyzer()
        if enable_ai is not None:
            self.enable_ai = enable_ai
        elif ai_analyzer is not None:
            self.enable_ai = True
        else:
            self.enable_ai = (
                os.getenv("AEGIS_AI_ENABLED", "false").lower() == "true"
            )

    def analyze(
        self,
        url: str,
        force_cyber_analysis: Optional[bool] = None,
        force_ai_analysis: Optional[bool] = None,
    ) -> AnalysisResult:
        """Run complete Aegis security analysis on the provided URL.

        Args:
            url: The input URL string.
            force_cyber_analysis: Override whether deep cybersecurity analysis is executed.
            force_ai_analysis: Override whether Local AI context analysis is executed.

        Returns:
            AnalysisResult with classification, risk_score, reasons, signals, ai, etc.

        Raises:
            InvalidURLError: If the input URL is empty, None, or non-string.
            EngineError / MLError: If analysis or prediction fails (Never fails open).
        """
        if url is None or not isinstance(url, str):
            raise InvalidURLError(
                f"URL must be a non-empty string, got {type(url).__name__}"
            )

        if not url.strip():
            raise InvalidURLError("URL string cannot be empty or whitespace-only")

        canonical_url = normalize_url(url)
        start_time = time.perf_counter()
        active_version = MODEL_VERSION

        # 1. Trust Cache lookup
        cached_data = self.cache.get(
            canonical_url, active_model_version=active_version
        )
        if cached_data is not None:
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return AnalysisResult(
                url=canonical_url,
                classification=cached_data["classification"],
                risk_score=cached_data["risk_score"],
                cached=True,
                reasons=list(cached_data.get("reasons", [])),
                signals=dict(cached_data.get("signals", {})),
                model_version=cached_data.get("model_version", active_version),
                analysis_time_ms=elapsed_ms,
                ai=cached_data.get("ai"),
            )

        # 2. Phase 1 ML Analysis (Cache Miss)
        ml_result = self.predictor_fn(url)

        if not isinstance(ml_result, dict):
            raise EngineError(
                f"Predictor returned invalid result type: {type(ml_result).__name__}"
            )

        # 3. Optional Deep Cybersecurity Analysis
        should_run_cyber = (
            force_cyber_analysis
            if force_cyber_analysis is not None
            else self.enable_cyber_analysis
        )

        cyber_result: Optional[CyberAnalysisResult] = None
        cyber_signals: List[Any] = []

        if should_run_cyber:
            try:
                cyber_result = self.cyber_orchestrator.analyze(canonical_url)
                if cyber_result and cyber_result.signals:
                    cyber_signals = cyber_result.signals
            except Exception:
                # Controlled failure: if deep analysis fails unexpectedly, record error but do not fail open
                cyber_signals = []

        # 4. Integrated Risk Scoring (DETERMINISTIC)
        risk_res = calculate_risk_score(ml_result, security_signals=cyber_signals)

        # 5. Decision Classification (DETERMINISTIC)
        classification = classify_risk(risk_res.score, self.decision_config)

        # 6. Reason Generation
        reasons = generate_reasons(
            classification, risk_res.score, ml_result, security_signals=cyber_signals
        )

        # 7. Aggregated Signals
        signals: Dict[str, Any] = {
            "ml_probability": ml_result.get("probability"),
            "ml_prediction": ml_result.get("prediction"),
            "ml_label": ml_result.get("label"),
        }

        if cyber_result is not None:
            signals["cyber_analysis"] = cyber_result.to_dict()

        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        model_version = ml_result.get("model_version", active_version)

        result = AnalysisResult(
            url=canonical_url,
            classification=classification,
            risk_score=risk_res.score,
            cached=False,
            reasons=reasons,
            signals=signals,
            model_version=model_version,
            analysis_time_ms=elapsed_ms,
            ai=None,
        )

        # 8. Optional Local AI Analysis (ADVISORY / EXPLANATORY ONLY - NEVER OVERRIDES RISK SCORE)
        should_run_ai = (
            force_ai_analysis
            if force_ai_analysis is not None
            else self.enable_ai
        )

        if should_run_ai:
            try:
                ai_res = self.ai_analyzer.analyze(result)
                if ai_res:
                    result.ai = ai_res.to_dict()
            except Exception as e:
                result.ai = {
                    "available": False,
                    "status": "provider_error",
                    "error": str(e),
                }

        # 9. Trust Cache Storage
        self.cache.set(
            canonical_url, result.to_dict(), model_version=model_version
        )

        return result
