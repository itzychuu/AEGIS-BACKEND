import logging
from fastapi import APIRouter, Depends, HTTPException, status
from api.schemas.analysis import AnalyzeRequest, AnalyzeResponse, ClassificationEnum
from api.dependencies import get_aegis_engine
from aegis_engine import AegisEngine, AnalysisResult
from aegis_engine.exceptions import EngineError

logger = logging.getLogger("aegis.api")

router = APIRouter(prefix="/api/v1", tags=["Analysis"])


@router.post(
    "/analyze",
    response_model=AnalyzeResponse,
    status_code=status.HTTP_200_OK,
    summary="Primary URL security analysis endpoint",
    description="Analyzes a target URL for phishing threats using ML classification, cybersecurity analysis, and advisory local AI.",
)
def analyze_url(
    payload: AnalyzeRequest,
    engine: AegisEngine = Depends(get_aegis_engine),
) -> AnalyzeResponse:
    """Analyze input URL and return structured security classification and signals."""
    logger.info(f"Received analysis request for URL length {len(payload.url)}")

    # Execute Aegis Engine pipeline
    result: AnalysisResult = engine.analyze(payload.url)

    # Validate risk score range strictly (0 <= risk_score <= 100)
    if not isinstance(result.risk_score, int) or not (0 <= result.risk_score <= 100):
        logger.critical(f"Engine returned invalid risk score out of bounds: {result.risk_score}")
        raise EngineError(f"Internal risk score out of bounds [0-100]: {result.risk_score}")

    # Validate classification enum strictly
    try:
        classification_enum = ClassificationEnum(result.classification)
    except ValueError:
        logger.critical(f"Engine returned invalid classification value: {result.classification}")
        raise EngineError(f"Internal classification invalid: {result.classification}")

    return AnalyzeResponse(
        url=result.url,
        classification=classification_enum,
        risk_score=result.risk_score,
        reasons=result.reasons,
        signals=result.signals,
        ai=result.ai,
        model_version=result.model_version,
        cached=result.cached,
        analysis_time_ms=result.analysis_time_ms,
    )
