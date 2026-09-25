from fastapi import APIRouter, Depends
from api.schemas.health import HealthResponse, ReadinessChecks, ReadinessResponse
from api.dependencies import get_aegis_engine
from aegis_engine import AegisEngine
from ml_model import get_loaded_model, MODEL_VERSION
from local_ai.models import AIStatus

router = APIRouter(tags=["Health"])


@router.get("/health", response_model=HealthResponse, summary="Lightweight health check endpoint")
@router.get("/api/v1/health", response_model=HealthResponse, summary="Lightweight health check endpoint (v1)")
def health_check() -> HealthResponse:
    """Lightweight service health check.
    
    Performs zero network, ML, or AI operations.
    """
    return HealthResponse(
        status="ok",
        service="aegis-backend",
        version="1.0.0"
    )


@router.get("/ready", response_model=ReadinessResponse, summary="Service readiness check endpoint")
@router.get("/api/v1/ready", response_model=ReadinessResponse, summary="Service readiness check endpoint (v1)")
def readiness_check(engine: AegisEngine = Depends(get_aegis_engine)) -> ReadinessResponse:
    """Check subsystem readiness for accepting analysis traffic.
    
    Validates local model artifacts and subsystem configurations without executing network analysis.
    """
    # 1. ML Model readiness check
    try:
        model = get_loaded_model()
        ml_status = "ready" if model is not None else "not_ready"
    except Exception:
        ml_status = "not_ready"

    # 2. Cyber Analysis readiness check
    cyber_status = "ready" if engine.enable_cyber_analysis else "disabled"

    # 3. Local AI readiness check
    ai_status = "disabled"
    if engine.enable_ai and engine.ai_analyzer:
        try:
            if not engine.ai_analyzer.config.enabled:
                ai_status = AIStatus.DISABLED
            elif not engine.ai_analyzer.provider.health_check():
                ai_status = AIStatus.UNAVAILABLE
            elif not engine.ai_analyzer.provider.is_model_available(engine.ai_analyzer.config.model):
                ai_status = AIStatus.MODEL_NOT_FOUND
            else:
                ai_status = "available"
        except Exception:
            ai_status = AIStatus.UNAVAILABLE

    # Core backend readiness depends on ML Model & Core Engine
    overall_status = "ready" if ml_status == "ready" else "not_ready"

    return ReadinessResponse(
        status=overall_status,
        checks=ReadinessChecks(
            ml_model=ml_status,
            cyber_analysis=cyber_status,
            local_ai=str(ai_status)
        )
    )
