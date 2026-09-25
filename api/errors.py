import logging
from typing import Optional, Dict, Any
from fastapi import Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from ml_model.exceptions import InvalidURLError, MLError
from aegis_engine.exceptions import EngineError
from pydantic import BaseModel, Field

logger = logging.getLogger("aegis.api")


class ErrorDetail(BaseModel):
    code: str = Field(..., description="Machine-readable error code")
    message: str = Field(..., description="Human-readable error description")
    details: Optional[Any] = Field(default=None, description="Optional safe error context")


class ErrorResponse(BaseModel):
    error: ErrorDetail


def create_error_response(
    status_code: int,
    code: str,
    message: str,
    details: Optional[Any] = None
) -> JSONResponse:
    content = {
        "error": {
            "code": code,
            "message": message,
        }
    }
    if details is not None:
        content["error"]["details"] = details

    return JSONResponse(status_code=status_code, content=content)


async def invalid_url_exception_handler(request: Request, exc: InvalidURLError) -> JSONResponse:
    logger.warning(f"Invalid URL requested on path {request.url.path}: {str(exc)}")
    return create_error_response(
        status_code=status.HTTP_400_BAD_REQUEST,
        code="INVALID_URL",
        message=str(exc) or "The supplied URL is invalid.",
    )


async def ml_exception_handler(request: Request, exc: MLError) -> JSONResponse:
    logger.warning(f"ML extraction exception on path {request.url.path}: {str(exc)}")
    return create_error_response(
        status_code=status.HTTP_400_BAD_REQUEST,
        code="INVALID_URL",
        message=f"Invalid URL format: {str(exc)}",
    )


async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    logger.warning(f"Validation error on path {request.url.path}: {exc.errors()}")
    # Format message from errors cleanly
    err_msgs = []
    for err in exc.errors():
        loc = ".".join(str(l) for l in err.get("loc", []))
        msg = err.get("msg", "Invalid input")
        err_msgs.append(f"{loc}: {msg}" if loc else msg)
    
    combined_msg = "; ".join(err_msgs) if err_msgs else "Validation error"
    
    return create_error_response(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        code="VALIDATION_ERROR",
        message=f"Request validation failed: {combined_msg}",
    )


async def engine_exception_handler(request: Request, exc: EngineError) -> JSONResponse:
    logger.error(f"Engine exception on path {request.url.path}: {str(exc)}", exc_info=True)
    return create_error_response(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        code="ENGINE_ERROR",
        message="An error occurred inside the security analysis engine.",
    )


async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    code = "HTTP_ERROR"
    if exc.status_code == status.HTTP_404_NOT_FOUND:
        code = "NOT_FOUND"
    elif exc.status_code == status.HTTP_405_METHOD_NOT_ALLOWED:
        code = "METHOD_NOT_ALLOWED"

    msg = str(exc.detail) if isinstance(exc.detail, str) else "HTTP request error"
    return create_error_response(
        status_code=exc.status_code,
        code=code,
        message=msg,
    )


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.error(f"Unhandled server error on path {request.url.path}: {str(exc)}", exc_info=True)
    return create_error_response(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        code="INTERNAL_ERROR",
        message="An internal server error occurred.",
    )
