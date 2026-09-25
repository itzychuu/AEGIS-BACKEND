import logging
from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from ml_model.exceptions import InvalidURLError, MLError
from aegis_engine.exceptions import EngineError
from api.middleware import setup_middleware
from api.routes import health_router, analysis_router
from api.errors import (
    invalid_url_exception_handler,
    ml_exception_handler,
    validation_exception_handler,
    engine_exception_handler,
    http_exception_handler,
    unhandled_exception_handler,
)

# Configure standard logger for Aegis API
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s (%(threadName)s): %(message)s",
)
logger = logging.getLogger("aegis.api")


def create_app() -> FastAPI:
    """Factory function to build and configure the FastAPI application."""
    app = FastAPI(
        title="Aegis Backend",
        description="AI-assisted phishing prevention backend",
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )

    # Attach custom middleware (CORS, Security Headers, Request ID)
    setup_middleware(app)

    # Register centralized exception handlers
    app.add_exception_handler(InvalidURLError, invalid_url_exception_handler)
    app.add_exception_handler(MLError, ml_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(EngineError, engine_exception_handler)
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(Exception, unhandled_exception_handler)

    # Include route modules
    app.include_router(health_router)
    app.include_router(analysis_router)

    return app


app = create_app()
