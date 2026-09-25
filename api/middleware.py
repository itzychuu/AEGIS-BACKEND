import os
import uuid
import re
import logging
from typing import List
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

logger = logging.getLogger("aegis.api")

SAFE_REQUEST_ID_REGEX = re.compile(r"^[a-zA-Z0-9\-_]{1,128}$")


class RequestIdMiddleware(BaseHTTPMiddleware):
    """Attach unique X-Request-ID to incoming request state and outgoing response header."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        incoming_id = request.headers.get("X-Request-ID")
        if incoming_id and SAFE_REQUEST_ID_REGEX.match(incoming_id):
            request_id = incoming_id
        else:
            request_id = str(uuid.uuid4())

        request.state.request_id = request_id
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add basic HTTP security headers to responses."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        return response


def parse_cors_origins() -> List[str]:
    cors_env = os.getenv("AEGIS_CORS_ORIGINS", "")
    if not cors_env.strip():
        # Default origins for development / local extension compatibility
        return [
            "chrome-extension://*",
            "http://localhost:3000",
            "http://localhost:8000",
            "http://127.0.0.1:8000",
            "*"
        ]
    origins = [o.strip() for o in cors_env.split(",") if o.strip()]
    return origins if origins else ["*"]


def setup_middleware(app: FastAPI) -> None:
    origins = parse_cors_origins()
    
    # Configure CORS
    allow_credentials = "*" not in origins
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=allow_credentials,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Content-Type", "Authorization", "X-Request-ID", "X-Client-Version", "Accept"],
    )

    # Custom Middlewares
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestIdMiddleware)
