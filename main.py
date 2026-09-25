"""AEGIS Backend FastAPI Entrypoint."""
from api.app import app

__all__ = ["app"]

if __name__ == "__main__":
    import os
    import uvicorn

    host = os.getenv("AEGIS_API_HOST", "127.0.0.1")
    port = int(os.getenv("AEGIS_API_PORT", "8000"))
    uvicorn.run("main:app", host=host, port=port, reload=True)