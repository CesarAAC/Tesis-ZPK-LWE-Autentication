from fastapi import FastAPI

from api.v1.auth import router as auth_router


def create_app() -> FastAPI:
    app = FastAPI(
        title="LWE Authentication Prototype API",
        version="0.1.0",
    )
    app.include_router(auth_router, prefix="/api/v1")

    @app.get("/health", tags=["system"])
    def health() -> dict[str, str]:
        return {"status": "ok"}

    return app


app = create_app()
