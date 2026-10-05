import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.config import settings
from app.database.connection import verify_database_connection

# Configure structured logging
logging.basicConfig(
    level=logging.INFO if not settings.DEBUG else logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("zero_trust.engine")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager handling startup and shutdown diagnostics."""
    logger.info("Starting up %s (version: %s)...", settings.APP_NAME, settings.APP_VERSION)
    
    # Startup database connection verification
    is_connected = verify_database_connection()
    if is_connected:
        logger.info("[STARTUP CHECK] PostgreSQL database connection successful.")
    else:
        logger.warning(
            "[STARTUP CHECK WARNING] PostgreSQL database is unavailable or credentials incorrect. "
            "Server running in degraded state."
        )
    
    yield
    
    logger.info("Shutting down %s...", settings.APP_NAME)


# Instantiate FastAPI application
app = FastAPI(
    title="Zero-Trust API Security Engine",
    version="0.1.0",
    description="Hackathon MVP - Behavioral Anomaly Detection & Zero-Trust Verification Engine",
    lifespan=lifespan,
)

# Configure CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get(
    "/health",
    tags=["Health"],
    summary="General service health status",
    response_description="Returns general operational status and service metadata",
)
def get_service_health():
    """Health check endpoint reporting service availability."""
    return {
        "status": "ok",
        "service": "zero-trust-api-security",
        "version": settings.APP_VERSION,
    }


@app.get(
    "/health/database",
    tags=["Health"],
    summary="Live PostgreSQL connectivity health check",
    response_description="Returns live PostgreSQL connection state",
)
def get_database_health():
    """Database health check endpoint that actually verifies PostgreSQL connectivity."""
    is_connected = verify_database_connection()
    if is_connected:
        return {
            "status": "ok",
            "database": "connected",
        }
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={
            "status": "error",
            "database": "unavailable",
            "message": "Unable to establish connection to PostgreSQL database",
        },
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
