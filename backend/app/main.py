import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.auth.routes import auth_router, test_router
from app.config import settings
from app.database.connection import Base, engine, verify_database_connection
from app.gateway.demo_routes import demo_router
from app.gateway.dependencies import SecurityGatewayException
from app.gateway.middleware import RequestContextMiddleware
from app.gateway.telemetry_routes import telemetry_router
from app.behavior.routes import behavior_router
# Ensure models are imported so Base.metadata knows about all schemas
import app.database.models  # noqa: F401

# Configure structured logging
logging.basicConfig(
    level=logging.INFO if not settings.DEBUG else logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("zero_trust.engine")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager handling startup table creation and diagnostics."""
    logger.info("Starting up %s (version: %s)...", settings.APP_NAME, settings.APP_VERSION)

    # Startup database connection verification
    is_connected = verify_database_connection()
    if is_connected:
        logger.info("[STARTUP CHECK] PostgreSQL database connection successful.")
        try:
            # Automatically create tables if they do not exist (users, api_request_logs, security_events)
            Base.metadata.create_all(bind=engine)
            logger.info("[STARTUP] Database schema verification complete (telemetry tables initialized).")
        except Exception as exc:
            logger.error("[STARTUP ERROR] Failed to initialize database schema: %s", type(exc).__name__)
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

# Step 3 & 4: Gateway & Telemetry Middleware
app.add_middleware(RequestContextMiddleware)

# Configure CORS Middleware with X-Request-ID exposed to browser clients
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID"],
)


@app.exception_handler(SecurityGatewayException)
async def security_gateway_exception_handler(request: Request, exc: SecurityGatewayException):
    """Formats gateway authorization failures into standardized Zero-Trust security error responses."""
    request_id = getattr(request.state, "request_id", "")
    headers = {"X-Request-ID": request_id} if request_id else {}
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "error": {
                "code": exc.code,
                "message": exc.message,
            },
        },
        headers=headers,
    )


# Include Authentication and Protected Test routers (Step 2)
app.include_router(auth_router)
app.include_router(test_router)

# Include Protected Demo APIs (Step 3)
app.include_router(demo_router)

# Include Security Telemetry & Audit Event APIs (Step 4)
app.include_router(telemetry_router)

# Include Behavioral Baseline & Feature Engine APIs (Step 5)
app.include_router(behavior_router)


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
