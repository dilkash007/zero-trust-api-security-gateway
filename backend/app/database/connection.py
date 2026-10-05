import logging
from typing import Generator
from sqlalchemy import create_engine, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from app.config import settings

logger = logging.getLogger("zero_trust.database")


class Base(DeclarativeBase):
    """SQLAlchemy 2.x Declarative Base for future data models."""
    pass


# SQLAlchemy 2.x Engine
engine = create_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,
    echo=False,
)

# Session factory for handling requests
SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency yielding database session per request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def verify_database_connection() -> bool:
    """Verifies that the PostgreSQL database connection is operational.

    Executes a lightweight ping query ('SELECT 1') without leaking credentials.
    Returns True if healthy, False otherwise.
    """
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception as exc:
        safe_url = engine.url.render_as_string(hide_password=True)
        logger.error(
            "Database connectivity check failed against target [%s]: %s",
            safe_url,
            type(exc).__name__,
        )
        return False
