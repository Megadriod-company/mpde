import os
import logging
import structlog
from fastapi import Security, HTTPException, status
from fastapi.security.api_key import APIKeyHeader
from pydantic_settings import BaseSettings
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# ==========================================
# 1. ENTERPRISE CONFIGURATION (Environment)
# ==========================================
class Settings(BaseSettings):
    """Loads configuration from the .env file or system environment."""
    PROJECT_NAME: str = "MPDE (Megadriod Phishing Detection Engine)"
    API_KEY: str = "megadriod_super_secret_key_2026" # Default fallback
    DATABASE_URL: str = "sqlite:///./data/mpde.db"
    LOG_LEVEL: str = "INFO"

    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()

# ==========================================
# 2. STRUCTURED JSON LOGGING (For SIEM)
# ==========================================
# This ensures all print/log statements output as JSON objects.
structlog.configure(
    processors=[
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)
logger = structlog.get_logger("mpde.core")

# ==========================================
# 3. DATABASE SETUP (Persistence layer)
# ==========================================
# We use SQLite for the lightweight, compiler-free architecture.
# The `check_same_thread=False` allows FastAPI's async workers to use it.
os.makedirs("./data", exist_ok=True)

engine = create_engine(
    settings.DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ==========================================
# 4. SECURITY & AUTHENTICATION
# ==========================================
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

def verify_api_key(api_key: str = Security(api_key_header)):
    """FastAPI Dependency to validate the API key on secured endpoints."""
    if api_key != settings.API_KEY:
        logger.warning("unauthorized_access_attempt", provided_key=api_key)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-API-Key header",
        )
    return api_key

# ==========================================
# 5. DATABASE OPERATIONS (Background Tasks)
# ==========================================
def log_prediction_to_db(prediction_response):
    """
    Saves the scan result to the SQLite database.
    Runs in the background so the API doesn't slow down.
    """
    # Local import to prevent circular dependency with models.py
    from app.models import AuditLog 
    
    db = SessionLocal()
    try:
        db_log = AuditLog(
            url=prediction_response.url,
            verdict=prediction_response.verdict,
            confidence_score=prediction_response.confidence_score,
            entropy=prediction_response.features.get("entropy", 0.0),
            length=prediction_response.features.get("length", 0)
        )
        db.add(db_log)
        db.commit()
        logger.info("prediction_logged", url=prediction_response.url, verdict=prediction_response.verdict)
    except Exception as e:
        db.rollback()
        logger.error("db_write_failed", error=str(e))
    finally:
        db.close()

def get_recent_logs(limit: int = 100):
    """Fetches recent scans for the /audit endpoint."""
    from app.models import AuditLog
    
    db = SessionLocal()
    try:
        logs = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit).all()
        # Convert SQLAlchemy objects to standard dictionaries for the API response
        return [
            {
                "id": log.id,
                "timestamp": log.timestamp.isoformat(),
                "url": log.url,
                "verdict": log.verdict,
                "confidence_score": log.confidence_score
            } for log in logs
        ]
    finally:
        db.close()