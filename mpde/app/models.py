from datetime import datetime
from typing import List, Dict, Optional
from pydantic import BaseModel, HttpUrl, Field
from sqlalchemy import Column, Integer, String, Float, DateTime, JSON
from app.core import Base

# ==========================================
# 1. DATABASE MODELS (SQLAlchemy)
# ==========================================
# This defines the "audit_logs" table in your SQLite database.

class AuditLog(Base):
    """
    SQLAlchemy model for storing every URL scan.
    Essential for Megadriod's incident response and audit trails.
    """
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    url = Column(String, index=True)
    verdict = Column(String)
    confidence_score = Column(Float)
    
    # We store the core features as individual columns for fast querying...
    entropy = Column(Float)
    length = Column(Integer)
    
    # ...and the rest of the behavioral metadata as a JSON blob.
    raw_features = Column(JSON, nullable=True)

# ==========================================
# 2. API REQUEST MODELS (Pydantic)
# ==========================================
# These ensure the user sends valid data to the API.

class URLRequest(BaseModel):
    """Data shape for a single URL scan request."""
    url: str = Field(..., example="http://secure-login-megadriod.com/update")

class BatchURLRequest(BaseModel):
    """Data shape for high-volume enterprise scanning."""
    batch_id: str = Field(..., example="BN-2026-X99")
    urls: List[str]

# ==========================================
# 3. API RESPONSE MODELS (Pydantic)
# ==========================================
# These define exactly what the user (or SIEM) receives.

class PredictionResponse(BaseModel):
    """Standardized response for a single prediction."""
    url: str
    verdict: str
    confidence_score: float
    features: Dict
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        # This allows Pydantic to read data directly from SQLAlchemy objects
        from_attributes = True

class BatchPredictionResponse(BaseModel):
    """Standardized response for batch operations."""
    batch_id: str
    total_processed: int
    results: List[PredictionResponse]
    status: str = "Completed"