#audit_log.py
from sqlalchemy import Column, String, DateTime, Integer, Boolean
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.sql import func
from database import Base
import uuid

class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    job_id = Column(UUID(as_uuid=True))
    pii_types_found = Column(JSONB)
    pii_count = Column(Integer)
    confidence_scores = Column(JSONB)
    risk_score = Column(String(10))
    requires_review = Column(Boolean, default=False)
    agent_decisions = Column(JSONB)
    items_redacted = Column(Integer)
    items_flagged = Column(Integer)
    processing_time_ms = Column(Integer)
    created_at = Column(DateTime, server_default=func.now())
