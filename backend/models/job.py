from sqlalchemy import Column, String, DateTime, Text, UUID, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func
import uuid

Base = declarative_base()


class Job(Base):
    __tablename__ = "jobs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    status = Column(String(20), nullable=False, default="pending")
    original_filename = Column(String(255))
    original_image_path = Column(Text)
    enhanced_image_path = Column(Text)
    redacted_image_path = Column(Text, nullable=True)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, server_default=func.now())
    completed_at = Column(DateTime, nullable=True)

    # --- PDF support ---
    file_type = Column(String(10), nullable=False, default="image")  # "image" | "pdf"
    redacted_pdf_path = Column(Text, nullable=True)
    page_count = Column(Integer, nullable=True)
    pages_done = Column(Integer, nullable=False, default=0)