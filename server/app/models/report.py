import uuid
from datetime import datetime
from sqlalchemy import Column, String, Float, Integer, DateTime, ForeignKey, Text
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
from app.database import Base


class Report(Base):
    __tablename__ = "reports"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id = Column(UUID(as_uuid=True), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False)
    version = Column(Integer, default=1)
    report_data = Column(JSONB, nullable=False)
    summary = Column(JSONB)
    risk_score = Column(Float, default=0.0)
    total_items = Column(Integer, default=0)
    suspicious_items = Column(Integer, default=0)
    high_risk_items = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)

    case = relationship("Case", back_populates="reports")
    marks = relationship("ReviewMark", back_populates="report", cascade="all, delete-orphan")


class ReviewMark(Base):
    __tablename__ = "review_marks"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    report_id = Column(UUID(as_uuid=True), ForeignKey("reports.id", ondelete="CASCADE"), nullable=False)
    item_type = Column(String(32), nullable=False)  # event/process/file/hardware
    item_hash = Column(String(128), nullable=False)
    verdict = Column(String(32), nullable=False)  # suspicious/confirmed/benign/false_positive
    comment = Column(Text)
    marked_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    report = relationship("Report", back_populates="marks")
