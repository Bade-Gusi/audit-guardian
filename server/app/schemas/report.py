from pydantic import BaseModel
from datetime import datetime


class ReportUpload(BaseModel):
    case_name: str
    machine_name: str | None = None
    encrypted_data: str  # Base64 encrypted report JSON
    hardware_id: str | None = None


class ReportListItem(BaseModel):
    id: str
    case_name: str
    version: int
    risk_score: float
    total_items: int
    suspicious_items: int
    high_risk_items: int
    created_at: datetime

    class Config:
        from_attributes = True


class ReviewMarkCreate(BaseModel):
    item_type: str
    item_hash: str
    verdict: str  # suspicious/confirmed/benign/false_positive
    comment: str | None = None


class ReviewMarkResponse(BaseModel):
    id: str
    item_type: str
    item_hash: str
    verdict: str
    comment: str | None
    marked_by: str | None
    created_at: datetime

    class Config:
        from_attributes = True
