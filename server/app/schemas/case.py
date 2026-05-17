from pydantic import BaseModel
from datetime import datetime


class CaseListItem(BaseModel):
    id: str
    case_name: str
    machine_name: str | None
    status: str
    priority: str
    risk_score: float | None
    created_at: datetime

    class Config:
        from_attributes = True


class CaseDetail(BaseModel):
    id: str
    case_name: str
    machine_name: str | None
    hardware_id: str | None
    license_key: str | None
    status: str
    priority: str
    assigned_to: str | None
    risk_score: float | None
    report_count: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class CaseUpdate(BaseModel):
    status: str | None = None
    priority: str | None = None
    assigned_to: str | None = None
