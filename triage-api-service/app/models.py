from pydantic import BaseModel, Field
from enum import Enum
from datetime import datetime
from typing import Optional, List

class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class IncidentStatus(str, Enum):
    NEW = "new"
    TRIAGING = "triaging"
    ACKNOWLEDGED = "acknowledged"
    ESCALATED = "escalated"
    RESOLVED = "resolved"

class AlertSource(BaseModel):
    service: str
    rule_id: str
    fingerprint: str

class IncidentCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=500)
    description: str = Field(default="", max_length=5000)
    severity: SeverityLevel = SeverityLevel.MEDIUM
    source: AlertSource
    labels: dict = Field(default_factory=dict)
    dedup_key: Optional[str] = None

class IncidentUpdate(BaseModel):
    severity: Optional[SeverityLevel] = None
    status: Optional[IncidentStatus] = None
    assignee: Optional[str] = None
    notes: Optional[str] = None

class Incident(BaseModel):
    id: str
    title: str
    description: str
    severity: SeverityLevel
    status: IncidentStatus
    source: AlertSource
    labels: dict
    dedup_key: Optional[str] = None
    assignee: Optional[str] = None
    notes: Optional[str] = None
    alert_count: int = 1
    related_incident_ids: List[str] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime