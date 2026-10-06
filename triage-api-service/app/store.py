import uuid
from datetime import datetime, timezone
from typing import Optional, Dict
from .models import Incident, IncidentCreate, IncidentUpdate, IncidentStatus

class IncidentStore:
    def __init__(self):
        self._incidents: Dict[str, Incident] = {}
        self._dedup_index: Dict[str, str] = {}

    async def init(self):
        pass

    async def create(self, payload: IncidentCreate) -> Incident:
        now = datetime.now(timezone.utc)
        if payload.dedup_key and payload.dedup_key in self._dedup_index:
            existing_id = self._dedup_index[payload.dedup_key]
            existing = self._incidents[existing_id]
            existing.alert_count += 1
            existing.updated_at = now
            if payload.severity.value > existing.severity.value:
                pass
            sev_order = ["info", "low", "medium", "high", "critical"]
            if sev_order.index(payload.severity.value) > sev_order.index(existing.severity.value):
                existing.severity = payload.severity
            return existing
        incident_id = str(uuid.uuid4())
        incident = Incident(
            id=incident_id,
            title=payload.title,
            description=payload.description,
            severity=payload.severity,
            status=IncidentStatus.NEW,
            source=payload.source,
            labels=payload.labels,
            dedup_key=payload.dedup_key,
            created_at=now,
            updated_at=now,
        )
        self._incidents[incident_id] = incident
        if payload.dedup_key:
            self._dedup_index[payload.dedup_key] = incident_id
        return incident

    async def get(self, incident_id: str) -> Optional[Incident]:
        return self._incidents.get(incident_id)

    async def update(self, incident_id: str, payload: IncidentUpdate) -> Incident:
        incident = self._incidents[incident_id]
        if payload.severity is not None:
            incident.severity = payload.severity
        if payload.status is not None:
            incident.status = payload.status
        if payload.assignee is not None:
            incident.assignee = payload.assignee
        if payload.notes is not None:
            incident.notes = payload.notes
        incident.updated_at = datetime.now(timezone.utc)
        return incident