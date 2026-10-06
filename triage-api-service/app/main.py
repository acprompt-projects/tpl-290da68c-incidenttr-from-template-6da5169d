from fastapi import FastAPI, HTTPException
from contextlib import asynccontextmanager
from .models import IncidentCreate, IncidentUpdate, Incident, IncidentStatus, SeverityLevel
from .store import IncidentStore

store = IncidentStore()

@asynccontextmanager
async def lifespan(app: FastAPI):
    await store.init()
    yield

app = FastAPI(title="Incident Triage Service", version="1.0.0", lifespan=lifespan)

@app.post("/incidents", response_model=Incident, status_code=201)
async def create_incident(payload: IncidentCreate):
    incident = await store.create(payload)
    return incident

@app.get("/incidents/{incident_id}", response_model=Incident)
async def get_incident(incident_id: str):
    incident = await store.get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident

@app.patch("/incidents/{incident_id}/triage", response_model=Incident)
async def update_triage(incident_id: str, payload: IncidentUpdate):
    incident = await store.get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    if incident.status == IncidentStatus.RESOLVED:
        raise HTTPException(status_code=409, detail="Cannot triage a resolved incident")
    updated = await store.update(incident_id, payload)
    return updated

@app.get("/health")
async def health():
    return {"status": "healthy"}