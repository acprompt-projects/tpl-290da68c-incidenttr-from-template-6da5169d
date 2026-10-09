"""
FastAPI endpoints for the notification dispatcher.
"""
from __future__ import annotations

import logging
import os

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

fromdispatcher import (
    Channel,
    Incident,
    NotificationDispatcher,
    RateLimiter,
    RoutingRule,
    RoutingTable,
    Severity,
    build_default_routing,
)

logger = logging.getLogger("notification-dispatcher")

# ---------------------------------------------------------------------------
# Config from environment
# ---------------------------------------------------------------------------
SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK_URL", "")
PAGERDUTY_KEY = os.getenv("PAGERDUTY_ROUTING_KEY", "")
SMTP_URL = os.getenv("SMTP_URL", "")

app = FastAPI(title="Notification Dispatcher", version="0.1.0")

_dispatcher: NotificationDispatcher | None = None


def _get_dispatcher() -> NotificationDispatcher:
    global _dispatcher
    if _dispatcher is None:
        _dispatcher = NotificationDispatcher(
            routing=build_default_routing(),
            slack_webhook=SLACK_WEBHOOK,
            pagerduty_key=PAGERDUTY_KEY,
            smtp_url=SMTP_URL,
        )
    return _dispatcher


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------
class IncidentIn(BaseModel):
    id: str
    title: str
    severity: Severity
    category: str
    description: str = ""
    metadata: dict = Field(default_factory=dict)


class DispatchResult(BaseModel):
    incident_id: str
    channels: dict[str, bool]


class RuleIn(BaseModel):
    channels: list[Channel]
    severities: list[Severity]
    categories: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@app.post("/dispatch", response_model=DispatchResult)
async def dispatch_incident(payload: IncidentIn):
    incident = Incident(**payload.model_dump())
    dispatcher = _get_dispatcher()
    results = await dispatcher.dispatch(incident)
    return DispatchResult(incident_id=incident.id, channels=results)


@app.post("/rules")
async def add_routing_rule(rule: RuleIn):
    dispatcher = _get_dispatcher()
    dispatcher.routing.add(RoutingRule(
        channels=rule.channels,
        severities=rule.severities,
        categories=rule.categories,
    ))
    return {"status": "added"}


@app.get("/health")
async def health():
    return {"status": "ok"}