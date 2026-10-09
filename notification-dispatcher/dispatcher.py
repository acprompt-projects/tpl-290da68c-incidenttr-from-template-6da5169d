"""
Notification dispatcher: routes triaged incidents to Slack, PagerDuty, or email
based on severity/category rules with per-channel rate limiting.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger("notification-dispatcher")


# ---------------------------------------------------------------------------
# Domain models
# ---------------------------------------------------------------------------
class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Channel(str, Enum):
    SLACK = "slack"
    PAGERDUTY = "pagerduty"
    EMAIL = "email"


@dataclass
class Incident:
    id: str
    title: str
    severity: Severity
    category: str
    description: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Rate limiter  (token-bucket per channel)
# ---------------------------------------------------------------------------
class RateLimiter:
    def __init__(self, max_tokens: int, refill_period: float):
        self.max_tokens = max_tokens
        self.refill_period = refill_period
        self._tokens: float = max_tokens
        self._last_refill: float = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> bool:
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            self._tokens = min(self.max_tokens, self._tokens + elapsed * (self.max_tokens / self.refill_period))
            self._last_refill = now
            if self._tokens >= 1:
                self._tokens -= 1
                return True
            return False


# ---------------------------------------------------------------------------
# Channel senders
# ---------------------------------------------------------------------------
async def _send_slack(webhook_url: str, incident: Incident) -> bool:
    color = {"critical": "#ff0000", "high": "#ff6600", "medium": "#ffcc00", "low": "#36a64f", "info": "#808080"}
    payload = {
        "attachments": [{
            "color": color.get(incident.severity.value, "#808080"),
            "title": f"[{incident.severity.value.upper()}] {incident.title}",
            "text": incident.description,
            "fields": [
                {"title": "Category", "value": incident.category, "short": True},
                {"title": "Incident ID", "value": incident.id, "short": True},
            ],
            "footer": "incident-triage",
        }]
    }
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(webhook_url, json=payload)
            resp.raise_for_status()
            logger.info("Slack notification sent for incident %s", incident.id)
            return True
    except Exception:
        logger.exception("Slack notification failed for incident %s", incident.id)
        return False


async def _send_pagerduty(routing_key: str, incident: Incident) -> bool:
    severity_map = {"critical": "critical", "high": "high", "medium": "warning", "low": "info", "info": "info"}
    dedup_key = hashlib.sha256(f"{incident.id}:{incident.category}".encode()).hexdigest()[:32]
    payload = {
        "routing_key": routing_key,
        "event_action": "trigger",
        "dedup_key": dedup_key,
        "payload": {
            "summary": incident.title,
            "severity": severity_map.get(incident.severity.value, "warning"),
            "source": "incident-triage",
            "component": incident.category,
            "group": incident.category,
            "custom_details": {"description": incident.description, "incident_id": incident.id},
        },
    }
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post("https://events.pagerduty.com/v2/enqueue", json=payload)
            resp.raise_for_status()
            logger.info("PagerDuty notification sent for incident %s", incident.id)
            return True
    except Exception:
        logger.exception("PagerDuty notification failed for incident %s", incident.id)
        return False


async def _send_email(smtp_url: str, incident: Incident) -> bool:
    # Minimal email sender – in production replace with aiosmtplib or SES call
    logger.info("Email notification for incident %s (smtp=%s)", incident.id, smtp_url)
    return True


# ---------------------------------------------------------------------------
# Routing rules
# ---------------------------------------------------------------------------
@dataclass
class RoutingRule:
    channels: List[Channel]
    severities: List[Severity] = field(default_factory=lambda: list(Severity))
    categories: List[str] = field(default_factory=list)  # empty = all


class RoutingTable:
    def __init__(self, rules: Optional[List[RoutingRule]] = None):
        self._rules: List[RoutingRule] = rules or []

    def add(self, rule: RoutingRule) -> None:
        self._rules.append(rule)

    def resolve(self, incident: Incident) -> List[Channel]:
        channels: List[Channel] = []
        for rule in self._rules:
            if incident.severity not in rule.severities:
                continue
            if rule.categories and incident.category not in rule.categories:
                continue
            channels.extend(rule.channels)
        # deduplicate while preserving order
        seen: set = set()
        unique: List[Channel] = []
        for ch in channels:
            if ch not in seen:
                seen.add(ch)
                unique.append(ch)
        return unique


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------
class NotificationDispatcher:
    def __init__(
        self,
        routing: RoutingTable,
        rate_limiters: Optional[Dict[Channel, RateLimiter]] = None,
        slack_webhook: str = "",
        pagerduty_key: str = "",
        smtp_url: str = "",
    ):
        self.routing = routing
        self.limiters = rate_limiters or {
            Channel.SLACK: RateLimiter(max_tokens=20, refill_period=60),
            Channel.PAGERDUTY: RateLimiter(max_tokens=10, refill_period=60),
            Channel.EMAIL: RateLimiter(max_tokens=50, refill_period=60),
        }
        self._cfg: Dict[str, str] = {
            "slack_webhook": slack_webhook,
            "pagerduty_key": pagerduty_key,
            "smtp_url": smtp_url,
        }

    async def dispatch(self, incident: Incident) -> Dict[str, bool]:
        channels = self.routing.resolve(incident)
        results: Dict[str, bool] = {}
        tasks = []
        for ch in channels:
            limiter = self.limiters.get(ch)
            if limiter and not await limiter.acquire():
                logger.warning("Rate-limited %s for incident %s", ch.value, incident.id)
                results[ch.value] = False
                continue
            tasks.append(self._send_one(ch, incident, results))
        if tasks:
            await asyncio.gather(*tasks)
        return results

    async def _send_one(self, channel: Channel, incident: Incident, results: Dict[str, bool]) -> None:
        if channel == Channel.SLACK:
            ok = await _send_slack(self._cfg["slack_webhook"], incident)
        elif channel == Channel.PAGERDUTY:
            ok = await _send_pagerduty(self._cfg["pagerduty_key"], incident)
        elif channel == Channel.EMAIL:
            ok = await _send_email(self._cfg["smtp_url"], incident)
        else:
            ok = False
        results[channel.value] = ok


# ---------------------------------------------------------------------------
# Default routing builder
# ---------------------------------------------------------------------------
def build_default_routing() -> RoutingTable:
    table = RoutingTable()
    table.add(RoutingRule(channels=[Channel.PAGERDUTY, Channel.SLACK], severities=[Severity.CRITICAL]))
    table.add(RoutingRule(channels=[Channel.PAGERDUTY, Channel.SLACK], severities=[Severity.HIGH]))
    table.add(RoutingRule(channels=[Channel.SLACK, Channel.EMAIL], severities=[Severity.MEDIUM]))
    table.add(RoutingRule(channels=[Channel.SLACK], severities=[Severity.LOW, Severity.INFO]))
    table.add(RoutingRule(
        channels=[Channel.PAGERDUTY, Channel.SLACK, Channel.EMAIL],
        severities=[Severity.HIGH, Severity.CRITICAL],
        categories=["security"],
    ))
    return table