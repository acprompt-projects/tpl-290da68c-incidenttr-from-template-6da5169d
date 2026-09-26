from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(Enum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


class Category(Enum):
    INFRA = "infra"
    APP = "app"
    SECURITY = "security"
    NETWORK = "network"


@dataclass
class TriageLabel:
    severity: Severity
    category: Category
    confidence: float
    matched_rules: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "severity": self.severity.value,
            "category": self.category.value,
            "confidence": round(self.confidence, 2),
            "matched_rules": self.matched_rules,
        }


@dataclass
class ThresholdConfig:
    cpu_pct_p1: float = 95.0
    cpu_pct_p2: float = 85.0
    cpu_pct_p3: float = 75.0
    mem_pct_p1: float = 95.0
    mem_pct_p2: float = 85.0
    mem_pct_p3: float = 75.0
    disk_pct_p1: float = 95.0
    disk_pct_p2: float = 85.0
    disk_pct_p3: float = 75.0
    error_rate_pct_p1: float = 50.0
    error_rate_pct_p2: float = 25.0
    error_rate_pct_p3: float = 10.0
    latency_ms_p1: float = 5000.0
    latency_ms_p2: float = 2000.0
    latency_ms_p3: float = 1000.0
    packet_loss_pct_p1: float = 30.0
    packet_loss_pct_p2: float = 15.0
    packet_loss_pct_p3: float = 5.0
    confidence_boost: float = 0.15
    confidence_penalty: float = 0.1


_KEYWORD_CATEGORY_MAP: Dict[str, Category] = {
    "cpu": Category.INFRA,
    "memory": Category.INFRA,
    "ram": Category.INFRA,
    "disk": Category.INFRA,
    "storage": Category.INFRA,
    "iops": Category.INFRA,
    "host": Category.INFRA,
    "server": Category.INFRA,
    "vm": Category.INFRA,
    "container": Category.INFRA,
    "pod": Category.INFRA,
    "node": Category.INFRA,
    "latency": Category.APP,
    "error_rate": Category.APP,
    "http_5xx": Category.APP,
    "http_4xx": Category.APP,
    "exception": Category.APP,
    "timeout": Category.APP,
    "deployment": Category.APP,
    "service": Category.APP,
    "unauthorized": Category.SECURITY,
    "auth": Category.SECURITY,
    "breach": Category.SECURITY,
    "intrusion": Category.SECURITY,
    "malware": Category.SECURITY,
    "vulnerability": Category.SECURITY,
    "cve": Category.SECURITY,
    "firewall": Category.SECURITY,
    "ddos": Category.SECURITY,
    "ssl": Category.SECURITY,
    "certificate": Category.SECURITY,
    "packet_loss": Category.NETWORK,
    "dns": Category.NETWORK,
    "connection_refused": Category.NETWORK,
    "network": Category.NETWORK,
    "tcp": Category.NETWORK,
    "bandwidth": Category.NETWORK,
    "route": Category.NETWORK,
    "gateway": Category.NETWORK,
    "latency_network": Category.NETWORK,
}

_SEVERITY_KEYWORDS: Dict[Severity, List[str]] = {
    Severity.P1: ["outage", "down", "unreachable", "critical", "data_loss", "breach", "compromised"],
    Severity.P2: ["degraded", "partial_outage", "high_error", "slow", "failover"],
    Severity.P3: ["warning", "elevated", "minor", "retryable"],
    Severity.P4: ["info", "notice", "low", "routine", "threshold_exceeded"],
}


class IncidentClassifier:
    def __init__(self, thresholds: Optional[ThresholdConfig] = None, extra_rules: Optional[List[dict]] = None):
        self.thresholds = thresholds or ThresholdConfig()
        self.extra_rules = extra_rules or []

    def classify(self, incident: Dict[str, Any]) -> TriageLabel:
        category = self._determine_category(incident)
        severity, matched = self._determine_severity(incident)
        confidence = self._compute_confidence(incident, severity, category, matched)
        return TriageLabel(
            severity=severity,
            category=category,
            confidence=confidence,
            matched_rules=matched,
        )

    def _determine_category(self, incident: Dict[str, Any]) -> Category:
        votes: Dict[Category, int] = {c: 0 for c in Category}
        if "category" in incident and isinstance(incident["category"], str):
            try:
                return Category(incident["category"])
            except ValueError:
                pass
        text_fields = " ".join(
            str(incident.get(k, "")) for k in ("alert_type", "metric_name", "message", "tags")
        ).lower()
        for keyword, cat in _KEYWORD_CATEGORY_MAP.items():
            if keyword in text_fields:
                votes[cat] += 1
        source = str(incident.get("source", "")).lower()
        if source in ("prometheus", "node_exporter", "cadvisor"):
            votes[Category.INFRA] += 2
        elif source in ("sentry", "appdynamics", "datadog-apm"):
            votes[Category.APP] += 2
        elif source in ("suricata", "snort", "waf"):
            votes[Category.SECURITY] += 2
        elif source in ("ping", "traceroute", "netflow"):
            votes[Category.NETWORK] += 2
        best = max(votes, key=votes.get)
        if votes[best] == 0:
            return Category.APP
        return best

    def _determine_severity(self, incident: Dict[str, Any]) -> tuple[Severity, List[str]]:
        matched: List[str] = []
        scores: Dict[Severity, float] = {s: 0.0 for s in Severity}
        metric_name = str(incident.get("metric_name", "")).lower()
        metric_value = float(incident.get("metric_value", 0))
        text = " ".join(
            str(incident.get(k, "")) for k in ("alert_type", "message", "tags")
        ).lower()

        for sev, keywords in _SEVERITY_KEYWORDS.items():
            for kw in keywords:
                if kw in text:
                    scores[sev] += 1.0
                    matched.append(f"keyword:{sev.value}:{kw}")

        thr = self.thresholds
        metric_rules = [
            ("cpu", thr.cpu_pct_p1, thr.cpu_pct_p2, thr.cpu_pct_p3),
            ("memory|mem|ram", thr.mem_pct_p1, thr.mem_pct_p2, thr.mem_pct_p3),
            ("disk|storage|iops", thr.disk_pct_p1, thr.disk_pct_p2, thr.disk_pct_p3),
            ("error_rate|5xx", thr.error_rate_pct_p1, thr.error_rate_pct_p2, thr.error_rate_pct_p3),
            ("latency|response_time", thr.latency_ms_p1, thr.latency_ms_p2, thr.latency_ms_p3),
            ("packet_loss|drop", thr.packet_loss_pct_p1, thr.packet_loss_pct_p2, thr.packet_loss_pct_p3),
        ]
        for pattern, p1, p2, p3 in metric_rules:
            if re.search(pattern, metric_name):
                if metric_value >= p1:
                    scores[Severity.P1] += 2.0
                    matched.append(f"metric:P1:{metric_name}>={p1}")
                elif metric_value >= p2:
                    scores[Severity.P2] += 2.0
                    matched.append(f"metric:P2:{metric_name}>={p2}")
                elif metric_value >= p3:
                    scores[Severity.P3] += 2.0
                    matched.append(f"metric:P3:{metric_name}>={p3}")
                else:
                    scores[Severity.P4] += 0.5
                    matched.append(f"metric:P4:{metric_name}<{p3}")
                break

        affected_count = len(incident.get("affected_services", []) or [])
        if affected_count >= 5:
            scores[Severity.P1] += 1.5
            matched.append("blast_radius:>=5_services")
        elif affected_count >= 3:
            scores[Severity.P2] += 1.0
            matched.append("blast_radius:>=3_services")
        elif affected_count >= 1:
            scores[Severity.P3] += 0.5
            matched.append("blast_radius:>=1_service")

        for rule in self.extra_rules:
            condition_fn = rule.get("condition")
            target_sev = Severity(rule.get("severity", "P4"))
            rule_name = rule.get("name", "custom_rule")
            if callable(condition_fn) and condition_fn(incident):
                scores[target_sev] += rule.get("weight", 1.0)
                matched.append(f"custom:{rule_name}")

        best = max(Severity, key=lambda s: scores[s])
        if scores[best] == 0:
            return Severity.P4, ["default:P4"]
        return best, matched

    def _compute_confidence(
        self, incident: Dict[str, Any], severity: Severity, category: Category, matched: List[str]
    ) -> float:
        base = 0.5
        base += min(len(matched) * self.thresholds.confidence_boost, 0.35)
        if incident.get("metric_value") is not None and incident.get("metric_name"):
            base += 0.1
        if incident.get("affected_services"):
            base += 0.05
        if category == Category.SECURITY and severity in (Severity.P1, Severity.P2):
            base -= self.thresholds.confidence_penalty
        return min(max(base, 0.0), 1.0)


def classify_incident(incident: Dict[str, Any], thresholds: Optional[ThresholdConfig] = None) -> Dict[str, Any]:
    classifier = IncidentClassifier(thresholds=thresholds)
    return classifier.classify(incident).to_dict()