from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from typing import Iterable

from socdedup.blast_radius import compute_blast_radius
from socdedup.confidence import assess_confidence
from socdedup.decision import assess_decision
from socdedup.models import Alert, EntitiesSummary, Incident
from socdedup.reasoning import derive_signals


@dataclass
class ClusterState:
    incident_id: str
    alerts: list[Alert] = field(default_factory=list)
    hosts: set[str] = field(default_factory=set)
    users: set[str] = field(default_factory=set)
    ips: set[str] = field(default_factory=set)
    techniques: set[str] = field(default_factory=set)
    latest_time: Alert | None = None

    def add_alert(self, alert: Alert) -> None:
        self.alerts.append(alert)
        if alert.host:
            self.hosts.add(alert.host)
        if alert.user:
            self.users.add(alert.user)
        if alert.source_ip:
            self.ips.add(alert.source_ip)
        if alert.mitre_technique:
            self.techniques.add(alert.mitre_technique)
        if self.latest_time is None or alert.timestamp > self.latest_time.timestamp:
            self.latest_time = alert


def _score_alert(alert: Alert, cluster: ClusterState, time_window: timedelta) -> int:
    score = 0
    if alert.host and alert.host in cluster.hosts:
        score += 2
    if alert.user and alert.user in cluster.users:
        score += 2
    if alert.source_ip and alert.source_ip in cluster.ips:
        score += 1
    if alert.mitre_technique and alert.mitre_technique in cluster.techniques:
        score += 3
    if cluster.latest_time is not None:
        delta = abs(alert.timestamp - cluster.latest_time.timestamp)
        if delta <= time_window:
            score += 1
    return score


def cluster_alerts(
    alerts: Iterable[Alert],
    time_window: timedelta,
    min_score: int,
) -> list[Incident]:
    sorted_alerts = sorted(alerts, key=lambda a: a.timestamp)
    clusters: list[ClusterState] = []
    counter = 1

    for alert in sorted_alerts:
        best_score = -1
        best_cluster: ClusterState | None = None
        for cluster in clusters:
            score = _score_alert(alert, cluster, time_window)
            if score > best_score:
                best_score = score
                best_cluster = cluster

        if best_cluster is not None and best_score >= min_score:
            best_cluster.add_alert(alert)
            continue

        incident_id = f"INC-{counter:04d}"
        counter += 1
        new_cluster = ClusterState(incident_id=incident_id)
        new_cluster.add_alert(alert)
        clusters.append(new_cluster)

    incidents: list[Incident] = []
    for cluster in clusters:
        blast = compute_blast_radius(cluster.alerts)
        signals = derive_signals(cluster.alerts, blast)
        confidence, reasoning = assess_confidence(signals, blast)
        decision_replay = assess_decision(signals, blast, confidence)
        entities = EntitiesSummary(
            hosts=set(cluster.hosts),
            users=set(cluster.users),
            ips=set(cluster.ips),
        )
        incident = Incident(
            incident_id=cluster.incident_id,
            alerts=cluster.alerts,
            techniques=set(cluster.techniques),
            entities=entities,
            confidence=confidence,
            reasoning=reasoning,
            decision_replay=decision_replay,
        )
        incidents.append(incident)

    return incidents
