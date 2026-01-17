from __future__ import annotations

from datetime import datetime, timedelta, timezone

from socdedup.clustering import cluster_alerts
from socdedup.models import Alert


def _alert(ts: datetime, host: str | None, user: str | None, ip: str | None, tech: str | None):
    return Alert(
        timestamp=ts,
        host=host,
        user=user,
        source_ip=ip,
        dest_ip=None,
        alert_type="Test",
        mitre_technique=tech,
        raw={},
    )


def test_clustering_greedy_scoring():
    base = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    alerts = [
        _alert(base, "host-a", "alice", "10.0.0.1", "T1000"),
        _alert(base + timedelta(minutes=5), "host-a", "alice", "10.0.0.2", None),
        _alert(base + timedelta(minutes=6), "host-b", "bob", "10.0.0.3", "T1000"),
    ]

    incidents = cluster_alerts(alerts, timedelta(minutes=15), min_score=5)
    assert len(incidents) == 2

    first = incidents[0]
    second = incidents[1]
    assert len(first.alerts) == 2
    assert len(second.alerts) == 1
    assert first.confidence.value in {"LOW", "MEDIUM", "HIGH"}
