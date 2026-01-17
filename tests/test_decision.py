from __future__ import annotations

from datetime import datetime, timedelta, timezone

import json

from typer.testing import CliRunner

from socdedup.blast_radius import compute_blast_radius
from socdedup.cli import app
from socdedup.confidence import assess_confidence
from socdedup.decision import assess_decision
from socdedup.models import Alert, Incident
from socdedup.reasoning import derive_signals


def _alert(ts, host, user, ip, tech, alert_type):
    return Alert(
        timestamp=ts,
        host=host,
        user=user,
        source_ip=ip,
        dest_ip=None,
        alert_type=alert_type,
        mitre_technique=tech,
        raw={},
    )


def _evaluate(alerts):
    blast = compute_blast_radius(alerts)
    signals = derive_signals(alerts, blast)
    confidence, _ = assess_confidence(signals, blast)
    decision = assess_decision(signals, blast, confidence)
    return decision, confidence


def test_cli_replay_output(tmp_path):
    runner = CliRunner()
    base = datetime(2024, 1, 1, 3, 0, 0, tzinfo=timezone.utc)
    alerts = [
        _alert(base, "host-a", "admin_ops", "10.0.0.1", "T1021", "Remote Service"),
        _alert(base + timedelta(minutes=1), "host-b", "admin_ops", "10.0.0.1", "T1021", "Remote Service"),
        _alert(base + timedelta(minutes=2), "host-c", "admin_ops", "10.0.0.1", "T1021", "Remote Service"),
    ]
    blast = compute_blast_radius(alerts)
    signals = derive_signals(alerts, blast)
    confidence, _ = assess_confidence(signals, blast)
    decision = assess_decision(signals, blast, confidence)
    incident = Incident(
        incident_id="INC-0001",
        alerts=alerts,
        techniques=set(blast.techniques),
        entities={"hosts": set(blast.unique_hosts), "users": set(blast.unique_users), "ips": set()},
        confidence=confidence,
        reasoning=["test reasoning 1"],
        decision_replay=decision,
    )
    path = tmp_path / "incidents.json"
    path.write_text(json.dumps([incident.model_dump(mode="json")]))

    result = runner.invoke(app, ["incidents", "replay", "INC-0001", "--path", str(path)])
    assert result.exit_code == 0
    assert "Action: DISABLE_ACCOUNT" in result.output
    assert "Urgency: IMMEDIATE" in result.output


def test_decision_high_privileged_context_disables_account():
    base = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    alerts = [
        _alert(base, "host-a", "admin_ops", "10.0.0.1", "T1021", "Remote Service"),
        _alert(base + timedelta(minutes=1), "host-b", "admin_ops", "10.0.0.1", "T1021", "Remote Service"),
        _alert(base + timedelta(minutes=2), "host-c", "admin_ops", "10.0.0.1", "T1021", "Remote Service"),
    ]

    decision, confidence = _evaluate(alerts)
    assert confidence.value == "HIGH"
    assert decision.action == "DISABLE_ACCOUNT"
    assert decision.urgency == "IMMEDIATE"
    assert any(char.isdigit() for line in decision.justification for char in line)


def test_decision_medium_collect_forensics():
    base = datetime(2024, 1, 1, 1, 0, 0, tzinfo=timezone.utc)
    alerts = [
        _alert(base, "host-a", "bob", "10.0.0.2", "T1046", "Port Scan"),
        _alert(base + timedelta(minutes=1), "host-a", "bob", "10.0.0.2", "T1059", "Command Exec"),
    ]

    decision, confidence = _evaluate(alerts)
    assert confidence.value == "MEDIUM"
    assert decision.action == "COLLECT_FORENSICS"
    assert decision.urgency == "HIGH"


def test_decision_low_monitor():
    base = datetime(2024, 1, 1, 2, 0, 0, tzinfo=timezone.utc)
    alerts = [
        _alert(base, "host-a", "user1", "10.0.0.3", "T1046", "Port Scan"),
    ]

    decision, confidence = _evaluate(alerts)
    assert confidence.value == "LOW"
    assert decision.action == "MONITOR"
    assert decision.urgency == "LOW"
