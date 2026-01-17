from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from typer.testing import CliRunner

from socdedup.blast_radius import compute_blast_radius
from socdedup.cli import app
from socdedup.confidence import assess_confidence
from socdedup.models import Alert, Incident
from socdedup.reasoning import derive_signals

runner = CliRunner()


def _alert(
    ts: datetime,
    host: str | None,
    user: str | None,
    ip: str | None,
    tech: str | None,
    alert_type: str,
):
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


def _assess(alerts: list[Alert]):
    blast = compute_blast_radius(alerts)
    signals = derive_signals(alerts, blast)
    confidence, reasoning = assess_confidence(signals, blast)
    return confidence, reasoning, blast, signals


def _assert_reasoning_has_numbers(reasoning: list[str]) -> None:
    assert reasoning
    for line in reasoning:
        assert any(char.isdigit() for char in line)


def test_confidence_high_privileged_lateral():
    base = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    alerts = [
        _alert(base, "host-a", "admin_ops", "10.0.0.1", "T1021", "Remote Service"),
        _alert(base + timedelta(minutes=1), "host-b", "admin_ops", "10.0.0.1", "T1021", "Remote Service"),
        _alert(base + timedelta(minutes=2), "host-c", "admin_ops", "10.0.0.1", "T1021", "Remote Service"),
    ]

    confidence, reasoning, _, _ = _assess(alerts)
    assert confidence.value == "HIGH"
    assert any("privileged_users=" in line for line in reasoning)
    _assert_reasoning_has_numbers(reasoning)


def test_confidence_high_credential_spray_blast_growth():
    base = datetime(2024, 1, 1, 1, 0, 0, tzinfo=timezone.utc)
    alerts = []
    for i in range(5):
        alerts.append(
            _alert(
                base + timedelta(minutes=i),
                f"host-{i}",
                f"user{i}",
                "203.0.113.10",
                "T1110.003",
                "Failed Login",
            )
        )

    confidence, reasoning, _, _ = _assess(alerts)
    assert confidence.value == "HIGH"
    assert any("source IPs" in line for line in reasoning)
    _assert_reasoning_has_numbers(reasoning)


def test_confidence_medium_technique_progression():
    base = datetime(2024, 1, 1, 2, 0, 0, tzinfo=timezone.utc)
    alerts = [
        _alert(base, "host-a", "bob", "10.0.0.2", "T1046", "Port Scan"),
        _alert(base + timedelta(minutes=1), "host-a", "bob", "10.0.0.2", "T1059", "Command Exec"),
    ]

    confidence, reasoning, _, _ = _assess(alerts)
    assert confidence.value == "MEDIUM"
    assert any("techniques" in line for line in reasoning)
    _assert_reasoning_has_numbers(reasoning)


def test_confidence_medium_unique_hosts_lateral_movement():
    base = datetime(2024, 1, 1, 3, 0, 0, tzinfo=timezone.utc)
    alerts = [
        _alert(base, "host-a", "bob", "10.0.0.2", "T1021", "Remote Service"),
        _alert(base + timedelta(minutes=1), "host-b", "bob", "10.0.0.2", "T1021", "Remote Service"),
        _alert(base + timedelta(minutes=2), "host-c", "bob", "10.0.0.2", "T1021", "Remote Service"),
    ]

    confidence, reasoning, _, _ = _assess(alerts)
    assert confidence.value == "MEDIUM"
    assert any("hosts" in line for line in reasoning)
    _assert_reasoning_has_numbers(reasoning)


def test_cli_explain_outputs_reasoning(tmp_path):
    alert = _alert(
        datetime(2024, 1, 1, 4, 0, 0, tzinfo=timezone.utc),
        "host-a",
        "admin_user",
        "10.0.0.3",
        "T1021",
        "Remote Service",
    )
    confidence, reasoning, _, _ = _assess([alert])
    incident = Incident(
        incident_id="INC-0001",
        alerts=[alert],
        techniques={"T1021"},
        confidence=confidence,
        reasoning=reasoning,
        entities={"hosts": {"host-a"}, "users": {"admin_user"}, "ips": {"10.0.0.3"}},
    )
    path = tmp_path / "incidents.json"
    path.write_text(json.dumps([incident.model_dump(mode="json")]))

    result = runner.invoke(
        app,
        ["incidents", "show", "INC-0001", "--explain", "--path", str(path)],
    )
    assert result.exit_code == 0
    assert "Confidence:" in result.output
    assert "Reasoning:" in result.output
    assert "Blast radius: hosts=1 users=1 privileged_users=1" in result.output
