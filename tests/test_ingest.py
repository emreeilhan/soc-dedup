from __future__ import annotations

import json
from datetime import datetime, timezone

from socdedup.ingest import ingest_csv, ingest_json


def test_ingest_json_normalization(tmp_path):
    payload = [
        {
            "timestamp": "2024-01-01T00:00:00Z",
            "src_ip": "10.1.1.1",
            "dest_ip": "10.1.1.2",
            "username": "alice",
            "hostname": "host-a",
            "alert_type": "Test Alert",
            "mitre_technique": "T1110",
        }
    ]
    path = tmp_path / "alerts.json"
    path.write_text(json.dumps(payload))

    alerts = ingest_json(path)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.source_ip == "10.1.1.1"
    assert alert.dest_ip == "10.1.1.2"
    assert alert.user == "alice"
    assert alert.host == "host-a"
    assert alert.mitre_technique == "T1110"
    assert alert.timestamp == datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)


def test_ingest_csv_normalization(tmp_path):
    content = "timestamp,ip,account,computer,alert_type\n"
    content += "2024-01-01T00:00:05Z,10.2.2.2,bob,host-b,CSV Alert\n"
    path = tmp_path / "alerts.csv"
    path.write_text(content)

    alerts = ingest_csv(path)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.source_ip == "10.2.2.2"
    assert alert.user == "bob"
    assert alert.host == "host-b"
    assert alert.alert_type == "CSV Alert"
