from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from socdedup.models import Alert


_TIMESTAMP_FIELDS = ["timestamp", "time", "event_time", "@timestamp"]
_ALERT_TYPE_FIELDS = ["alert_type", "type", "name", "signature"]
_MITRE_FIELDS = ["mitre_technique", "mitre", "technique"]


def _parse_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, (int, float)):
        dt = datetime.fromtimestamp(value, tz=timezone.utc)
    elif isinstance(value, str):
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
    else:
        raise ValueError("Unsupported timestamp format")
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _get_first(data: dict[str, Any], keys: list[str]) -> Any | None:
    for key in keys:
        if key in data and data[key] not in (None, ""):
            return data[key]
    return None


def _normalize_alert(data: dict[str, Any]) -> Alert:
    source_ip = _get_first(data, ["src_ip", "source_ip", "ip"])
    dest_ip = _get_first(data, ["dest_ip", "dst_ip", "destination_ip"])
    user = _get_first(data, ["user", "username", "account"])
    host = _get_first(data, ["host", "hostname", "computer"])

    ts_value = _get_first(data, _TIMESTAMP_FIELDS)
    if ts_value is None:
        raise ValueError("Missing timestamp")

    alert_type = _get_first(data, _ALERT_TYPE_FIELDS) or "unknown"
    mitre_technique = _get_first(data, _MITRE_FIELDS)

    alert = Alert(
        timestamp=_parse_timestamp(ts_value),
        source_ip=source_ip,
        dest_ip=dest_ip,
        user=user,
        host=host,
        alert_type=str(alert_type),
        mitre_technique=str(mitre_technique) if mitre_technique else None,
        raw=data,
    )
    return alert


def ingest_json(path: str | Path) -> list[Alert]:
    path = Path(path)
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)

    if isinstance(payload, dict) and "alerts" in payload:
        records = payload["alerts"]
    else:
        records = payload

    if not isinstance(records, list):
        raise ValueError("JSON payload must be a list of alerts")

    alerts: list[Alert] = []
    for item in records:
        if not isinstance(item, dict):
            raise ValueError("Alert must be an object")
        alerts.append(_normalize_alert(item))
    return alerts


def ingest_csv(path: str | Path) -> list[Alert]:
    path = Path(path)
    alerts: list[Alert] = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            alerts.append(_normalize_alert(row))
    return alerts
