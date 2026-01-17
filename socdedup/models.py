from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Alert(BaseModel):
    model_config = ConfigDict(extra="allow")

    timestamp: datetime
    source_ip: str | None = None
    dest_ip: str | None = None
    user: str | None = None
    host: str | None = None
    alert_type: str
    mitre_technique: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp", mode="before")
    @classmethod
    def ensure_utc(cls, value: Any) -> datetime:
        if isinstance(value, datetime):
            dt = value
        elif isinstance(value, str):
            text = value.strip()
            if text.endswith("Z"):
                text = text[:-1] + "+00:00"
            dt = datetime.fromisoformat(text)
        elif isinstance(value, (int, float)):
            dt = datetime.fromtimestamp(value, tz=timezone.utc)
        else:
            raise ValueError("timestamp must be a datetime")
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)


class EntitiesSummary(BaseModel):
    hosts: set[str] = Field(default_factory=set)
    users: set[str] = Field(default_factory=set)
    ips: set[str] = Field(default_factory=set)


class Confidence(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class Incident(BaseModel):
    incident_id: str
    alerts: list[Alert]
    techniques: set[str] = Field(default_factory=set)
    entities: EntitiesSummary = Field(default_factory=EntitiesSummary)
    confidence: Confidence = Confidence.LOW
    reasoning: list[str] = Field(default_factory=list)
    decision_replay: "DecisionReplay | None" = None


class DecisionReplay(BaseModel):
    action: str
    urgency: str
    justification: list[str] = Field(default_factory=list)
    human_in_the_loop: bool = True
