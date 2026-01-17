from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from math import ceil

from socdedup.blast_radius import BlastRadius
from socdedup.models import Alert


@dataclass(frozen=True)
class CredentialSprayPattern:
    detected: bool
    source_ips: int
    users: int
    window_minutes: int


@dataclass(frozen=True)
class LateralMovementPattern:
    detected: bool
    user: str | None
    hosts: int
    window_minutes: int
    technique_t1021: int


@dataclass(frozen=True)
class TechniqueProgression:
    detected: bool
    techniques: int
    window_minutes: int


@dataclass(frozen=True)
class PrivilegedContext:
    detected: bool
    privileged_users: int


@dataclass(frozen=True)
class ReasoningSignals:
    credential_spray_pattern: CredentialSprayPattern
    lateral_movement_pattern: LateralMovementPattern
    technique_progression: TechniqueProgression
    privileged_context: PrivilegedContext


def _window_minutes(start: datetime, end: datetime) -> int:
    minutes = ceil((end - start).total_seconds() / 60)
    return max(1, minutes)


def _has_credential_spray_indicators(alerts: list[Alert]) -> bool:
    for alert in alerts:
        if alert.mitre_technique and alert.mitre_technique.startswith("T1110"):
            return True
        if "failed login" in alert.alert_type.lower():
            return True
    return False


def _credential_spray_window(alerts: list[Alert]) -> int:
    if not alerts:
        return 0
    start = min(a.timestamp for a in alerts)
    end = max(a.timestamp for a in alerts)
    return _window_minutes(start, end)


def _lateral_movement_window(alerts: list[Alert], user: str) -> int:
    user_alerts = [a for a in alerts if a.user == user]
    if not user_alerts:
        return 0
    start = min(a.timestamp for a in user_alerts)
    end = max(a.timestamp for a in user_alerts)
    return _window_minutes(start, end)


def _technique_window(alerts: list[Alert]) -> int:
    tech_alerts = [a for a in alerts if a.mitre_technique]
    if not tech_alerts:
        return 0
    start = min(a.timestamp for a in tech_alerts)
    end = max(a.timestamp for a in tech_alerts)
    return _window_minutes(start, end)


def derive_signals(alerts: list[Alert], blast: BlastRadius) -> ReasoningSignals:
    source_ips = len({a.source_ip for a in alerts if a.source_ip})
    users = len({a.user for a in alerts if a.user})
    credential_window = _credential_spray_window(alerts)
    credential_indicator = _has_credential_spray_indicators(alerts)
    credential_spray_pattern = CredentialSprayPattern(
        detected=users >= 5 and source_ips <= 2 and credential_indicator,
        source_ips=source_ips,
        users=users,
        window_minutes=credential_window,
    )

    user_hosts: dict[str, set[str]] = {}
    for alert in alerts:
        if not alert.user or not alert.host:
            continue
        user_hosts.setdefault(alert.user, set()).add(alert.host)

    best_user: str | None = None
    best_hosts = 0
    for user, hosts in user_hosts.items():
        if len(hosts) > best_hosts:
            best_hosts = len(hosts)
            best_user = user

    technique_t1021 = 1 if any(t.startswith("T1021") for t in blast.techniques) else 0
    lateral_window = _lateral_movement_window(alerts, best_user) if best_user else 0
    lateral_movement_pattern = LateralMovementPattern(
        detected=best_hosts >= 3
        and (len(blast.unique_users) == 1 or technique_t1021 == 1),
        user=best_user,
        hosts=best_hosts,
        window_minutes=lateral_window,
        technique_t1021=technique_t1021,
    )

    technique_count = len(blast.techniques)
    technique_progression = TechniqueProgression(
        detected=technique_count >= 2,
        techniques=technique_count,
        window_minutes=_technique_window(alerts),
    )

    privileged_context = PrivilegedContext(
        detected=len(blast.privileged_users) > 0,
        privileged_users=len(blast.privileged_users),
    )

    return ReasoningSignals(
        credential_spray_pattern=credential_spray_pattern,
        lateral_movement_pattern=lateral_movement_pattern,
        technique_progression=technique_progression,
        privileged_context=privileged_context,
    )
