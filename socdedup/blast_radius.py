from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from math import ceil

from socdedup.models import Alert


@dataclass(frozen=True)
class BlastGrowth:
    detected: bool
    window_minutes: int
    start_hosts: int
    end_hosts: int
    new_hosts: int


@dataclass(frozen=True)
class BlastRadius:
    unique_hosts: set[str]
    unique_users: set[str]
    privileged_users: set[str]
    techniques: set[str]
    blast_growth: BlastGrowth


def _window_minutes(start: datetime, end: datetime) -> int:
    minutes = ceil((end - start).total_seconds() / 60)
    return max(1, minutes)


def _compute_blast_growth(alerts: list[Alert], host_times: list[datetime]) -> BlastGrowth:
    if not host_times:
        return BlastGrowth(False, 0, 0, 0, 0)

    window = timedelta(minutes=10)
    times = sorted(host_times)
    max_new_hosts = 1
    best_start = 0
    best_end = 1
    end_index = 0

    for start_index, start_time in enumerate(times):
        if end_index < start_index:
            end_index = start_index
        while end_index < len(times) and times[end_index] - start_time <= window:
            end_index += 1
        new_hosts = end_index - start_index
        if new_hosts > max_new_hosts:
            max_new_hosts = new_hosts
            best_start = start_index
            best_end = end_index

    if best_end > best_start:
        growth_window = _window_minutes(times[best_start], times[best_end - 1])
    else:
        growth_window = 0

    start_hosts = best_start
    end_hosts = best_end

    incident_window = _window_minutes(min(a.timestamp for a in alerts), max(a.timestamp for a in alerts))
    detected = max_new_hosts >= 5 or len(times) >= 5

    if detected and max_new_hosts < 5:
        start_hosts = 0
        end_hosts = len(times)
        growth_window = incident_window
        max_new_hosts = len(times)

    return BlastGrowth(detected, growth_window, start_hosts, end_hosts, max_new_hosts)


def compute_blast_radius(alerts: list[Alert]) -> BlastRadius:
    if not alerts:
        return BlastRadius(
            unique_hosts=set(),
            unique_users=set(),
            privileged_users=set(),
            techniques=set(),
            blast_growth=BlastGrowth(False, 0, 0, 0, 0),
        )

    unique_hosts: set[str] = set()
    unique_users: set[str] = set()
    privileged_users: set[str] = set()
    techniques: set[str] = set()
    host_times: list[datetime] = []

    for alert in alerts:
        if alert.host:
            if alert.host not in unique_hosts:
                host_times.append(alert.timestamp)
            unique_hosts.add(alert.host)
        if alert.user:
            unique_users.add(alert.user)
            if alert.user.lower().startswith("admin"):
                privileged_users.add(alert.user)
        if alert.mitre_technique:
            techniques.add(alert.mitre_technique)

    blast_growth = _compute_blast_growth(alerts, host_times)

    return BlastRadius(
        unique_hosts=unique_hosts,
        unique_users=unique_users,
        privileged_users=privileged_users,
        techniques=techniques,
        blast_growth=blast_growth,
    )
