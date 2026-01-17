from __future__ import annotations

from socdedup.models import Alert, Confidence, EntitiesSummary


def analyze_incident(alerts: list[Alert]) -> dict[str, object]:
    hosts: set[str] = set()
    users: set[str] = set()
    ips: set[str] = set()
    techniques: set[str] = set()
    privileged_users: set[str] = set()

    for alert in alerts:
        if alert.host:
            hosts.add(alert.host)
        if alert.user:
            users.add(alert.user)
            if alert.user.lower().startswith("admin"):
                privileged_users.add(alert.user)
        if alert.source_ip:
            ips.add(alert.source_ip)
        if alert.mitre_technique:
            techniques.add(alert.mitre_technique)

    if len(privileged_users) > 0 or len(hosts) >= 10:
        confidence = Confidence.HIGH
    elif len(hosts) >= 3:
        confidence = Confidence.MEDIUM
    else:
        confidence = Confidence.LOW

    entities = EntitiesSummary(hosts=hosts, users=users, ips=ips)

    return {
        "entities": entities,
        "confidence": confidence,
        "unique_hosts": hosts,
        "unique_users": users,
        "privileged_users": privileged_users,
        "techniques": techniques,
    }
