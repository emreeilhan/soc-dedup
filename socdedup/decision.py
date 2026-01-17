from __future__ import annotations

from enum import Enum

from socdedup.blast_radius import BlastRadius
from socdedup.models import Confidence, DecisionReplay
from socdedup.reasoning import ReasoningSignals


class ResponseAction(str, Enum):
    MONITOR = "MONITOR"
    COLLECT_FORENSICS = "COLLECT_FORENSICS"
    ISOLATE_HOST = "ISOLATE_HOST"
    DISABLE_ACCOUNT = "DISABLE_ACCOUNT"


class Urgency(str, Enum):
    LOW = "LOW"
    HIGH = "HIGH"
    IMMEDIATE = "IMMEDIATE"


def assess_decision(
    signals: ReasoningSignals,
    blast_radius: BlastRadius,
    confidence: Confidence,
) -> DecisionReplay:
    justification: list[str] = []
    action = ResponseAction.MONITOR
    urgency = Urgency.LOW

    if confidence == Confidence.HIGH and signals.privileged_context.detected:
        action = ResponseAction.DISABLE_ACCOUNT
        urgency = Urgency.IMMEDIATE
        justification.append(
            "Privileged context: {} privileged users; lateral movement across {} hosts.".format(
                signals.privileged_context.privileged_users,
                signals.lateral_movement_pattern.hosts,
            )
        )
    elif confidence == Confidence.HIGH and blast_radius.blast_growth.detected:
        action = ResponseAction.ISOLATE_HOST
        urgency = Urgency.IMMEDIATE
        justification.append(
            "Blast growth: hosts expanded from {} to {} in {} minutes.".format(
                blast_radius.blast_growth.start_hosts,
                blast_radius.blast_growth.end_hosts,
                blast_radius.blast_growth.window_minutes,
            )
        )
    elif confidence == Confidence.MEDIUM:
        action = ResponseAction.COLLECT_FORENSICS
        urgency = Urgency.HIGH
        justification.append(
            "Moderate confidence: techniques={} hosts={} users={}.".format(
                len(blast_radius.techniques),
                len(blast_radius.unique_hosts),
                len(blast_radius.unique_users),
            )
        )
    else:
        action = ResponseAction.MONITOR
        urgency = Urgency.LOW
        justification.append(
            "Low confidence: hosts={} users={} privileged_users={}.".format(
                len(blast_radius.unique_hosts),
                len(blast_radius.unique_users),
                len(blast_radius.privileged_users),
            )
        )

    if signals.credential_spray_pattern.detected:
        justification.append(
            "Credential spray signal: {} source IPs targeted {} users in {} minutes.".format(
                signals.credential_spray_pattern.source_ips,
                signals.credential_spray_pattern.users,
                signals.credential_spray_pattern.window_minutes,
            )
        )
    if signals.lateral_movement_pattern.detected:
        justification.append(
            "Lateral movement signal: user '{}' accessed {} hosts in {} minutes.".format(
                signals.lateral_movement_pattern.user or "unknown",
                signals.lateral_movement_pattern.hosts,
                signals.lateral_movement_pattern.window_minutes,
            )
        )
    if blast_radius.blast_growth.detected:
        justification.append(
            "Blast radius growth window: {} new hosts in {} minutes.".format(
                blast_radius.blast_growth.new_hosts,
                blast_radius.blast_growth.window_minutes,
            )
        )

    return DecisionReplay(
        action=action.value,
        urgency=urgency.value,
        justification=justification,
        human_in_the_loop=True,
    )
