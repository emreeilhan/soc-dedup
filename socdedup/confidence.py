from __future__ import annotations

from socdedup.blast_radius import BlastRadius
from socdedup.models import Confidence
from socdedup.reasoning import ReasoningSignals


def _format_minutes(value: int) -> str:
    return f"{value} minute" if value == 1 else f"{value} minutes"


def assess_confidence(signals: ReasoningSignals, blast: BlastRadius) -> tuple[Confidence, list[str]]:
    reasoning: list[str] = []

    privileged_users = len(blast.privileged_users)
    unique_hosts = len(blast.unique_hosts)
    unique_users = len(blast.unique_users)

    if signals.privileged_context.detected and signals.lateral_movement_pattern.detected:
        confidence = Confidence.HIGH
        reasoning.append(
            "Confidence HIGH: privileged_users={} with user '{}' across {} hosts in {}.".format(
                privileged_users,
                signals.lateral_movement_pattern.user or "unknown",
                signals.lateral_movement_pattern.hosts,
                _format_minutes(signals.lateral_movement_pattern.window_minutes),
            )
        )
    elif (
        signals.credential_spray_pattern.detected
        and blast.blast_growth.detected
    ):
        confidence = Confidence.HIGH
        reasoning.append(
            "Confidence HIGH: {} source IPs targeted {} users in {}; hosts expanded from {} to {} in {}.".format(
                signals.credential_spray_pattern.source_ips,
                signals.credential_spray_pattern.users,
                _format_minutes(signals.credential_spray_pattern.window_minutes),
                blast.blast_growth.start_hosts,
                blast.blast_growth.end_hosts,
                _format_minutes(blast.blast_growth.window_minutes),
            )
        )
    elif signals.technique_progression.detected:
        confidence = Confidence.MEDIUM
        reasoning.append(
            "Confidence MEDIUM: {} techniques observed in {}.".format(
                signals.technique_progression.techniques,
                _format_minutes(signals.technique_progression.window_minutes),
            )
        )
    elif unique_hosts >= 3 and (
        signals.lateral_movement_pattern.detected or signals.technique_progression.detected
    ):
        confidence = Confidence.MEDIUM
        window = (
            signals.lateral_movement_pattern.window_minutes
            if signals.lateral_movement_pattern.detected
            else signals.technique_progression.window_minutes
        )
        reasoning.append(
            "Confidence MEDIUM: {} hosts with escalation signal in {}.".format(
                unique_hosts,
                _format_minutes(window),
            )
        )
    else:
        confidence = Confidence.LOW
        reasoning.append(
            "Confidence LOW: hosts={} users={} privileged_users={}.".format(
                unique_hosts,
                unique_users,
                privileged_users,
            )
        )

    if signals.credential_spray_pattern.detected:
        reasoning.append(
            "Credential spraying detected: {} source IPs targeted {} users within {}.".format(
                signals.credential_spray_pattern.source_ips,
                signals.credential_spray_pattern.users,
                _format_minutes(signals.credential_spray_pattern.window_minutes),
            )
        )
    if signals.lateral_movement_pattern.detected:
        reasoning.append(
            "Lateral movement suspected: user '{}' accessed {} hosts within {} (technique_T1021={}).".format(
                signals.lateral_movement_pattern.user or "unknown",
                signals.lateral_movement_pattern.hosts,
                _format_minutes(signals.lateral_movement_pattern.window_minutes),
                signals.lateral_movement_pattern.technique_t1021,
            )
        )
    if signals.technique_progression.detected:
        reasoning.append(
            "Technique progression observed: {} techniques within {}.".format(
                signals.technique_progression.techniques,
                _format_minutes(signals.technique_progression.window_minutes),
            )
        )
    if signals.privileged_context.detected:
        reasoning.append(
            "Privileged context observed: {} privileged users.".format(
                signals.privileged_context.privileged_users,
            )
        )
    if blast.blast_growth.detected:
        reasoning.append(
            "Blast radius expanded from {} to {} hosts in {}.".format(
                blast.blast_growth.start_hosts,
                blast.blast_growth.end_hosts,
                _format_minutes(blast.blast_growth.window_minutes),
            )
        )

    return confidence, reasoning
