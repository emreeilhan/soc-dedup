# soc-dedup

`soc-dedup` is a CLI tool that groups noisy SIEM alerts into incident-level clusters
and analyzes blast radius to reduce alert fatigue in SOC environments.

## Why this exists
Modern SIEMs generate alerts at the event level.
SOC analysts think at the incident level.

This tool bridges that gap.

## Scope
- Alert normalization (SIEM-agnostic)
- Temporal and entity-based correlation
- Incident summarization
- Blast radius analysis

## Non-goals
- Machine learning–driven decisions
- Real-time streaming
- UI dashboards

## Status
Early development (MVP).

## Installation note (Python 3.13)
On Python 3.13, editable installs may not always register the console script.
If this occurs, use:
  pip install .
This does not affect runtime behavior.
