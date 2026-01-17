# soc-dedup

Explainable SOC incident deduplication and decision engine.

## Why this exists

SOC alerts are noisy. Clustering alerts is not enough.
This project focuses on **reasoning-first decisions**:

* Why incidents are classified as high / medium / low confidence
* Which SOC response action is recommended
* Why that action is justified with concrete evidence

The goal is not automation for its own sake, but **auditable, deterministic SOC decisions**.

## What it does

1. Ingests heterogeneous SIEM alerts (JSON / CSV)
2. Correlates alerts into incidents using temporal and entity-based logic
3. Computes blast radius (hosts, users, growth over time)
4. Derives behavioral signals (credential spray, lateral movement, etc.)
5. Assigns **explainable confidence** levels
6. Replays the **SOC decision** with recommended action and urgency

## Architecture

```
blast_radius.py   → impact analysis (WHAT happened)
reasoning.py      → behavior analysis (HOW it looks)
confidence.py     → assessment logic (WHAT we think)
decision.py       → response replay (WHAT we would do)
```

Each layer has a single responsibility and produces auditable output.

## Example: Incident Walkthrough

```bash
socdedup cluster data/sample_alerts.json --time-window 15m --min-score 5
socdedup incidents show INC-0003 --explain
socdedup incidents replay INC-0003
```

**Example output (excerpt):**

* Confidence: HIGH
* Reasoning:

  * Blast radius expanded from 0 to 11 hosts in 10 minutes
  * Privileged account involved
* Recommended action: ISOLATE_HOST
* Urgency: IMMEDIATE

## Design Principles

* Deterministic logic only (no ML, no black boxes)
* Human-in-the-loop by default
* SOC-auditable decisions
* Separation of impact, behavior, assessment, and response

## Installation

```bash
pip install .
```

## Installation note (Python 3.13)

On Python 3.13, editable installs may not always register the console script.
If this occurs, use:

```bash
pip install .
```

This does not affect runtime behavior.

## Status

Early-stage but production-minded MVP, designed to demonstrate SOC reasoning and decision-making rather than alert volume metrics.
