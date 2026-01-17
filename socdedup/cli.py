from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

import typer

from socdedup.clustering import cluster_alerts
from socdedup.ingest import ingest_csv, ingest_json
from socdedup.models import Incident

app = typer.Typer(add_completion=False)
incidents_app = typer.Typer(add_completion=False)


def _parse_time_window(value: str) -> timedelta:
    text = value.strip().lower()
    if text.endswith("m"):
        return timedelta(minutes=int(text[:-1]))
    if text.endswith("h"):
        return timedelta(hours=int(text[:-1]))
    if text.endswith("s"):
        return timedelta(seconds=int(text[:-1]))
    raise typer.BadParameter("time-window must end with s, m, or h")


def _load_alerts(path: Path):
    if path.suffix.lower() == ".json":
        return ingest_json(path)
    if path.suffix.lower() == ".csv":
        return ingest_csv(path)
    raise typer.BadParameter("unsupported file type")


@app.command()
def ingest(path: str) -> None:
    """Ingest alerts from JSON or CSV and print a sample."""
    input_path = Path(path)
    alerts = _load_alerts(input_path)
    typer.echo(f"alerts={len(alerts)}")
    sample = [a.model_dump(mode="json") for a in alerts[:5]]
    typer.echo(json.dumps(sample, indent=2, sort_keys=True))


@app.command()
def cluster(
    path: str,
    time_window: str = typer.Option("15m", "--time-window"),
    min_score: int = typer.Option(5, "--min-score"),
) -> None:
    """Cluster alerts into incidents and write output."""
    input_path = Path(path)
    alerts = _load_alerts(input_path)
    window = _parse_time_window(time_window)
    incidents = cluster_alerts(alerts, window, min_score)

    output_path = Path("data/out/incidents.json")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = [incident.model_dump(mode="json") for incident in incidents]
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)

    typer.echo("incident_id alerts hosts users ips techniques confidence")
    for incident in incidents:
        hosts = len(incident.entities.hosts)
        users = len(incident.entities.users)
        ips = len(incident.entities.ips)
        techniques = len(incident.techniques)
        typer.echo(
            f"{incident.incident_id} {len(incident.alerts)} {hosts} {users} {ips} "
            f"{techniques} {incident.confidence.value}"
        )


@incidents_app.command("show")
def incidents_show(
    incident_id: str,
    explain: bool = typer.Option(False, "--explain"),
    path: str = typer.Option("data/out/incidents.json", "--path"),
) -> None:
    """Show a single incident by ID."""
    input_path = Path(path)
    if not input_path.exists():
        raise typer.BadParameter(f"incidents file not found: {input_path}")
    payload = json.loads(input_path.read_text(encoding="utf-8"))
    incidents = [Incident.model_validate(item) for item in payload]
    for incident in incidents:
        if incident.incident_id == incident_id:
            typer.echo(f"Incident: {incident.incident_id}")
            typer.echo(f"Confidence: {incident.confidence.value}")
            if explain:
                typer.echo("Reasoning:")
                for line in incident.reasoning:
                    typer.echo(f"- {line}")
                privileged_users = {
                    alert.user
                    for alert in incident.alerts
                    if alert.user and alert.user.lower().startswith("admin")
                }
                typer.echo(
                    f"Blast radius: hosts={len(incident.entities.hosts)} "
                    f"users={len(incident.entities.users)} "
                    f"privileged_users={len(privileged_users)}"
                )
            return
    raise typer.BadParameter(f"incident not found: {incident_id}")


@incidents_app.command("replay")
def incidents_replay(
    incident_id: str,
    path: str = typer.Option("data/out/incidents.json", "--path"),
) -> None:
    """Show decision replay for a single incident by ID."""
    input_path = Path(path)
    if not input_path.exists():
        raise typer.BadParameter(f"incidents file not found: {input_path}")
    payload = json.loads(input_path.read_text(encoding="utf-8"))
    incidents = [Incident.model_validate(item) for item in payload]
    for incident in incidents:
        if incident.incident_id == incident_id:
            if incident.decision_replay is None:
                raise typer.BadParameter(f"decision replay not found: {incident_id}")
            replay = incident.decision_replay
            typer.echo(f"Action: {replay.action}")
            typer.echo(f"Urgency: {replay.urgency}")
            typer.echo("Justification:")
            for line in replay.justification:
                typer.echo(f"- {line}")
            typer.echo(f"Human-in-the-loop: {replay.human_in_the_loop}")
            return
    raise typer.BadParameter(f"incident not found: {incident_id}")


app.add_typer(incidents_app, name="incidents")


if __name__ == "__main__":
    app()
