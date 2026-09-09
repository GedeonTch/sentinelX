"""
cli.py — Typer entry point for SentinelX NetLab V1

Rules enforced here:
- Typer only — never argparse, never click
- ZERO business logic — orchestrates calls, formats output, exits
- ZERO import sqlite3
- ZERO print() — display via core/logger.py
- All scan actions require explicit (y/n) confirmation before execution

Commands (Section L of the steering document):
    netlab doctor
    netlab scan --target <ip/cidr> --profile <normal|stealth|aggressive>
    netlab findings list --session <id>
    netlab findings show <id>
    netlab findings explain <id>
    netlab findings rescan --session <id>
    netlab sentinel start
    netlab sentinel status
    netlab sentinel stop
    netlab report generate --session <id> --format <pdf|html|json>
    netlab cleanup --session <id>
    netlab cleanup --sessions --older-than <duration>
    netlab config set <key> <value>
    netlab config show
    netlab --version
"""

from typing import List, Optional

import typer
from rich.table import Table
from rich.panel import Panel
from rich import box

from core.dependencies import (
    DependencyCheck,
    check_environment,
    check_status,
    environment_ready,
)
from core.logger import display

# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------

VERSION = "0.1.0-dev"

# ---------------------------------------------------------------------------
# App + sub-apps
# ---------------------------------------------------------------------------

app = typer.Typer(
    name="netlab",
    help="SentinelX NetLab V1 — educational network audit CLI",
    no_args_is_help=True,
)

findings_app = typer.Typer(help="Manage and display findings from a session.")
sentinel_app = typer.Typer(help="Baseline learning and network change detection.")
report_app = typer.Typer(help="Generate reports from a session.")
cleanup_app = typer.Typer(help="Clean up lab artifacts and old sessions.")
config_app = typer.Typer(help="Read and write NetLab configuration.")

app.add_typer(findings_app, name="findings")
app.add_typer(sentinel_app, name="sentinel")
app.add_typer(report_app, name="report")
app.add_typer(cleanup_app, name="cleanup")
app.add_typer(config_app, name="config")


# ---------------------------------------------------------------------------
# Version callback
# ---------------------------------------------------------------------------

def version_callback(value: bool) -> None:
    if value:
        display(f"NetLab version [bold]{VERSION}[/bold]")
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-v",
        callback=version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    """SentinelX NetLab — educational network audit CLI."""


# ---------------------------------------------------------------------------
# netlab doctor
# ---------------------------------------------------------------------------

@app.command()
def doctor() -> None:
    """Verify that Python, nmap, enum4linux, and ~/.netlab/ are ready for a scan."""
    checks = check_environment()
    _render_doctor_report(checks)
    if not environment_ready(checks):
        display(
            "[red]Environment is not ready.[/red] "
            "Install missing tools and ensure Python >= 3.10 before running a scan."
        )
        raise typer.Exit(code=1)
    display("[green]Environment is ready.[/green]")


def _render_doctor_report(checks: List[DependencyCheck]) -> None:
    """Render one row per DependencyCheck — no logic here."""
    table = Table(title="NetLab environment check", box=box.ROUNDED)
    table.add_column("Name", style="bold")
    table.add_column("Present")
    table.add_column("Version")
    table.add_column("Status")

    for check in checks:
        table.add_row(
            check.name,
            "yes" if check.present else "no",
            check.version if check.version else "—",
            _status_markup(check_status(check)),
        )
    display(table)


def _status_markup(status: str) -> str:
    """Map a status token to Rich markup."""
    mapping = {
        "ok": "[green]ok[/green]",
        "python_too_old": "[red]python < 3.10[/red]",
        "failed": "[red]failed[/red]",
        "missing": "[red]missing[/red]",
    }
    return mapping.get(status, "[red]unknown[/red]")


# ---------------------------------------------------------------------------
# netlab scan
# ---------------------------------------------------------------------------

_VALID_PROFILES = ("normal", "stealth", "aggressive")


@app.command()
def scan(
    target: str = typer.Option(..., "--target", "-t", help="IP address or CIDR range to scan."),
    profile: str = typer.Option("normal", "--profile", "-p", help="Scan profile: normal, stealth, aggressive."),
    session: Optional[str] = typer.Option(None, "--session", "-s", help="Session ID (auto-generated if omitted)."),
) -> None:
    """Discover assets and detect vulnerabilities on a target network."""
    if profile not in _VALID_PROFILES:
        display(f"[red]Invalid profile:[/red] '{profile}'. Choose from: {', '.join(_VALID_PROFILES)}")
        raise typer.Exit(code=1)

    display(Panel(
        f"[bold]Target:[/bold] {target}\n"
        f"[bold]Profile:[/bold] {profile}",
        title="NetLab Scan",
        border_style="cyan",
    ))

    confirmed = typer.confirm(f"Start scan on {target} with profile '{profile}'?")
    if not confirmed:
        display("[yellow]Scan cancelled.[/yellow]")
        raise typer.Exit(code=0)

    # Modules not yet implemented — stubs will be replaced as tickets are completed
    try:
        import uuid
        import datetime
        from datetime import timezone
        from core.database import init_db, save_session

        session_id = session or f"session-{uuid.uuid4().hex[:8]}"
        init_db(session_id)
        save_session(
            session_id,
            target=target,
            profile=profile,
            start_time=datetime.datetime.now(timezone.utc).isoformat(),
        )
        display(f"[green]Session created:[/green] {session_id}")
        display("[yellow]Scan modules not yet implemented (tickets #006–#013).[/yellow]")
        display(f"[dim]Run:[/dim] netlab findings list --session {session_id}")
    except Exception as exc:
        display(f"[red]Scan failed:[/red] {exc}")
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# netlab findings
# ---------------------------------------------------------------------------

@findings_app.callback(invoke_without_command=True)
def findings_main(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand is None:
        display("[yellow]Usage: netlab findings [list|show|explain|rescan][/yellow]")


@findings_app.command("list")
def findings_list(
    session: str = typer.Option(..., "--session", "-s", help="Session ID."),
) -> None:
    """List all findings for a session, ordered by severity."""
    try:
        from core.database import get_findings
        findings = get_findings(session)
        if not findings:
            display(f"[yellow]No findings for session {session}.[/yellow]")
            return
        _render_findings_table(findings)
    except Exception as exc:
        display(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1)


@findings_app.command("show")
def findings_show(
    finding_id: str = typer.Argument(..., help="Finding ID."),
    session: str = typer.Option(..., "--session", "-s", help="Session ID."),
) -> None:
    """Show full details of a single finding."""
    try:
        from core.database import get_finding_by_id
        finding = get_finding_by_id(session, finding_id)
        if finding is None:
            display(f"[red]Finding {finding_id} not found in session {session}.[/red]")
            raise typer.Exit(code=1)
        _render_finding_detail(finding)
    except typer.Exit:
        raise
    except Exception as exc:
        display(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1)


@findings_app.command("explain")
def findings_explain(
    finding_id: str = typer.Argument(..., help="Finding ID."),
    session: str = typer.Option(..., "--session", "-s", help="Session ID."),
) -> None:
    """Display the 3-angle explanation for a finding (what / attack / defense)."""
    try:
        from core.database import get_finding_by_id
        finding = get_finding_by_id(session, finding_id)
        if finding is None:
            display(f"[red]Finding {finding_id} not found in session {session}.[/red]")
            raise typer.Exit(code=1)
        if finding.explanation is None:
            display(
                f"[yellow]No explanation available for this finding.[/yellow]\n"
                f"The detection rule has no matching entry in the knowledge base yet."
            )
            return
        _render_explanation(finding)
    except typer.Exit:
        raise
    except Exception as exc:
        display(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1)


@findings_app.command("rescan")
def findings_rescan(
    session: str = typer.Option(..., "--session", "-s", help="Session ID."),
) -> None:
    """Rescan the session targets and update finding statuses."""
    confirmed = typer.confirm(f"Rescan all targets from session {session}?")
    if not confirmed:
        display("[yellow]Rescan cancelled.[/yellow]")
        raise typer.Exit(code=0)
    display("[yellow]Rescan not yet implemented (ticket #009+).[/yellow]")


# ---------------------------------------------------------------------------
# netlab sentinel
# ---------------------------------------------------------------------------

@sentinel_app.callback(invoke_without_command=True)
def sentinel_main(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand is None:
        display("[yellow]Usage: netlab sentinel [start|status|stop][/yellow]")


@sentinel_app.command("start")
def sentinel_start() -> None:
    """Learn the network baseline and start monitoring for changes."""
    confirmed = typer.confirm("Start Sentinel monitoring? This will scan the network to establish a baseline.")
    if not confirmed:
        display("[yellow]Sentinel start cancelled.[/yellow]")
        raise typer.Exit(code=0)
    display("[yellow]Sentinel not yet implemented (ticket #016).[/yellow]")


@sentinel_app.command("status")
def sentinel_status() -> None:
    """Show current Sentinel monitoring status and recent alerts."""
    display("[yellow]Sentinel not yet implemented (ticket #016).[/yellow]")


@sentinel_app.command("stop")
def sentinel_stop() -> None:
    """Stop Sentinel monitoring."""
    display("[yellow]Sentinel not yet implemented (ticket #016).[/yellow]")


# ---------------------------------------------------------------------------
# netlab report
# ---------------------------------------------------------------------------

_VALID_FORMATS = ("pdf", "html", "json")


@report_app.callback(invoke_without_command=True)
def report_main(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand is None:
        display("[yellow]Usage: netlab report generate --session <id> --format <pdf|html|json>[/yellow]")


@report_app.command("generate")
def report_generate(
    session: str = typer.Option(..., "--session", "-s", help="Session ID."),
    format: str = typer.Option("json", "--format", "-f", help="Output format: pdf, html, json."),
) -> None:
    """Generate a report for a session."""
    if format not in _VALID_FORMATS:
        display(f"[red]Invalid format:[/red] '{format}'. Choose from: {', '.join(_VALID_FORMATS)}")
        raise typer.Exit(code=1)
    display("[yellow]Report generation not yet implemented (ticket #017).[/yellow]")


# ---------------------------------------------------------------------------
# netlab cleanup
# ---------------------------------------------------------------------------

@cleanup_app.callback(invoke_without_command=True)
def cleanup_main(
    ctx: typer.Context,
    session: Optional[str] = typer.Option(None, "--session", "-s", help="Session ID to clean up."),
    sessions: bool = typer.Option(False, "--sessions", help="Clean up multiple sessions."),
    older_than: Optional[str] = typer.Option(None, "--older-than", help="Remove sessions older than duration (e.g. 30d)."),
) -> None:
    """Clean up lab artifacts. Use --session <id> or --sessions --older-than <duration>."""
    if ctx.invoked_subcommand is not None:
        return

    if session:
        confirmed = typer.confirm(
            f"Remove all artifacts for session {session}? Type 'yes' to confirm.",
            default=False,
        )
        if not confirmed:
            display("[yellow]Cleanup cancelled.[/yellow]")
            raise typer.Exit(code=0)
        display("[yellow]Cleanup not yet implemented (ticket #018–#019).[/yellow]")
        return

    if sessions and older_than:
        confirmed = typer.confirm(
            f"Remove all sessions older than {older_than}? Type 'yes' to confirm.",
            default=False,
        )
        if not confirmed:
            display("[yellow]Cleanup cancelled.[/yellow]")
            raise typer.Exit(code=0)
        display("[yellow]Cleanup not yet implemented (ticket #018–#019).[/yellow]")
        return

    display("[yellow]Usage: netlab cleanup --session <id>  OR  netlab cleanup --sessions --older-than <duration>[/yellow]")


# ---------------------------------------------------------------------------
# netlab config
# ---------------------------------------------------------------------------

@config_app.callback(invoke_without_command=True)
def config_main(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand is None:
        display("[yellow]Usage: netlab config [set|show][/yellow]")


@config_app.command("set")
def config_set(
    key: str = typer.Argument(..., help="Config key (e.g. lab.scope)."),
    value: str = typer.Argument(..., help="Config value (e.g. 192.168.1.0/24)."),
) -> None:
    """Set a configuration value."""
    _write_config(key, value)
    display(f"[green]Config updated:[/green] {key} = {value}")


@config_app.command("show")
def config_show() -> None:
    """Display current NetLab configuration."""
    config = _read_config()
    if not config:
        display("[yellow]No configuration found. Run 'netlab config set <key> <value>' to begin.[/yellow]")
        return
    table = Table(title="NetLab Configuration", box=box.ROUNDED)
    table.add_column("Key", style="bold")
    table.add_column("Value")
    for key, value in config.items():
        table.add_row(str(key), str(value))
    display(table)


# ---------------------------------------------------------------------------
# Rendering helpers — no logic, display only
# ---------------------------------------------------------------------------

def _render_findings_table(findings: list) -> None:
    """Render a summary table of findings."""
    table = Table(title=f"Findings ({len(findings)} total)", box=box.ROUNDED)
    table.add_column("ID", style="dim", max_width=12)
    table.add_column("Severity")
    table.add_column("Module")
    table.add_column("Target")
    table.add_column("Service")
    table.add_column("Status")
    table.add_column("Score")

    for f in findings:
        severity_color = {
            "critical": "red",
            "high": "orange3",
            "medium": "yellow",
            "low": "cyan",
            "info": "dim",
        }.get(f.severity.value, "white")

        table.add_row(
            f.id[:8],
            f"[{severity_color}]{f.severity.value}[/{severity_color}]",
            f.module,
            f"{f.target_ip}:{f.target_port}" if f.target_port else f.target_ip,
            f.target_service or "—",
            f.status.value,
            f"{f.risk_score:.1f}" if f.risk_score is not None else "—",
        )
    display(table)


def _render_finding_detail(finding: object) -> None:
    """Render full detail panel for a single finding."""
    from core.finding import Finding
    f: Finding = finding  # type: ignore
    lines = [
        f"[bold]ID:[/bold]       {f.id}",
        f"[bold]Module:[/bold]   {f.module}",
        f"[bold]Target:[/bold]   {f.target_ip}" + (f":{f.target_port}" if f.target_port else ""),
        f"[bold]Service:[/bold]  {f.target_service or '—'} {f.service_version or ''}".strip(),
        f"[bold]Severity:[/bold] {f.severity.value}",
        f"[bold]Confidence:[/bold] {f.confidence.name} ({float(f.confidence):.2f})",
        f"[bold]Exposure:[/bold] {f.exposure.value}",
        f"[bold]Score:[/bold]    {f'{f.risk_score:.1f}' if f.risk_score is not None else 'not scored yet'}",
        f"[bold]Status:[/bold]   {f.status.value}",
        f"[bold]CVEs:[/bold]     {', '.join(f.cve_refs) if f.cve_refs else '—'}",
        "",
        f"[bold]Evidence:[/bold]",
        f"  command : {f.evidence.command or '—'}",
        f"  raw     : {f.evidence.raw or '—'}",
    ]
    display(Panel("\n".join(lines), title="Finding Detail", border_style="cyan"))


def _render_explanation(finding: object) -> None:
    """Render the 3-angle explanation panel."""
    from core.finding import Finding
    f: Finding = finding  # type: ignore
    exp = f.explanation
    content = (
        f"[bold cyan]WHAT[/bold cyan]\n{exp.what}\n\n"
        f"[bold red]ATTACK[/bold red]\n{exp.attack}\n\n"
        f"[bold green]DEFENSE[/bold green]\n{exp.defense}"
    )
    display(Panel(content, title=f"Explanation — {f.module}", border_style="cyan"))


# ---------------------------------------------------------------------------
# Config helpers — read/write config.yaml, no business logic
# ---------------------------------------------------------------------------

def _read_config() -> dict:
    """Read the user config section from config.yaml. Returns empty dict on error."""
    from pathlib import Path
    config_path = Path(__file__).parent / "config.yaml"
    if not config_path.exists():
        return {}
    try:
        import yaml
        with open(config_path, "r") as f:
            data = yaml.safe_load(f) or {}
        return data.get("lab", {})
    except Exception:
        return {}


def _write_config(key: str, value: str) -> None:
    """Write a key under the [lab] section of config.yaml."""
    from pathlib import Path
    import yaml
    config_path = Path(__file__).parent / "config.yaml"
    try:
        with open(config_path, "r") as f:
            data = yaml.safe_load(f) or {}
    except Exception:
        data = {}

    if "lab" not in data:
        data["lab"] = {}
    data["lab"][key] = value

    with open(config_path, "w") as f:
        yaml.dump(data, f, default_flow_style=False, allow_unicode=True)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app()
