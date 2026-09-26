"""
cli.py — Typer entry point for SentinelX NetLab V1

Rules enforced here:
- Typer only — never argparse, never click
- ZERO business logic — orchestrates calls, formats output, exits
- ZERO import sqlite3
- ZERO print() — display via core/logger.py
- All scan actions require explicit (y/n) confirmation before execution
  (or --yes/-y to confirm the entire pipeline at once)
"""

from __future__ import annotations

import dataclasses
import datetime
import uuid
from dataclasses import dataclass, field
from datetime import timezone
from typing import List, Optional

import typer
from rich import box
from rich.panel import Panel
from rich.table import Table

from core.dependencies import (
    DependencyCheck,
    check_environment,
    check_status,
    environment_ready,
)
from core.finding import Finding
from core.logger import display

# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------

VERSION = "0.1.0-dev"

# ---------------------------------------------------------------------------
# Pipeline result — in-memory scan status (no new DB table needed)
# ---------------------------------------------------------------------------

@dataclass
class StepResult:
    name: str
    status: str                         # "ok" | "partial" | "failed"
    detail: str = ""
    failed_hosts: List[str] = field(default_factory=list)

    def icon(self) -> str:
        return {"ok": "✓", "partial": "⚠", "failed": "✗"}.get(self.status, "?")

    def color(self) -> str:
        return {"ok": "green", "partial": "yellow", "failed": "red"}.get(self.status, "white")


@dataclass
class PipelineResult:
    steps: List[StepResult] = field(default_factory=list)
    session_id: str = ""
    findings_count: int = 0
    global_score: Optional[float] = None

    def add(self, name: str, status: str, detail: str = "", failed_hosts=None) -> StepResult:
        sr = StepResult(name, status, detail, failed_hosts or [])
        self.steps.append(sr)
        return sr

    @property
    def overall_status(self) -> str:
        critical_failed = any(
            s.status == "failed"
            for s in self.steps
            if s.name in ("session", "discover")
        )
        if critical_failed:
            return "FAILED"
        if any(s.status in ("partial", "failed") for s in self.steps):
            return "PARTIAL"
        return "SUCCESS"

    @property
    def failure_count(self) -> int:
        return sum(
            1 for s in self.steps
            if s.status in ("partial", "failed")
        )


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
report_app   = typer.Typer(help="Generate reports from a session.")
cleanup_app  = typer.Typer(help="Clean up lab artifacts and old sessions.")
config_app   = typer.Typer(help="Read and write NetLab configuration.")

app.add_typer(findings_app, name="findings")
app.add_typer(sentinel_app, name="sentinel")
app.add_typer(report_app,   name="report")
app.add_typer(cleanup_app,  name="cleanup")
app.add_typer(config_app,   name="config")


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
        None, "--version", "-v",
        callback=version_callback, is_eager=True,
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
    mapping = {
        "ok":            "[green]ok[/green]",
        "python_too_old":"[red]python < 3.10[/red]",
        "failed":        "[red]failed[/red]",
        "missing":       "[red]missing[/red]",
    }
    return mapping.get(status, "[red]unknown[/red]")


# ---------------------------------------------------------------------------
# netlab scan — full pipeline
# ---------------------------------------------------------------------------

_VALID_PROFILES = ("normal", "stealth", "aggressive")


@app.command()
def scan(
    target:  str           = typer.Option(..., "--target",  "-t", help="IP address or CIDR range to scan."),
    profile: str           = typer.Option("normal", "--profile", "-p", help="Scan profile: normal, stealth, aggressive."),
    session: Optional[str] = typer.Option(None, "--session", "-s", help="Session ID (auto-generated if omitted)."),
    yes:     bool          = typer.Option(False, "--yes", "-y", help="Auto-confirm all scan prompts (pipeline mode)."),
) -> None:
    """Discover assets and detect vulnerabilities on a target network."""
    if profile not in _VALID_PROFILES:
        display(f"[red]Invalid profile:[/red] '{profile}'. Choose from: {', '.join(_VALID_PROFILES)}")
        raise typer.Exit(code=1)

    display(Panel(
        f"[bold]Target:[/bold]  {target}\n"
        f"[bold]Profile:[/bold] {profile}\n"
        f"[bold]Auto:[/bold]    {'yes (--yes)' if yes else 'interactive'}",
        title="NetLab Scan", border_style="cyan",
    ))

    if not yes:
        confirmed = typer.confirm(f"Start full scan on {target} with profile '{profile}'?")
        if not confirmed:
            display("[yellow]Scan cancelled.[/yellow]")
            raise typer.Exit(code=0)

    result = PipelineResult()
    findings = _run_pipeline(target, profile, session, yes, result)
    _render_scan_summary(result, findings)

    if result.overall_status == "FAILED":
        raise typer.Exit(code=1)


def _run_pipeline(
    target: str,
    profile: str,
    session: Optional[str],
    auto_confirm: bool,
    result: PipelineResult,
) -> List[Finding]:
    """Execute the full scan pipeline and return produced findings."""
    from core.database import (
        close_session, init_db, save_findings, save_session,
        update_finding_risk_score,
    )

    # ── Step 1 — Session ──────────────────────────────────────────────────
    try:
        session_id = session or f"session-{uuid.uuid4().hex[:8]}"
        init_db(session_id)
        save_session(
            session_id, target=target, profile=profile,
            start_time=datetime.datetime.now(timezone.utc).isoformat(),
        )
        result.session_id = session_id
        result.add("session", "ok", f"Session {session_id}")
    except Exception as exc:
        result.add("session", "failed", str(exc))
        return []  # cannot continue without a session

    # ── Step 2 — DISCOVER ─────────────────────────────────────────────────
    active_ips: List[str] = []
    try:
        from recon.device_fingerprint import fingerprint
        host_findings = fingerprint(target, session_id, auto_confirm=auto_confirm)
        if host_findings:
            save_findings(host_findings)
            active_ips = list({f.target_ip for f in host_findings if f.target_ip})
            result.add("discover", "ok", f"{len(active_ips)} host(s) found")
        else:
            result.add("discover", "ok", "0 hosts found (network may be empty)")
    except Exception as exc:
        result.add("discover", "failed", str(exc))
        # No IPs — subsequent steps will produce empty results but we continue

    # ── Step 3 — TCP scan ─────────────────────────────────────────────────
    all_tcp_findings = []
    if active_ips:
        tcp_ok, tcp_fail, tcp_failed_hosts = 0, 0, []
        from detect.tcp_scan import tcp_scan
        for ip in active_ips:
            try:
                findings = tcp_scan(ip, session_id, profile=profile, auto_confirm=auto_confirm)
                all_tcp_findings.extend(findings)
                tcp_ok += 1
            except Exception as exc:
                tcp_fail += 1
                tcp_failed_hosts.append(ip)
        if tcp_fail == 0:
            result.add("tcp_scan", "ok", f"{tcp_ok}/{len(active_ips)} hosts scanned")
        else:
            result.add("tcp_scan", "partial",
                       f"{tcp_ok}/{len(active_ips)} réussis",
                       failed_hosts=tcp_failed_hosts)
        if all_tcp_findings:
            save_findings(all_tcp_findings)

    # ── Step 4 — UDP scan ─────────────────────────────────────────────────
    all_udp_findings = []
    if active_ips:
        udp_ok, udp_fail, udp_failed_hosts = 0, 0, []
        from detect.udp_scan import udp_scan
        for ip in active_ips:
            try:
                findings = udp_scan(ip, session_id, profile=profile, auto_confirm=auto_confirm)
                all_udp_findings.extend(findings)
                udp_ok += 1
            except Exception as exc:
                udp_fail += 1
                udp_failed_hosts.append(ip)
        if udp_fail == 0:
            result.add("udp_scan", "ok", f"{udp_ok}/{len(active_ips)} hosts scanned")
        else:
            result.add("udp_scan", "partial",
                       f"{udp_ok}/{len(active_ips)} réussis",
                       failed_hosts=udp_failed_hosts)
        if all_udp_findings:
            save_findings(all_udp_findings)

    # ── Step 5 — CVE enrichment ───────────────────────────────────────────
    all_port_findings = all_tcp_findings + all_udp_findings
    enriched = all_port_findings
    if all_port_findings:
        try:
            from detect.service_detection import enrich_findings
            enriched = enrich_findings(all_port_findings)
            result.add("cve_enrichment", "ok", f"{len(enriched)} finding(s) processed")
        except Exception as exc:
            result.add("cve_enrichment", "failed", str(exc))

    # ── Step 6 — Misconfiguration detection ───────────────────────────────
    misconfig_findings = []
    if active_ips and enriched:
        mc_ok, mc_fail, mc_failed_hosts = 0, 0, []
        from detect.misconfig_detection import detect_misconfigs
        for ip in active_ips:
            try:
                ip_findings = [f for f in enriched if f.target_ip == ip]
                mc = detect_misconfigs(ip_findings, session_id)
                misconfig_findings.extend(mc)
                mc_ok += 1
            except Exception as exc:
                mc_fail += 1
                mc_failed_hosts.append(ip)
        if mc_fail == 0:
            result.add("misconfig_detection", "ok",
                       f"{len(misconfig_findings)} misconfiguration(s) found")
        else:
            result.add("misconfig_detection", "partial",
                       f"{mc_ok}/{len(active_ips)} réussis",
                       failed_hosts=mc_failed_hosts)

    # ── Step 8 — Explanation enrichment ───────────────────────────────────
    # Knowledge Base enrichment is deliberately non-critical: an unavailable
    # or failing explanation must not change the pipeline status or interrupt
    # scoring and persistence of the findings.
    all_findings = enriched + misconfig_findings
    explained = []
    try:
        from knowledge.knowledge_base import get_explanation_for_finding
    except Exception:
        get_explanation_for_finding = None

    for f in all_findings:
        if get_explanation_for_finding is not None and f.explanation is None:
            try:
                exp = get_explanation_for_finding(f.module, f.target_service)
                if exp:
                    f = dataclasses.replace(f, explanation=exp)
            except Exception:
                pass
        explained.append(f)

    result.add("explanation", "ok", f"{len(explained)} finding(s) processed")

    # ── Step 9 — Risk scoring ─────────────────────────────────────────────
    scored = explained
    try:
        from core.risk_scorer import score_findings, get_global_score
        scored = score_findings(explained)
        result.global_score = get_global_score(scored)
        result.add("risk_scoring", "ok",
                   f"global score: {result.global_score:.1f}" if result.global_score else "no qualifying findings")
    except Exception as exc:
        result.add("risk_scoring", "failed", str(exc))

    # ── Step 9 — Persist final findings ───────────────────────────────────
    result.findings_count = len(scored)
    try:
        save_findings(scored)
        for f in scored:
            if f.risk_score is not None:
                update_finding_risk_score(session_id, f.id, f.risk_score)
        result.add("persist", "ok", f"{len(scored)} finding(s) saved")
    except Exception as exc:
        result.add("persist", "failed", str(exc))

    # ── Step 10 — Close session ───────────────────────────────────────────
    try:
        close_session(session_id)
    except Exception:
        pass  # non-fatal

    return scored


def _render_scan_summary(
    result: PipelineResult,
    findings: List[Finding],
) -> None:
    """Display pipeline steps, findings by severity, and final status."""
    from core.finding import Severity
    severity_counts = {severity.value: 0 for severity in Severity}
    for finding in findings:
        severity = getattr(finding, "severity", None)
        severity_value = getattr(severity, "value", severity)
        if severity_value in severity_counts:
            severity_counts[severity_value] += 1

    display("")
    for step in result.steps:
        color = step.color()
        display(f"[{color}]{step.icon()} {step.name}[/{color}]"
                + (f"  [dim]{step.detail}[/dim]" if step.detail else ""))
        for host in step.failed_hosts:
            display(f"  [dim]└─ {host}[/dim]")

    severity_table = Table(title="Findings", box=box.ROUNDED)
    severity_table.add_column("Severity", style="bold")
    severity_table.add_column("Count", justify="right")
    for severity in Severity:
        severity_table.add_row(severity.name, str(severity_counts[severity.value]))
    display(severity_table)

    display("\n" + "─" * 40)
    status = result.overall_status
    status_color = {"SUCCESS": "green", "PARTIAL": "yellow", "FAILED": "red"}.get(status, "white")
    display(f"[bold {status_color}]RÉSULTAT : {status}[/bold {status_color}]")
    display("─" * 40)
    display(f"[dim]Session:[/dim] {result.session_id}")
    display(f"[dim]Findings:[/dim] {result.findings_count}")
    if result.global_score is not None:
        display(f"[dim]Global score:[/dim] {result.global_score:.1f}/100")
    display(f"\n[dim]› netlab findings list --session {result.session_id}[/dim]")
    display(f"[dim]› netlab report generate --session {result.session_id} --format html[/dim]")

    if result.failure_count:
        display(f"\n[yellow]⚠ {result.failure_count} opération(s) ont échoué.[/yellow]")


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
    session:    str = typer.Option(..., "--session", "-s", help="Session ID."),
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
    session:    str = typer.Option(..., "--session", "-s", help="Session ID."),
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
                "[yellow]No explanation available for this finding.[/yellow]\n"
                "The detection rule has no matching entry in the knowledge base yet."
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
    display("[yellow]Rescan not yet implemented.[/yellow]")


# ---------------------------------------------------------------------------
# netlab sentinel
# ---------------------------------------------------------------------------

@sentinel_app.callback(invoke_without_command=True)
def sentinel_main(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand is None:
        display("[yellow]Usage: netlab sentinel [start|status|stop][/yellow]")


@sentinel_app.command("start")
def sentinel_start(
    target:  str           = typer.Option(..., "--target", "-t", help="Network to monitor (CIDR)."),
    session: Optional[str] = typer.Option(None, "--session", "-s", help="Session ID."),
    relearn: bool          = typer.Option(False, "--relearn", help="Force baseline relearn."),
) -> None:
    """Learn the network baseline and start monitoring for changes."""
    from sentinel.sentinel_manager import start
    start(target_network=target, session_id=session, force_relearn=relearn)


@sentinel_app.command("status")
def sentinel_status(
    session: str = typer.Option(..., "--session", "-s", help="Session or network ID."),
) -> None:
    """Show current Sentinel monitoring status and recent alerts."""
    from sentinel.sentinel_manager import display_status
    display_status(session)


@sentinel_app.command("stop")
def sentinel_stop(
    session: str = typer.Option(..., "--session", "-s", help="Session or network ID."),
) -> None:
    """Stop Sentinel monitoring."""
    from sentinel.sentinel_manager import stop
    stop(session)


# ---------------------------------------------------------------------------
# netlab report
# ---------------------------------------------------------------------------

_VALID_FORMATS = ("html", "json")


@report_app.callback(invoke_without_command=True)
def report_main(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand is None:
        display("[yellow]Usage: netlab report generate --session <id> --format <html|json>[/yellow]")


@report_app.command("generate")
def report_generate(
    session: str           = typer.Option(..., "--session", "-s", help="Session ID."),
    format:  str           = typer.Option("json", "--format", "-f", help="Output format: html, json."),
    output:  Optional[str] = typer.Option(None, "--output", "-o", help="Output file path."),
) -> None:
    """Generate a report for a session (HTML or JSON)."""
    if format.lower() == "pdf":
        display("[red]PDF is not supported in V1.[/red] Use --format html and print from browser.")
        raise typer.Exit(code=1)
    if format.lower() not in _VALID_FORMATS:
        display(f"[red]Invalid format:[/red] '{format}'. Choose from: {', '.join(_VALID_FORMATS)}")
        raise typer.Exit(code=1)

    if output is None:
        from pathlib import Path
        out_dir = Path.home() / ".netlab" / "reports"
        out_dir.mkdir(parents=True, exist_ok=True)
        output = str(out_dir / f"{session}.{format.lower()}")

    from reports.generator import generate_report
    ok = generate_report(session_id=session, format=format, output_path=output)
    if ok:
        display(f"[green]Report saved:[/green] {output}")
    else:
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# netlab cleanup
# ---------------------------------------------------------------------------

@cleanup_app.callback(invoke_without_command=True)
def cleanup_main(
    ctx:        typer.Context,
    session:    Optional[str] = typer.Option(None, "--session", "-s"),
    sessions:   bool          = typer.Option(False, "--sessions"),
    older_than: Optional[str] = typer.Option(None, "--older-than"),
) -> None:
    """Clean up lab artifacts."""
    if ctx.invoked_subcommand is not None:
        return
    if session:
        from cleanup.restore import RestoreStatus, restore_session
        try:
            status = restore_session(session)
        except ValueError as exc:
            display(f"[red]{exc}[/red]")
            raise typer.Exit(code=1)
        if status == RestoreStatus.PARTIAL:
            raise typer.Exit(code=1)
        return
    if sessions and older_than:
        confirmed = typer.confirm(f"Remove all sessions older than {older_than}?", default=False)
        if not confirmed:
            display("[yellow]Cleanup cancelled.[/yellow]")
            raise typer.Exit(code=0)
        display("[yellow]Cleanup not yet implemented (tickets #018–#019).[/yellow]")
        return
    display("[yellow]Usage: netlab cleanup --session <id>  OR  --sessions --older-than <duration>[/yellow]")


# ---------------------------------------------------------------------------
# netlab config
# ---------------------------------------------------------------------------

@config_app.callback(invoke_without_command=True)
def config_main(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand is None:
        display("[yellow]Usage: netlab config [set|show][/yellow]")


@config_app.command("set")
def config_set(
    key:   str = typer.Argument(..., help="Config key (e.g. lab.scope)."),
    value: str = typer.Argument(..., help="Config value."),
) -> None:
    """Set a configuration value."""
    _write_config(key, value)
    display(f"[green]Config updated:[/green] {key} = {value}")


@config_app.command("show")
def config_show() -> None:
    """Display current NetLab configuration."""
    config = _read_config()
    if not config:
        display("[yellow]No configuration found.[/yellow]")
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
    table = Table(title=f"Findings ({len(findings)} total)", box=box.ROUNDED)
    table.add_column("ID", style="dim", max_width=12)
    table.add_column("Severity")
    table.add_column("Module")
    table.add_column("Target")
    table.add_column("Service")
    table.add_column("Status")
    table.add_column("Score")
    for f in findings:
        color = {"critical":"red","high":"orange3","medium":"yellow","low":"cyan","info":"dim"}.get(f.severity.value,"white")
        table.add_row(
            f.id[:8],
            f"[{color}]{f.severity.value}[/{color}]",
            f.module,
            f"{f.target_ip}:{f.target_port}" if f.target_port else f.target_ip,
            f.target_service or "—",
            f.status.value,
            f"{f.risk_score:.1f}" if f.risk_score is not None else "—",
        )
    display(table)


def _render_finding_detail(finding: object) -> None:
    from core.finding import Finding
    f: Finding = finding  # type: ignore
    lines = [
        f"[bold]ID:[/bold]         {f.id}",
        f"[bold]Module:[/bold]     {f.module}",
        f"[bold]Target:[/bold]     {f.target_ip}" + (f":{f.target_port}" if f.target_port else ""),
        f"[bold]Service:[/bold]    {f.target_service or '—'} {f.service_version or ''}".strip(),
        f"[bold]Severity:[/bold]   {f.severity.value}",
        f"[bold]Confidence:[/bold] {f.confidence.name} ({float(f.confidence):.2f})",
        f"[bold]Exposure:[/bold]   {f.exposure.value}",
        f"[bold]Score:[/bold]      {f'{f.risk_score:.1f}' if f.risk_score is not None else 'not scored yet'}",
        f"[bold]Status:[/bold]     {f.status.value}",
        f"[bold]CVEs:[/bold]       {', '.join(f.cve_refs) if f.cve_refs else '—'}",
        "",
        f"[bold]Evidence:[/bold]",
        f"  command : {f.evidence.command or '—'}",
        f"  raw     : {f.evidence.raw[:200] if f.evidence.raw else '—'}",
    ]
    display(Panel("\n".join(lines), title="Finding Detail", border_style="cyan"))


def _render_explanation(finding: object) -> None:
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
# Config helpers
# ---------------------------------------------------------------------------

def _read_config() -> dict:
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
