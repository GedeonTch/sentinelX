"""
cli.py — Typer entry point for SentinelX NetLab V1

Ticket #003 implements only ``netlab doctor``. Other commands belong to
later tickets. This file orchestrates and displays — it does not check
PATH, parse versions, or contain other business logic.
"""

from typing import List

import typer
from rich.table import Table

from core.dependencies import (
    DependencyCheck,
    check_environment,
    check_status,
    environment_ready,
)
from core.logger import display

app = typer.Typer(name="netlab", help="SentinelX NetLab — educational network audit CLI")


@app.callback()
def main() -> None:
    """SentinelX NetLab — educational network audit CLI."""
    return None


@app.command()
def doctor() -> None:
    """Verify that Python, nmap, enum4linux, and ~/.netlab/ are ready for a scan."""
    checks = check_environment()
    _render_doctor_report(checks)
    if not environment_ready(checks):
        display(
            "[red]Environment is not ready.[/red] "
            "Install missing tools, use Python 3.10+, and ensure ~/.netlab/ is writable "
            "before running a scan."
        )
        raise typer.Exit(code=1)
    display("[green]Environment is ready.[/green]")


def _render_doctor_report(checks: List[DependencyCheck]) -> None:
    """Display one row per DependencyCheck via Rich. No check logic here."""
    table = Table(title="NetLab environment check")
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
    """Map a status token from core.dependencies to Rich markup."""
    if status == "ok":
        return "[green]ok[/green]"
    if status == "python_too_old":
        return "[red]python < 3.10[/red]"
    if status == "failed":
        return "[red]failed[/red]"
    return "[red]missing[/red]"


if __name__ == "__main__":
    app()
